/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.authentication.authenticators.x509;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.ws.rs.core.MultivaluedHashMap;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.PemUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.truststore.TruststoreProvider;

import static java.util.stream.Collectors.joining;
import static org.keycloak.authentication.authenticators.util.AuthenticatorUtils.getDisabledByBruteForceEventError;

public class CnsX509ClientCertificateAuthenticator extends X509ClientCertificateAuthenticator {

    @Override
    public void close() {
        super.close();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        try {

            dumpContainerAttributes(context);

            X509Certificate[] certs = getCertificateChain(context);
            if (certs == null || certs.length == 0) {
                // No x509 client cert, fall through and
                // continue processing the rest of the authentication flow
                logger.debug("[X509ClientCertificateAuthenticator:authenticate] x509 client certificate is not available for mutual SSL.");
                context.attempted();
                return;
            }

            saveX509CertificateAuditDataToAuthSession(context, certs[0]);
            recordX509CertificateAuditDataViaContextEvent(context);

            X509AuthenticatorConfigModel config = null;
            if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getConfig() != null) {
                config = new X509AuthenticatorConfigModel(context.getAuthenticatorConfig());
            }
            if (config == null) {
                logger.warn("[X509ClientCertificateAuthenticator:authenticate] x509 Client Certificate Authentication configuration is not available.");
                context.challenge(createInfoResponse(context, "X509 client authentication has not been configured yet"));
                context.attempted();
                return;
            }

            // Validate X509 client certificate
            try {
                CertificateValidator.CertificateValidatorBuilder builder = certificateValidationParameters(context.getSession(), config);
                CertificateValidator validator = builder.build(certs);
                validator.checkRevocationStatus()
                         .validateKeyUsage()
                         .validateExtendedKeyUsage()
                         .validateTimestamps();
            } catch(Exception e) {
                logger.error(e.getMessage(), e);
                // TODO use specific locale to load error messages
                String errorMessage = "Certificate validation failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            // Validate X509 client certificate trust
            try {
                TruststoreProvider truststoreProvider = context.getSession().getProvider(TruststoreProvider.class);
                if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
                    logger.error("Cannot validate client certificate trust: Truststore not available");
                }
                else
                {
                    Set<X509Certificate> trustedRootCerts = truststoreProvider.getRootCertificates().entrySet().stream().map(t -> t.getValue()).collect(Collectors.toSet());
                    Set<X509Certificate> trustedIntermediateCerts = truststoreProvider.getIntermediateCertificates().entrySet().stream().map(t -> t.getValue()).collect(Collectors.toSet());

                    logger.errorf("Found %d trusted root certs, %d trusted intermediate certs", trustedRootCerts.size(), trustedIntermediateCerts.size());

                    verifyCertificateTrust(certs[0], trustedRootCerts, trustedIntermediateCerts);
                }
            } catch(Exception e) {
                logger.error(e.getMessage(), e);
                // TODO use specific locale to load error messages
                String errorMessage = "Certificate is not trusted.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            // Validate X509 certificate extended policies
            try {
                boolean hasCnsExtension = false, hasCieExtension = false;

                Extensions certExtensions = new JcaX509CertificateHolder(certs[0]).getExtensions();
                if (certExtensions != null)
                {
                    CertificatePolicies policies = CertificatePolicies.fromExtensions(certExtensions);

                    if (policies != null)
                    {
                        logger.infof("Certificate policies found: %s",
                            Arrays.stream(policies.getPolicyInformation()).map(t -> t.getPolicyIdentifier().toString()).collect(joining(",")));

                        for (PolicyInformation policy: policies.getPolicyInformation())
                        {
                            if (policy.getPolicyIdentifier().toString().equals("1.3.76.16.2.1")) hasCnsExtension = true;
                            if (policy.getPolicyIdentifier().toString().equals("1.3.76.47.4")) hasCieExtension = true;
                        }
                    }
                }

                logger.infof("CNS Extension: %s - CIE Extension: %s", hasCnsExtension ? "present": "absent", hasCieExtension ? "present": "absent");

                if (!hasCnsExtension && !hasCieExtension)
                    throw new Exception("Certificate extended policy does not contain required OIDs (1.3.76.16.2.1, 1.3.76.47.4).");
            } catch(Exception e) {
                logger.error(e.getMessage(), e);
                // TODO use specific locale to load error messages
                String errorMessage = "Certificate extended policy validation's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            Object userIdentity = getUserIdentityExtractor(config).extractUserIdentity(certs);
            if (userIdentity == null) {
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                logger.warnf("[X509ClientCertificateAuthenticator:authenticate] Unable to extract user identity from certificate.");
                // TODO use specific locale to load error messages
                String errorMessage = "Unable to extract user identity from specified certificate";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(), errorMessage));
                context.attempted();
                return;
            }

            UserModel user;
            try {
                context.getEvent().detail(Details.USERNAME, userIdentity.toString());
                context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, userIdentity.toString());
                user = getUserIdentityToModelMapper(config).find(context, userIdentity);
            }
            catch(ModelDuplicateException e) {
                logger.modelDuplicateException(e);
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, e.getMessage()));
                context.attempted();
                return;
            }

            if (invalidUser(context, user)) {
                try
                {
                    // Try to create the user
                    logger.infof("[CnsX509ClientCertificateAuthenticator:authenticate] Existing user not found - now trying to create a new one...");
                    user = importUserToKeycloak(context, certs, userIdentity.toString());
                }
                catch (Exception e)
                {
                    logger.warn("[CnsX509ClientCertificateAuthenticator:authenticate] Error creating user identity.", e);

                    // TODO use specific locale to load error messages
                    String errorMessage = "X509 certificate authentication's failed.";
                    // TODO is calling form().setErrors enough to show errors on login screen?
                    context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                            errorMessage, "Invalid user"));
                    context.attempted();
                    return;
                }
            }

            String bruteForceError = getDisabledByBruteForceEventError(context.getProtector(), context.getSession(), context.getRealm(), user);
            if (bruteForceError != null) {
                context.getEvent().user(user);
                context.getEvent().error(bruteForceError);
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "Invalid user"));
                context.attempted();
                return;
            }

            if (!userEnabled(context, user)) {
                // TODO use specific locale to load error messages
                String errorMessage = "X509 certificate authentication's failed.";
                // TODO is calling form().setErrors enough to show errors on login screen?
                context.challenge(createErrorResponse(context, certs[0].getSubjectDN().getName(),
                        errorMessage, "User is disabled"));
                context.attempted();
                return;
            }
            context.setUser(user);

            // Check whether to display the identity confirmation
            if (!config.getConfirmationPageDisallowed()) {
                // FIXME calling forceChallenge was the only way to display
                // a form to let users either choose the user identity from certificate
                // or to ignore it and proceed to a normal login screen. Attempting
                // to call the method "challenge" results in a wrong/unexpected behavior.
                // The question is whether calling "forceChallenge" here is ok from
                // the design viewpoint?
                context.forceChallenge(createSuccessResponse(context, certs[0].getSubjectDN().getName()));
                // Do not set the flow status yet, we want to display a form to let users
                // choose whether to accept the identity from certificate or to specify username/password explicitly
            }
            else {
                // Bypass the confirmation page and log the user in
                context.success();
            }
        }
        catch(Exception e) {
            logger.errorf("[X509ClientCertificateAuthenticator:authenticate] Exception: %s", e.getMessage());
            context.attempted();
        }
    }

    /**
    * Attempts to build a certification chain for given certificate and to verify
    * it. Relies on a set of root CA certificates (trust anchors) and a set of
    * intermediate certificates (to be used as part of the chain).
    * @param cert - certificate for validation
    * @param trustedRootCerts - set of trusted root CA certificates
    * @param intermediateCerts - set of intermediate certificates
    * @return the certification chain (if verification is successful)
    * @throws GeneralSecurityException - if the verification is not successful
    *       (e.g. certification path cannot be built or some certificate in the
    *       chain is expired)
    */
    private static PKIXCertPathBuilderResult verifyCertificateTrust(X509Certificate cert, Set<X509Certificate> trustedRootCerts,
        Set<X509Certificate> intermediateCerts) throws GeneralSecurityException {

        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        for (X509Certificate trustedRootCert : trustedRootCerts) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams =
        new PKIXBuilderParameters(trustAnchors, selector);

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Specify a list of intermediate certificates
        // certificate itself has to be added to the list
        intermediateCerts.add(cert);
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
        new CollectionCertStoreParameters(intermediateCerts), "BC");
        pkixParams.addCertStore(intermediateCertStore);

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
        PKIXCertPathBuilderResult result =
        (PKIXCertPathBuilderResult) builder.build(pkixParams);
        return result;
    }

    protected UserModel importUserToKeycloak(AuthenticationFlowContext context, X509Certificate[] certs, String userIdentity)
    {
        Function<X509Certificate[],X500Name> subject = _certs -> {
            try {
                return new JcaX509CertificateHolder(_certs[0]).getSubject();
            } catch (CertificateEncodingException e) {
                logger.warn("Unable to get certificate Subject", e);
            }
            return null;
        };

        logger.debug("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - Extracting subject.cn...");
        UserIdentityExtractor cnExtractor = UserIdentityExtractor.getX500NameExtractor(BCStyle.CN, subject);
        Object subjectCn = cnExtractor.extractUserIdentity(certs);
        String subjectCnStr = subjectCn != null ? subjectCn.toString(): null;
        logger.debugf("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - subject.cn='%s'", subjectCnStr);

        logger.debug("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - Extracting subject.surname...");
        UserIdentityExtractor surnameExtractor = UserIdentityExtractor.getX500NameExtractor(BCStyle.SURNAME, subject);
        Object subjectLastName = surnameExtractor.extractUserIdentity(certs);
        String subjectLastNameStr = subjectLastName != null ? subjectLastName.toString(): null;
        logger.debugf("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - subject.surname='%s'", subjectLastNameStr);

        logger.debug("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - Extracting subject.givenname...");
        UserIdentityExtractor givenNameExtractor = UserIdentityExtractor.getX500NameExtractor(BCStyle.GIVENNAME, subject);
        Object subjectFirstName = givenNameExtractor.extractUserIdentity(certs);
        String subjectFirstNameStr = subjectFirstName != null ? subjectFirstName.toString(): null;
        logger.debugf("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - subject.givenname='%s'", subjectFirstNameStr);

        logger.debug("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - Extracting subject.email...");
        UserIdentityExtractor emailExtractor1 = UserIdentityExtractor.getX500NameExtractor(BCStyle.EmailAddress, subject);
        Object subjectEmail1 = emailExtractor1.extractUserIdentity(certs);
        String subjectEmail1Str = subjectEmail1 != null ? subjectEmail1.toString(): null;

        UserIdentityExtractor emailExtractor2 = UserIdentityExtractor.getX500NameExtractor(BCStyle.E, subject);
        Object subjectEmail2 = emailExtractor2.extractUserIdentity(certs);
        String subjectEmail2Str = subjectEmail2 != null ? subjectEmail2.toString(): null;

        String subjectEmailStr = subjectEmail1Str == null ? subjectEmail2Str: subjectEmail1Str;
        logger.debugf("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - subject.email='%s'", subjectEmailStr);

        logger.debug("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - Extracting fiscal number from cn...");
        String subjectFiscalNumberStr = extractFiscalNumber(subjectCnStr);
        logger.debugf("CnsX509ClientCertificateAuthenticator::importUserToKeycloak - fiscalNumber='%s'", subjectFiscalNumberStr);

        String pemCertificate = PemUtils.encodeCertificate(certs[0]);

        return createNewKeycloakUser(context, userIdentity, subjectEmailStr, subjectFirstNameStr, subjectLastNameStr, subjectFiscalNumberStr, pemCertificate);
    }

    protected UserModel createNewKeycloakUser(AuthenticationFlowContext context, String username, String email, String firstname, String lastname, 
        String fiscalNumber, String pemCertificate) {
        logger.infof("Creating new user: %s, email: %s, first name: %s, last name: %s, fiscalNumber: %s to local Keycloak storage", username, email, firstname, lastname, fiscalNumber);

        RealmModel realm = context.getRealm();
        UserModel user = context.getSession().userLocalStorage().addUser(realm, username);
        user.setEnabled(true);
        user.setEmail(email);
        if (email != null && email.length() > 0)
            user.setEmailVerified(true);

        user.setFirstName(firstname);
        user.setLastName(lastname);
        user.setSingleAttribute("fiscalNumber", fiscalNumber);
        //user.setSingleAttribute(DEFAULT_ATTRIBUTE_NAME, userIdentity);

        return user;
    }

    protected String extractFiscalNumber(String subjectCn)
    {
        String _pattern = "^([-A-Z0-9]+)\\/";
        Pattern r = Pattern.compile(_pattern, Pattern.CASE_INSENSITIVE);
        Matcher m = r.matcher(subjectCn);

        if (!m.find()) {
            logger.debugf("[extractFiscalNumber] No matches were found for input \"%s\", pattern=\"%s\"", subjectCn, _pattern);
            return null;
        }

        if (m.groupCount() != 1) {
            logger.debugf("[extractFiscalNumber] Match produced more than a single group for input \"%s\", pattern=\"%s\"", subjectCn, _pattern);
            return null;
        }

        return m.group(1);
    }

    private Response createErrorResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         String errorMessage,
                                         String ... errorParameters) {

        return createResponse(context, subjectDN, false, errorMessage, errorParameters);
    }

    private Response createSuccessResponse(AuthenticationFlowContext context,
                                           String subjectDN) {
        return createResponse(context, subjectDN, true, null, null);
    }

    private Response createResponse(AuthenticationFlowContext context,
                                         String subjectDN,
                                         boolean isUserEnabled,
                                         String errorMessage,
                                         Object[] errorParameters) {

        LoginFormsProvider form = context.form();
        if (errorMessage != null && errorMessage.trim().length() > 0) {
            List<FormMessage> errors = new LinkedList<>();

            errors.add(new FormMessage(errorMessage));
            if (errorParameters != null) {

                for (Object errorParameter : errorParameters) {
                    if (errorParameter == null) continue;
                    for (String part : errorParameter.toString().split("\n")) {
                        errors.add(new FormMessage(part));
                    }
                }
            }
            form.setErrors(errors);
        }

        MultivaluedMap<String,String> formData = new MultivaluedHashMap<>();
        formData.add("username", context.getUser() != null ? context.getUser().getUsername() : "unknown user");
        formData.add("subjectDN", subjectDN);
        formData.add("isUserEnabled", String.valueOf(isUserEnabled));

        form.setFormData(formData);

        return form.createX509ConfirmPage();
    }

    private void dumpContainerAttributes(AuthenticationFlowContext context) {

        Enumeration<String> attributeNames = context.getHttpRequest().getAttributeNames();
        while(attributeNames.hasMoreElements()) {
            String a = attributeNames.nextElement();
            logger.tracef("[X509ClientCertificateAuthenticator:dumpContainerAttributes] \"%s\"", a);
        }
    }

    private boolean userEnabled(AuthenticationFlowContext context, UserModel user) {
        if (!user.isEnabled()) {
            context.getEvent().user(user);
            context.getEvent().error(Errors.USER_DISABLED);
            return false;
        }
        return true;
    }

    private boolean invalidUser(AuthenticationFlowContext context, UserModel user) {
        if (user == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            return true;
        }
        return false;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        super.action(context);
    }
}
