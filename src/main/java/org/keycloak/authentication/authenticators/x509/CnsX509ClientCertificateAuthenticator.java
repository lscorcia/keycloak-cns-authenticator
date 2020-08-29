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

import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import javax.ws.rs.core.MultivaluedHashMap;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

public class CnsX509ClientCertificateAuthenticator extends X509ClientCertificateAuthenticator {

    @Override
    public void close() {
        logger.info("SCORCIA MyX509ClientCertificateAuthenticator::close");
        super.close();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.info("SCORCIA MyX509ClientCertificateAuthenticator::authenticate");
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.info("SCORCIA MyX509ClientCertificateAuthenticator::action");
        super.action(context);
    }
}
