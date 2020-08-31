[![Build Status](https://travis-ci.com/lscorcia/keycloak-cns-authenticator.svg?branch=master)](https://travis-ci.com/lscorcia/keycloak-cns-authenticator) 
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/lscorcia/keycloak-cns-authenticator?sort=semver)](https://img.shields.io/github/v/release/lscorcia/keycloak-cns-authenticator?sort=semver) 
[![GitHub All Releases](https://img.shields.io/github/downloads/lscorcia/keycloak-cns-authenticator/total)](https://img.shields.io/github/downloads/lscorcia/keycloak-cns-authenticator/total)
[![GitHub issues](https://img.shields.io/github/issues/lscorcia/keycloak-cns-authenticator)](https://github.com/lscorcia/keycloak-cns-authenticator/issues)

# keycloak-cns-authenticator
Keycloak (https://www.keycloak.org/) custom authenticator for the Italian Carta Nazionale dei Servizi (CNS)

## Project details
The Italian CNS is an X.509 based authentication mechanism that uses digital certificates on Smart Cards/USB
Tokens to provide trusted authentication to Public Administrations. There is a bunch of accredited institutions
(https://eidas.agid.gov.it/TL/TSL-IT.xml) that can issue cards and they are widespread because every company
in Italy must have at least one.

Keycloak natively supports X.509 authentication, however its use is really limited because it only allows
the "corporate" use of certificates by requiring that all certificates are associated to existing users
beforehand. This is obviously not the case for the Italian CNS.

This project aims to create a new Authenticator that automatically creates users when a new certificate
is presented to Keycloak.

## Status
This project is under development, so for the moment I won't publish any release and you will have to build it yourself.  
It works and allows the creation of users from the data contained in the client certificate. The attribute
mapping is hardcoded - if you want to change it, please see file `CnsX509ClientCertificateAuthenticator.java`.

Until the project gets to a stable release, it will be targeting the most recent release of Keycloak as 
published on the website (see property `version.keycloak` in file pom.xml). Currently the main branch is 
targeting Keycloak 11.0.1. **Do not use this provider with previous versions of Keycloak, it won't work!**

## Build requirements
* git
* JDK8+
* Maven

## Build
Just run `mvn clean package` for a full rebuild. The output package will
be generated under `target/cns-authenticator.jar`.

## Deployment
This provider should be deployed as a module, i.e. copied under
`{$KEYCLOAK_PATH}/standalone/deployments/`, with the right permissions.
Keycloak will take care of loading the module, no restart needed.  

Use this command for reference:  
```
mvn clean package && \
sudo install -C -o keycloak -g keycloak target/cns-authenticator.jar /opt/keycloak/standalone/deployments/
```

If successful you will find a new Execution Flow type called `CNS X509/Validate Username Form` in the
`Add Execution` drop down list in the Authentication configuration screen.

## Open issues and limitations
Feel free to open issues on GitHub if you spot something not working correctly!

## License
This project is released under the Apache License 2.0, same as the main Keycloak
package.
