/*
 * Copyright 2019-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.Conditions.key
import static org.forgerock.openam.amp.dsl.Conditions.pathParamIsOneOf
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forRealmService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.generateSymmetricSecret
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addAttribute
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addToSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.migrateSaml2EntitiesToSecrets
import static org.forgerock.openam.amp.dsl.ServiceTransforms.movePasswordProtectedAliasToSecrets
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteInstance
import static org.forgerock.openam.amp.dsl.ServiceTransforms.moveSaml2EncryptionAlgorihtmsToExtendedMetadata
import static org.forgerock.openam.amp.dsl.ServiceTransforms.removeFromSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.removeSaml2CertAliasesAndKeyDescriptorsFromConfig
import static org.forgerock.openam.amp.dsl.ServiceTransforms.replace
import static org.forgerock.openam.amp.dsl.ServiceTransforms.where
import static org.forgerock.openam.amp.dsl.ServiceTransforms.within
import static org.forgerock.openam.amp.dsl.valueproviders.ValueProviders.removedFromSetProvider
import static org.forgerock.openam.amp.dsl.valueproviders.ValueProviders.valueOfAttribute
import static org.forgerock.openam.amp.framework.core.secrets.Saml2SecretConstants.METADATA_SIGNING_KEY_ALIAS
import static org.forgerock.openam.amp.framework.core.secrets.Saml2SecretConstants.METADATA_SIGNING_KEY_PASS
import static org.forgerock.openam.amp.framework.core.secrets.Saml2SecretConstants.SAML2_ENTRYPASS
import static org.forgerock.openam.amp.framework.core.secrets.Saml2SecretConstants.SAML2_METADATA_SIGNING_KEYSTORE
import static org.forgerock.openam.amp.framework.core.secrets.Saml2SecretConstants.SAML2_METADATA_SIGNING_PURPOSE
import static org.forgerock.openam.amp.rules.CustomRules.addAccessTokenScriptSettings
import static org.forgerock.openam.amp.rules.CustomRules.createSecretStores
import static org.forgerock.openam.amp.rules.CustomRules.migrateIdmIntegrationService

def getRules() {
    List<String> DEFAULT_AUDIT_FILTERS = [
            "/access/http/request/cookies/%AM_COOKIE_NAME%",
            "/access/http/request/cookies/session-jwt",
            "/access/http/request/headers/accept-encoding",
            "/access/http/request/headers/accept-language",
            "/access/http/request/headers/%AM_COOKIE_NAME%",
            "/access/http/request/headers/%AM_AUTH_COOKIE_NAME%",
            "/access/http/request/headers/authorization",
            "/access/http/request/headers/cache-control",
            "/access/http/request/headers/connection",
            "/access/http/request/headers/content-length",
            "/access/http/request/headers/content-type",
            "/access/http/request/headers/proxy-authorization",
            "/access/http/request/headers/X-OpenAM-Password",
            "/access/http/request/headers/X-OpenIDM-Password",
            "/access/http/request/queryParameters/access_token",
            "/access/http/request/queryParameters/id_token_hint",
            "/access/http/request/queryParameters/IDToken1",
            "/access/http/request/queryParameters/Login.Token1",
            "/access/http/request/queryParameters/redirect_uri",
            "/access/http/request/queryParameters/requester",
            "/access/http/request/queryParameters/sessionUpgradeSSOTokenId",
            "/access/http/request/queryParameters/tokenId",
            "/access/http/response/headers/Authorization",
            "/access/http/response/headers/Set-Cookie",
            "/access/http/response/headers/X-OpenIDM-Password",
            "/activity/after/kbaInfo",
            "/activity/after/oathDeviceProfiles",
            "/activity/after/pushDeviceProfiles",
            "/activity/after/userPassword",
            "/activity/after/webauthnDeviceProfiles",
            "/activity/before/kbaInfo",
            "/activity/before/oathDeviceProfiles",
            "/activity/before/pushDeviceProfiles",
            "/activity/before/userPassword",
            "/activity/before/webauthnDeviceProfiles",
            "/config/after",
            "/config/before"
    ]

    List<String> JAVA_AGENT_DELETE_GLOBAL = [
            "agentNotificationUrl", "remoteLogFilename"
    ]

    List<String> JAVA_AGENT_DELETE_APP = [
            "customLogoutHandlers",
            "shortenedPrivilegeAttributeValues",
            "customVerificationHandlers",
            "privilegedAttributeMappingEnabled",
            "privilegedSessionAttribute",
            "customAuthenticationHandlers",
            "defaultPrivilegedAttributes",
            "privilegedAttributeType",
            "privilegedAttributesToLowerCase",
            "privilegedAttributeMap",
            "useInternalLogin",
            "loginErrorUri",
            "applicationLogoutHandlers",
            "notEnforcedUrisRefreshSessionIdleTime",
            "loginContentFile"
    ]

    List<String> JAVA_AGENT_DELETE_SSO = [
            "cdssoClockSkew",
            "cdssoTrustedIdProvider",
            "cdssoUrls",
            "amCookieName",
            "ssoCacheEnabled",
            "cdsso"
    ]

    List<String> JAVA_AGENT_DELETE_AM_SERVICES = [
            "clientPollingPeriod",
            "policyActionBooleanValues",
            "loginUrlPrioritized",
            "loginProbeTimeout",
            "policyClientCacheMode",
            "amLogoutUrl",
            "logoutUrlPrioritized",
            "logoutProbeTimeout",
            "probeLogoutUrl",
            "probeLoginUrl",
            "userDataCacheNotifications",
            "serviceDataCacheTime",
            "serviceDataCacheNotifications",
            "policyClientClockSkew",
            "userDataCachePollingTime",
            "enableClientPolling",
            "policyClientResourceComparators",
            "useRedirectForCompositeAdvice",
            "policyClientPollingInterval"
    ]

    List<String> JAVA_AGENT_DELETE_MISC = [
            "bypassPrincipalList", "encryptionProvider"
    ]

    List<String> JAVA_AGENT_DELETE_ADVANCED = [
            "webServiceResponseProcessor",
            "webServiceAuthorizationErrorContentFile",
            "webServiceEnabled",
            "webServiceEndpoints",
            "jbossWebAuthenticationAvailable",
            "webServiceInternalErrorContentFile",
            "webServiceProcessGetEnabled",
            "webServiceAuthenticator"
    ]

    List<String> WEB_AGENT_DELETE_GLOBAL = [
            "configurationCleanupInterval",
            "agentNotificationUrl",
            "debugLogRotation",
            "debugRotationSize",
            "remoteLogFilename",
            "localAuditLogRotation",
            "localAuditRotationSize",
            "remoteLogSendInterval"
    ]

    List<String> WEB_AGENT_DELETE_SSO = [
            "cdsso", "cdssoUrls"
    ]

    List<String> WEB_AGENT_DELETE_AM_SERVICES = [
            "agentConnectionTimeout", "primaryServerPollingPeriod"
    ]

    List<String> WEB_AGENT_DELETE_MISC = [
            "agentLocale",
            "ignorePreferredNamingUrl",
            "ignoreServerCheck",
            "encodeProfileAttributes"
    ]

    List<String> WEB_AGENT_DELETE_ADVANCED = [
            "overrideProxyHostAndPort",
            "authenticationType",
            "filterPriority",
            "filterConfiguredWithOwa",
            "changeProtocolToHttps",
            "idleSessionTimeoutUrl",
            "checkUserInDomino",
            "useLtpaToken",
            "ltpaTokenCookieName",
            "ltpaTokenConfigurationname",
            "ltpaTokenOrganizationName",
            "loadBalanced",
            "overrideNotificationUrl"
    ]

    return [
            addAccessTokenScriptSettings(),
            forGlobalService("Authentication", deleteAttributes("xuiInterfaceEnabled")),
            forGlobalService("Session", deleteAttributes("iplanet-am-session-constraint-resulting-behavior")),
            forGlobalService("CommonFederationConfiguration", within("montoring", // [sic]
                    deleteAttributes("monitoringIdffClass", "monitoringSaml1Class"))),
            forGlobalService("Naming", within("endpointConfig",
                    deleteAttributes("securityTokenManagerUrl", "federationAssertionManagerUrl"))),
            forGlobalService("OAuth2Provider",
                    within("defaults/advancedOIDCConfig",
                            removeFromSet("supportedRequestParameterEncryptionAlgorithms").with(
                                    "RSA1_5"),
                            addToSet("supportedRequestParameterEncryptionAlgorithms").with(
                                    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"),
                            deleteAttributes("requireRequestUriRegistration")),
                    within("defaults/coreOIDCConfig",
                            removeFromSet("supportedIDTokenEncryptionAlgorithms").with(
                                    "RSA1_5"),
                            addToSet("supportedIDTokenEncryptionAlgorithms").with(
                                    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")),
                    within("defaults/consent",
                            removeFromSet("supportedRcsRequestEncryptionAlgorithms").with(
                                    "RSA1_5"),
                            addToSet("supportedRcsRequestEncryptionAlgorithms").with(
                                    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"),
                            removeFromSet("supportedRcsResponseEncryptionAlgorithms").with(
                                    "RSA1_5"),
                            addToSet("supportedRcsResponseEncryptionAlgorithms").with(
                                    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"))),
            forRealmService("OAuth2Provider",
                    within("advancedOIDCConfig",
                            deleteAttributes("requireRequestUriRegistration"))),
            forGlobalService("DataStoreInstance",
                    addAttribute("serverUrls").with(
                            valueOfAttribute("serverHostname") + ":" + valueOfAttribute("serverPort")),
                    deleteAttributes("serverHostname", "serverPort")
            ),
            forGlobalService("AuditLogging",
                    addAttribute("blacklistFieldFilters").with(
                            removedFromSetProvider(valueOfAttribute("fieldFilterPolicy"),
                                    *DEFAULT_AUDIT_FILTERS)),
                    deleteAttributes("fieldFilterPolicy")),
            forGlobalService("AuditLogging",
                    within("defaults",
                            addAttribute("blacklistFieldFilters").with(
                                    removedFromSetProvider(valueOfAttribute("defaults", "fieldFilterPolicy"),
                                            *DEFAULT_AUDIT_FILTERS)),
                            deleteAttributes("fieldFilterPolicy"))),
            forRealmService("AuditLogging",
                    addAttribute("blacklistFieldFilters").with(
                            removedFromSetProvider(valueOfAttribute("fieldFilterPolicy"),
                                    *DEFAULT_AUDIT_FILTERS)),
                    deleteAttributes("fieldFilterPolicy")),
            forGlobalService("DefaultAdvancedProperties",
                    where(key("com.iplanet.am.session.agentSessionIdleTime").is("0"),
                            replace("com.iplanet.am.session.agentSessionIdleTime")
                                    .with("1440")),
                    deleteAttributes("com.sun.identity.plugin.monitoring.saml1.class")),
            forGlobalService("DefaultAdvancedProperties",
                    where(key("opensso.protocol.handler.pkgs").is("com.sun.identity.protocol"),
                            addAttribute("org.forgerock.openam.http.ssl.connection.manager").with(
                                    "com.sun.identity.protocol.AmSslConnectionManager")),
                    deleteAttributes("com.sun.identity.plugin.monitoring.saml1.class")),
            forGlobalService("DefaultAdvancedProperties", deleteAttributes("com.iplanet.am.console.remote",
                    "com.sun.identity.plugin.monitoring.idff.class", "opensso.protocol.handler.pkgs",
                    "com.iplanet.services.cdc.invalidGotoStrings", "org.forgerock.openam.cdc.validLoginURIs")),
            generateSymmetricSecret("am.global.services.saml2.client.storage.jwt.encryption", 32),
            forGlobalService("DefaultSecurityProperties",
                    within("amconfig.header.securitykey",
                            replace("com.sun.identity.saml.xmlsig.keystore").with("%BASE_DIR%/security/keystores/keystore.jceks"),
                            replace("com.sun.identity.saml.xmlsig.storepass").with("%BASE_DIR%/security/secrets/default/.storepass"),
                            replace("com.sun.identity.saml.xmlsig.keypass").with("%BASE_DIR%/security/secrets/default/.keypass")
                    )
            ),
            forGlobalService("Jms",
                    within("batchEvents",
                            deleteAttributes("batchEnabled", "batchThreadCount", "insertTimeoutSec", "shutdownTimeoutSec"))),
            forRealmService("Jms",
                    within("batchEvents",
                            deleteAttributes("batchEnabled", "batchThreadCount", "insertTimeoutSec", "shutdownTimeoutSec"))),
            forGlobalService("SamlV2ServiceConfiguration",
                    deleteAttributes("failOverEnabled"),
                    within("defaults",
                            movePasswordProtectedAliasToSecrets(
                                    METADATA_SIGNING_KEY_ALIAS,
                                    METADATA_SIGNING_KEY_PASS,
                                    SAML2_METADATA_SIGNING_PURPOSE,
                                    SAML2_ENTRYPASS,
                                    SAML2_METADATA_SIGNING_KEYSTORE))),
            forRealmService("SamlV2ServiceConfiguration",
                    movePasswordProtectedAliasToSecrets(
                            METADATA_SIGNING_KEY_ALIAS,
                            METADATA_SIGNING_KEY_PASS,
                            SAML2_METADATA_SIGNING_PURPOSE,
                            SAML2_ENTRYPASS,
                            SAML2_METADATA_SIGNING_KEYSTORE),
                    deleteInstance()),
            forRealmService("Saml2Entity",
                    migrateSaml2EntitiesToSecrets(),
                    moveSaml2EncryptionAlgorihtmsToExtendedMetadata(),
                    removeSaml2CertAliasesAndKeyDescriptorsFromConfig()
            ),
            createSecretStores(),
            forGlobalService("EmailService",
                    within("defaults",
                            addAttribute("emailRateLimitSeconds").with(1))),
            forRealmService("EmailService",
                    addAttribute("emailRateLimitSeconds").with(1)),
            forRealmService("AgentService",
                    addAttribute("javascriptOrigins").with(Collections.emptySet())),
            // ----------------------------- Start: Delete unused Agents properties ------------------------
            forRealmService("J2eeAgents",
                    within("globalJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_GLOBAL)),
                    within("applicationJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_APP)),
                    within("ssoJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_SSO)),
                    within("amServicesJ2EEAgent", deleteAttributes(*JAVA_AGENT_DELETE_AM_SERVICES)),
                    within("miscJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_MISC)),
                    within("advancedJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_ADVANCED)),
                    deleteAttributes(*JAVA_AGENT_DELETE_GLOBAL, *JAVA_AGENT_DELETE_APP, *JAVA_AGENT_DELETE_SSO,
                            *JAVA_AGENT_DELETE_AM_SERVICES, *JAVA_AGENT_DELETE_MISC, *JAVA_AGENT_DELETE_ADVANCED)
            ),
            forRealmService("WebAgents",
                    within("globalWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_GLOBAL)),
                    within("ssoWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_SSO)),
                    within("amServicesWebAgent", deleteAttributes(*WEB_AGENT_DELETE_AM_SERVICES)),
                    within("miscWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_MISC)),
                    within("advancedWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_ADVANCED)),
                    deleteAttributes(*WEB_AGENT_DELETE_GLOBAL, *WEB_AGENT_DELETE_SSO, *WEB_AGENT_DELETE_AM_SERVICES,
                            *WEB_AGENT_DELETE_MISC, *WEB_AGENT_DELETE_ADVANCED)
            ),
            forRealmService("J2EEAgentGroups",
                    within("globalJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_GLOBAL)),
                    within("applicationJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_APP)),
                    within("ssoJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_SSO)),
                    within("amServicesJ2EEAgent", deleteAttributes(*JAVA_AGENT_DELETE_AM_SERVICES)),
                    within("miscJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_MISC)),
                    within("advancedJ2EEAgentConfig", deleteAttributes(*JAVA_AGENT_DELETE_ADVANCED)),
                    deleteAttributes(*JAVA_AGENT_DELETE_GLOBAL, *JAVA_AGENT_DELETE_APP, *JAVA_AGENT_DELETE_SSO,
                            *JAVA_AGENT_DELETE_AM_SERVICES, *JAVA_AGENT_DELETE_MISC, *JAVA_AGENT_DELETE_ADVANCED)
            ),
            forRealmService("WebAgentGroups",
                    within("globalWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_GLOBAL)),
                    within("ssoWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_SSO)),
                    within("amServicesWebAgent", deleteAttributes(*WEB_AGENT_DELETE_AM_SERVICES)),
                    within("miscWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_MISC)),
                    within("advancedWebAgentConfig", deleteAttributes(*WEB_AGENT_DELETE_ADVANCED)),
                    deleteAttributes(*WEB_AGENT_DELETE_GLOBAL, *WEB_AGENT_DELETE_SSO, *WEB_AGENT_DELETE_AM_SERVICES,
                            *WEB_AGENT_DELETE_MISC, *WEB_AGENT_DELETE_ADVANCED)
            ),
            // ------------------------------- End: Delete unused Agents properties ------------------------
            // ------------------------------- Start: Add new Agents properties ----------------------------
            forRealmService("J2eeAgents",
                    within("advancedJ2EEAgentConfig",
                            addAttribute("postDataCacheTtlMin").with(5),
                            addAttribute("ssoExchangeCacheTTL").with(5),
                            addAttribute("jwtCacheTTL").with(30),
                            addAttribute("sessionCacheTTL").with(15),
                            addAttribute("jwtCacheSize").with(5000),
                            addAttribute("ssoExchangeCacheSize").with(100),
                            addAttribute("policyCacheSize").with(5000),
                            addAttribute("policyCachePerUser").with(50),
                            addAttribute("monitoringToCSV").with(false),
                            addAttribute("fragmentRelayUri").with(valueOfAttribute("")),
                            addAttribute("idleTimeRefreshWindow").with(1)

                    ),
                    within("amServicesJ2EEAgent",
                            addAttribute("customLoginEnabled").with(false),
                            addAttribute("legacyLoginUrlList").with([""].toSet()),
                            addAttribute("agentAdviceEncode").with(false),
                            addAttribute("restrictToRealm").with(valueOfAttribute("")),
                            addAttribute("authSuccessRedirectUrl").with(false),
                            addAttribute("policyClientPollingInterval").with(3)
                    ),
                    within("applicationJ2EEAgentConfig",
                            addAttribute("notEnforcedFavicon").with(true)
                    ),
                    within("globalJ2EEAgentConfig",
                            addAttribute("debugLogfilePrefix").with(valueOfAttribute("")),
                            addAttribute("debugLogfileSuffix").with("-yyyy.MM.dd-HH.mm.ss"),
                            addAttribute("debugLogfileRotationMinutes").with(-1),
                            addAttribute("debugLogfileRotationSize").with(52428800),
                            addAttribute("debugLogfileRetentionCount").with(-1),
                            addAttribute("debugLogfileDirectory").with(valueOfAttribute("")),
                            addAttribute("localAuditLogfilePath").with(valueOfAttribute("")),
                            addAttribute("localAuditLogfileRetentionCount").with(-1),
                            addAttribute("agentSessionChangeNotificationsEnabled").with(true),
                            addAttribute("fallforwardModeEnabled").with(false),
                            addAttribute("preAuthCookieName").with("amFilterCDSSORequest"),
                            addAttribute("preAuthCookieMaxAge").with(300),
                            addAttribute("redirectAttemptLimitCookieName").with("amFilterRDParam"),
                            addAttribute("loginAttemptLimitCookieName").with("amFilterParam")
                    ),
                    within("miscJ2EEAgentConfig",
                            addAttribute("loginReasonParameterName").with(valueOfAttribute("")),
                            addAttribute("loginReasonMap").with(valueOfAttribute("")),
                            addAttribute("authFailReasonUrl").with(valueOfAttribute("")),
                            addAttribute("authFailReasonParameterRemapper").with(valueOfAttribute("")),
                            addAttribute("authFailReasonParameterName").with(valueOfAttribute("")),
                            addAttribute("gotoUrl").with(valueOfAttribute("")),
                            addAttribute("wantedHttpUrlParams").with([""].toSet()),
                            addAttribute("wantedHttpUrlRegexParams").with([""].toSet()),
                            addAttribute("unwantedHttpUrlParams").with([""].toSet()),
                            addAttribute("unwantedHttpUrlRegexParams").with([""].toSet()),
                            addAttribute("serviceResolverClass").with(valueOfAttribute(""))
                    ),
                    within("ssoJ2EEAgentConfig",
                            addAttribute("acceptIPDPCookie").with(false),
                            addAttribute("httpOnly").with(true),
                            addAttribute("encodeCookies").with(false),
                            addAttribute("secureCookies").with(false),
                            addAttribute("setCookieInternalMap").with(valueOfAttribute("")),
                            addAttribute("setCookieAttributeMap").with(valueOfAttribute("")),
                            addAttribute("excludedUserAgentsList").with([""].toList()),
                            addAttribute("authExchangeUri").with(valueOfAttribute("")),
                            addAttribute("authExchangeCookieName").with(valueOfAttribute(""))
                    )
            ),
            forRealmService("WebAgents",
                    within("globalWebAgentConfig",
                            addAttribute("resetIdleTime").with(false),
                            addAttribute("jwtAuditWhitelist").with(valueOfAttribute("")),
                            addAttribute("disableJwtAudit").with(false)
                    ),
                    within("applicationWebAgentConfig",
                            addAttribute("notEnforcedUrlsRegex").with(false),
                            addAttribute("notEnforcedIpsList").with([""].toSet()),
                            addAttribute("notEnforcedIpsRegex").with(false)
                    ),
                    within("ssoWebAgentConfig",
                            addAttribute("cookieResetOnRedirect").with(false),
                            addAttribute("httpOnly").with(true),
                            addAttribute("persistentJwtCookie").with(false),
                            addAttribute("acceptSsoToken").with(false),
                            addAttribute("multivaluePreAuthnCookie").with(false),
                            addAttribute("sameSite").with(valueOfAttribute(""))
                    ),
                    within("amServicesWebAgent",
                            addAttribute("customLoginMode").with(0),
                            addAttribute("enableLogoutRegex").with(false),
                            addAttribute("logoutUrlRegex").with(valueOfAttribute("")),
                            addAttribute("logoutRedirectDisabled").with(false),
                            addAttribute("invalidateLogoutSession").with(true),
                            addAttribute("conditionalLoginUrl").with(valueOfAttribute("")),
                            addAttribute("regexConditionalLoginPattern").with(valueOfAttribute("")),
                            addAttribute("regexConditionalLoginUrl").with(valueOfAttribute("")),
                            addAttribute("publicAmUrl").with(valueOfAttribute("")),
                            addAttribute("compositeAdviceEncode").with(false)
                    ),
                    within("miscWebAgentConfig",
                            addAttribute("addCacheControlHeader").with(false),
                            addAttribute("compositeAdviceRedirect").with(false),
                            addAttribute("invalidUrlRegex").with(valueOfAttribute("")),
                            addAttribute("urlJsonResponse").with(valueOfAttribute("")),
                            addAttribute("headerJsonResponse").with(valueOfAttribute("")),
                            addAttribute("invertUrlJsonResponse").with(false),
                            addAttribute("statusCodeJsonResponse").with(202),
                            addAttribute("mineEncodeHeader").with(0)
                    ),
                    within("advancedWebAgentConfig",
                            addAttribute("fragmentRedirectEnabled").with(false),
                            addAttribute("pdpStickySessionCookieName").with(valueOfAttribute("")),
                            addAttribute("pdpStickySessionMode").with("off"),
                            addAttribute("pdpStickySessionValue").with(valueOfAttribute("")),
                            addAttribute("pdpJavascriptRepost").with(false),
                            addAttribute("pdpSkipPostUrl").with(valueOfAttribute(""))
                    )
            ),
            // ------------------------------- End: Add new Agents properties ------------------------------
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["OIDC_CLAIMS", "OAUTH2_ACCESS_TOKEN_MODIFICATION"]),
                            addToSet("whiteList").with(
                                    "org.forgerock.openam.oauth2.token.macaroon.MacaroonAccessToken",
                                    "org.forgerock.macaroons.Macaroon"))),
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["AUTHENTICATION_SERVER_SIDE"]),
                            addToSet("whiteList").with(
                                    "org.forgerock.openam.scripting.idrepo.ScriptIdentityRepository")),
                    where(pathParamIsOneOf("contexts", ["AUTHENTICATION_TREE_DECISION_NODE"]),
                            addToSet("whiteList").with(
                                    "org.forgerock.openam.core.rest.devices.profile.DeviceProfilesDao",
                                    "org.forgerock.openam.scripting.idrepo.ScriptIdentityRepository",
                                    "org.forgerock.openam.scripting.api.secrets.ScriptedSecrets",
                                    "org.forgerock.openam.scripting.api.secrets.Secret"))),
            forRealmService("ScriptedDecision",
                    addAttribute("inputs").with(["*"].toSet()),
                    addAttribute("outputs").with(["*"].toSet())),
            migrateIdmIntegrationService()
    ]
}
