/*
 * Copyright 2019-2023 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import org.forgerock.openam.amp.dsl.ServicePathCreationMethod
import org.forgerock.openam.amp.dsl.conditions.ServiceInstanceCondition
import org.forgerock.openam.amp.rules.CustomMatcherConditions

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

import static org.forgerock.openam.amp.dsl.Conditions.entityIdContains
import static org.forgerock.openam.amp.dsl.Conditions.entityIdIn
import static org.forgerock.openam.amp.dsl.Conditions.entityIdIs
import static org.forgerock.openam.amp.dsl.Conditions.entityIdMatches
import static org.forgerock.openam.amp.dsl.Conditions.key
import static org.forgerock.openam.amp.dsl.ConfigTransforms.addToScriptingWhitelistForService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forAllServices
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forRealmService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forServicesMatching
import static org.forgerock.openam.amp.dsl.ServicePathCreationMethod.CREATE_IF_MISSING
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addAttribute
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addToSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.appendSocialProviderFormPostRedirectUriWithEntityId
import static org.forgerock.openam.amp.dsl.ServiceTransforms.configureOidcIssuerFromWellKnown
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteInstance
import static org.forgerock.openam.amp.dsl.ServiceTransforms.forVersionBefore
import static org.forgerock.openam.amp.dsl.ServiceTransforms.forVersionsBefore
import static org.forgerock.openam.amp.dsl.ServiceTransforms.moveKeyAliasToSecretsApi
import static org.forgerock.openam.amp.dsl.ServiceTransforms.removeFromSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.replace
import static org.forgerock.openam.amp.dsl.ServiceTransforms.updateServerDefaultKeyTransform
import static org.forgerock.openam.amp.dsl.ServiceTransforms.upgradePrivateKeyJwtAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.upgradeSocialProviderSigningAndEncryptionAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.where
import static org.forgerock.openam.amp.dsl.ServiceTransforms.within
import static org.forgerock.openam.amp.dsl.ServiceTransforms.withinSet
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.addNewGlobalServiceInstance
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.addNewService
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.forAllSettings
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.forDefaultInstanceSettings
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.forInstanceSettings
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.forNamedInstanceSettings
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.forRealmDefaults
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.forSettings
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.setVersion
import static org.forgerock.openam.amp.dsl.valueproviders.ValueProviders.originalValueOfAttribute
import static org.forgerock.openam.amp.dsl.valueproviders.ValueProviders.valueOfAttribute
import static org.forgerock.openam.amp.rules.CustomRules.createEmailServiceInstancesFbc
import static org.forgerock.openam.amp.rules.CustomRules.createSecretStores
import static org.forgerock.openam.amp.rules.CustomRules.migrateFapiSettingsAcrossServiceSections
import static org.forgerock.openam.amp.rules.CustomRules.updateOAuth2PluginsSettings

/**
 * Single file of idempotent upgrade rules for the next release.
 * The rules in this file will become the rules for the next release.
 *
 * @return The combined set of evaluated closure.
 */
def getRules() {
    return [
            /*
             Rules will be added here as configuration requires updating.

             Ensure that when adding new rules, existing rules are not modified.
             This is because the existing rules may have already been applied to some deployments
             and these rules may not ever run again. Resulting in modifying an existing rule definition
             not applying the config change required.
             */

            //---- Start Rules for: AME-20076 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration"),
                            addToSet("whiteList")
                                    .with("org.forgerock.openam.scripting.api.secrets.ScriptedSecrets",
                                            "org.forgerock.openam.scripting.api.secrets.Secret"),
                    ),
            )),
            //---- End Rules ----

            //---- Start Rules for: AME-13670 ----
            addNewService("MultiFactorRegistrationOptionsNode"),
            addNewService("PushRegistrationNode"),
            addNewService("OptOutMultiFactorAuthenticationNode"),
            addNewService("GetAuthenticatorAppNode"),
            //---- End Rules ----

            //---- Start Rules for: AME-13690 ----
            addNewService("OathRegistrationNode"),
            addNewService("OathTokenVerifierNode"),
            //---- End Rules ----

            //---- Start Rules for: AME-20143 ----
            forService("ScriptingService",
                    forDefaultInstanceSettings(
                            where(entityIdIs("default/OAUTH2_ACCESS_TOKEN_MODIFICATION/engineConfiguration"),
                                    addToSet("whiteList").with(
                                            "java.util.AbstractMap\$SimpleImmutableEntry",
                                            "org.forgerock.json.JsonValue")))),
            //---- End Rules ----

            //---- Start Rules for: AME-16537 ----
            forRealmService("RemoteConsentService",
                    moveKeyAliasToSecretsApi("signingKeyAlias", ["am.services.oauth2.remote.consent.response.signing.RSA"]),
                    moveKeyAliasToSecretsApi("encryptionKeyAlias", ["am.services.oauth2.remote.consent.request.encryption"])),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-14915 ----
            forRealmService("AgentService",
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.sunServiceID == "OAuth2Client" },
                                    within("advancedOAuth2ClientConfig",
                                            where(key("customProperties").isNotPresent(),
                                                    addAttribute("customProperties").with(Collections.emptySet())))))),
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_ACCESS_TOKEN_MODIFICATION/engineConfiguration"),
                            addToSet("whiteList")
                                    .with("java.util.HashMap\$KeySet", "java.net.URI",
                                            "org.forgerock.oauth2.core.GrantType"),
                    ),
                    where(entityIdIs("default/OIDC_CLAIMS/engineConfiguration"),
                            addToSet("whiteList")
                                    .with("java.util.HashMap\$KeySet", "java.net.URI",
                                            "org.forgerock.oauth2.core.GrantType"),
                    )
            )),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-16844 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            within("advancedOAuth2Config",
                                    // Order is important - add before remove otherwise the second where condition fails
                                    where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                            addToSet("responseTypeClasses").with("id_token|org.forgerock.openidconnect.IdTokenResponseTypeHandler")),
                                    where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                            removeFromSet("responseTypeClasses").with("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler")))),
                    forSettings(
                            within("advancedOAuth2Config",
                                    // Order is important - add before remove otherwise the second where condition fails
                                    where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                            addToSet("responseTypeClasses").with("id_token|org.forgerock.openidconnect.IdTokenResponseTypeHandler")),
                                    where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                            removeFromSet("responseTypeClasses").with("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"))))),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-16536 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            within("coreOIDCConfig",
                                    where(key("overrideableOIDCClaims").isNotPresent(),
                                            addAttribute("overrideableOIDCClaims").with(Collections.emptySet())))
                    ),
                    forSettings(
                            within("coreOIDCConfig",
                                    where(key("overrideableOIDCClaims").isNotPresent(),
                                            addAttribute("overrideableOIDCClaims").with(Collections.emptySet())))
                    )
            ),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-8715 ----
            forRealmService("iPlanetAMAuthLDAPService",
                    forInstanceSettings(where(key("stopLdapbindAfterInmemoryLockedEnabled").isNotPresent(),
                            addAttribute("stopLdapbindAfterInmemoryLockedEnabled").with(false))),
                    forRealmDefaults(where(key("stopLdapbindAfterInmemoryLockedEnabled").isNotPresent(),
                            addAttribute("stopLdapbindAfterInmemoryLockedEnabled").with(false)))),

            forRealmService("sunAMAuthADService",
                    forInstanceSettings(where(key("stopLdapbindAfterInmemoryLockedEnabled").isNotPresent(),
                            addAttribute("stopLdapbindAfterInmemoryLockedEnabled").with(false))),
                    forRealmDefaults(where(key("stopLdapbindAfterInmemoryLockedEnabled").isNotPresent(),
                            addAttribute("stopLdapbindAfterInmemoryLockedEnabled").with(false)))),
            //---- End Rules ----

            //---- Start Rules for: AME-20650 ----
            forService("ScriptingService",
                    forDefaultInstanceSettings(
                            where(entityIdIs("default/OAUTH2_MAY_ACT/engineConfiguration"),
                                    addToSet("whiteList").with(
                                            "org.forgerock.openidconnect.OpenIdConnectToken",
                                            "org.forgerock.oauth2.core.tokenexchange.ExchangeableToken")))),
            //---- End Rules ---

            //---- Start Rules for: AMAGENTS-3643, 3695, 3702, 3781, 3931, 3950, 4001, 4034, OPENAM-17029, OPENAM-19147 ----
            forRealmService("AgentService",
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.sunServiceID == "J2EEAgent" },
                                    within("globalJ2EEAgentConfig",
                                            where(key("lbCookieEnabled").isNotPresent(),
                                                    addAttribute("lbCookieEnabled").with(false))),
                                    within("globalJ2EEAgentConfig",
                                            where(key("lbCookieName").isNotPresent(),
                                                    addAttribute("lbCookieName").with("amlbcookie"))),
                                    within("globalJ2EEAgentConfig",
                                            where(key("agentSessionChangeNotificationsEnabled").exists(),
                                                    deleteAttributes("agentSessionChangeNotificationsEnabled"))),
                                    // After fixing OPENAM-17398 "where(key("localAuditLogfilePath").exists()," should be included
                                    within("globalJ2EEAgentConfig",
                                            deleteAttributes("localAuditLogfilePath")),
                                    // After fixing OPENAM-17398 "where(key("debugLogfileDirectory").exists()," should be included
                                    within("globalJ2EEAgentConfig",
                                            deleteAttributes("debugLogfileDirectory")),
                                    within("applicationJ2EEAgentConfig",
                                            where(key("clientIpValidationMode").isNotPresent(),
                                                    addAttribute("clientIpValidationMode").with(Collections.singletonMap("", "OFF")))),
                                    within("applicationJ2EEAgentConfig",
                                            where(key("clientIpValidationRange").isNotPresent(),
                                                    addAttribute("clientIpValidationRange").with(Collections.emptyMap()))),
                                    within("applicationJ2EEAgentConfig", deleteAttributes("loginFormUri")),
                                    within("advancedJ2EEAgentConfig",
                                            where(key("expiredSessionCacheTTL").isNotPresent(),
                                                    addAttribute("expiredSessionCacheTTL").with(20))),
                                    within("advancedJ2EEAgentConfig",
                                            where(key("expiredSessionCacheSize").isNotPresent(),
                                                    addAttribute("expiredSessionCacheSize").with(500))),
                                    within("ssoJ2EEAgentConfig",
                                            where(key("acceptSsoTokenEnabled").isNotPresent(),
                                                    addAttribute("acceptSsoTokenEnabled").with(false))),
                                    within("ssoJ2EEAgentConfig",
                                            where(key("acceptSsoTokenDomainList").isNotPresent(),
                                                    addAttribute("acceptSsoTokenDomainList").with(Collections.emptySet()))),
                                    within("ssoJ2EEAgentConfig",
                                            where(key("secureCookies").exists(),
                                                    deleteAttributes("secureCookies"))),
                                    within("amServicesJ2EEAgent",
                                            where(key("overridePolicyEvaluationRealmEnabled").isNotPresent(),
                                                    addAttribute("overridePolicyEvaluationRealmEnabled").with(false))),
                                    within("miscJ2EEAgentConfig",
                                            where(key("agent302RedirectEnabled").isNotPresent(),
                                                    addAttribute("agent302RedirectEnabled").with(true))),
                                    within("miscJ2EEAgentConfig",
                                            where(key("agent302RedirectStatusCode").isNotPresent(),
                                                    addAttribute("agent302RedirectStatusCode").with(200))),
                                    within("miscJ2EEAgentConfig",
                                            where(key("agent302RedirectContentType").isNotPresent(),
                                                    addAttribute("agent302RedirectContentType").with("application/json"))),
                                    within("miscJ2EEAgentConfig",
                                            where(key("agent302RedirectHttpData").isNotPresent(),
                                                    addAttribute("agent302RedirectHttpData").with("{redirect:{requestUri:%REQUEST_URI%,requestUrl:%REQUEST_URL%,targetUrl:%TARGET%}}"))),
                                    within("miscJ2EEAgentConfig",
                                            where(key("agent302RedirectNerList").isNotPresent(),
                                                    addAttribute("agent302RedirectNerList").with(Collections.emptySet()))),
                                    within("miscJ2EEAgentConfig",
                                            where(key("agent302RedirectInvertEnabled").isNotPresent(),
                                                    addAttribute("agent302RedirectInvertEnabled").with(false))),
                                    // // After fixing OPENAM-17398 "where(key("serviceResolverClass").exists()," should be included
                                    within("miscJ2EEAgentConfig",
                                            deleteAttributes("serviceResolverClass")))),
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.sunServiceID == "WebAgent" },
                                    within("globalWebAgentConfig",
                                            where(key("amLbCookieEnable").isNotPresent(),
                                                    addAttribute("amLbCookieEnable").with(false)))))),
            //---- End Rules ----

            //---- Start Rules for: AME-16544 ----
            forGlobalService("iPlanetAMSessionService",
                    within("stateless",
                            moveKeyAliasToSecretsApi("statelessSigningRsaCertAlias", ["am.global.services.session.clientbased.signing"]),
                            moveKeyAliasToSecretsApi("statelessEncryptionRsaCertAlias", ["am.global.services.session.clientbased.encryption"]))),
            //---- End Rules ---

            //---- Start Rules for: AME-20750 ----
            forRealmService("SocialIdentityProviders",
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.entityId.toString().containsIgnoreCase("default/oidcConfig/") },
                                    where(key("jwtRequestParameterOption").isNotPresent(),
                                            addAttribute("jwtRequestParameterOption").with("NONE")),
                                    where(key("requestObjectSigningAlg").isNotPresent(),
                                            addAttribute("requestObjectSigningAlg").with("")),
                                    where(key("requestObjectEncryptionAlg").isNotPresent(),
                                            addAttribute("requestObjectEncryptionAlg").with(""))))),
            //---- End Rules ---
            //---- Start Rules for radius server secrets
            forService("RadiusServerService",
                    forInstanceSettings("default",
                            where(
                                    key("clientSecret").isNotEmpty()
                                            .and(CustomMatcherConditions.key("clientSecret").isNotSecure()),
                                    replace("clientSecret")
                                            .with(originalValueOfAttribute("clientSecret").modify(value -> securifyString(value))))),
            ),
            //---- End rules for radius server secrets

            //---- Start Rules for: OPENAM-17047 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_ACCESS_TOKEN_MODIFICATION/engineConfiguration"),
                            where(key("whiteList").doesNotContain("java.util.Collections\$*"),
                                    addToSet("whiteList")
                                            .with("java.util.Collections\$UnmodifiableSet",
                                                    "java.util.Collections\$UnmodifiableMap")
                            )
                    ),
                    where(entityIdIs("default/OIDC_CLAIMS/engineConfiguration"),
                            where(key("whiteList").doesNotContain("java.util.Collections\$*"),
                                    addToSet("whiteList")
                                            .with("java.util.Collections\$UnmodifiableSet",
                                                    "java.util.Collections\$UnmodifiableMap"),)
                    ),
            )),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-17096 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            within("advancedOIDCConfig",
                                    where(key("includeAllKtyAlgCombinationsInJwksUri").isNotPresent(),
                                            addAttribute("includeAllKtyAlgCombinationsInJwksUri").with(false)))),
                    forSettings(
                            within("advancedOIDCConfig",
                                    where(key("includeAllKtyAlgCombinationsInJwksUri").isNotPresent(),
                                            addAttribute("includeAllKtyAlgCombinationsInJwksUri").with(false))))),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("advancedOIDCConfig",
                                    where(key("includeAllKtyAlgCombinationsInJwksUri").isNotPresent(),
                                            addAttribute("includeAllKtyAlgCombinationsInJwksUri").with(false)))),
                    forRealmDefaults(
                            within("advancedOIDCConfig",
                                    where(key("includeAllKtyAlgCombinationsInJwksUri").isNotPresent(),
                                            addAttribute("includeAllKtyAlgCombinationsInJwksUri").with(false))))
            ),
            //---- End Rules ----

            //---- Start Rules for: AME-21318 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            where(key("pluginsConfig").isNotPresent(),
                                    addAttribute("pluginsConfig").with([:])),
                            within("pluginsConfig",
                                    where(key("scopeImplementationClass").isNotPresent(),
                                            addAttribute("scopeImplementationClass").with(
                                                    valueOfAttribute("advancedOAuth2Config", "scopeImplementationClass")))),
                            within("advancedOAuth2Config", deleteAttributes("scopeImplementationClass"))
                    ),
                    forSettings(
                            where(key("advancedOAuth2Config").contains("scopeImplementationClass"),
                                within("pluginsConfig", ServicePathCreationMethod.CREATE_IF_MISSING,
                                            addAttribute("scopeImplementationClass").with(
                                                valueOfAttribute("advancedOAuth2Config", "scopeImplementationClass"))),
                            within("advancedOAuth2Config", deleteAttributes("scopeImplementationClass"))
                    )
                    )
            ),
            //---- End Rules ----

            //---- Start Rules for: AME-21304 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            where(key("pluginsConfig").isNotPresent(),
                                    addAttribute("pluginsConfig").with([:])),
                            within("pluginsConfig",
                                    where(key("oidcClaimsScript").isNotPresent(),
                                            addAttribute("oidcClaimsScript").with(
                                                    valueOfAttribute("coreOIDCConfig", "oidcClaimsScript")))),
                            within("coreOIDCConfig", deleteAttributes("oidcClaimsScript"))
                    ),
                    forSettings(
                            where(key("coreOIDCConfig").contains("oidcClaimsScript"),
                                    within("pluginsConfig", ServicePathCreationMethod.CREATE_IF_MISSING,
                                            addAttribute("oidcClaimsScript").with(
                                                    valueOfAttribute("coreOIDCConfig", "oidcClaimsScript"))),
                            within("coreOIDCConfig", deleteAttributes("oidcClaimsScript"))
                    )
            ),
            ),
            //---- End Rules ----

            //---- Start Rules for: AME-21305 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            where(key("pluginsConfig").isNotPresent(),
                                    addAttribute("pluginsConfig").with([:])),
                            within("pluginsConfig",
                                    where(key("accessTokenModificationScript").isNotPresent(),
                                            addAttribute("accessTokenModificationScript").with(
                                                    valueOfAttribute("coreOAuth2Config", "accessTokenModificationScript")))),
                            within("coreOAuth2Config", deleteAttributes("accessTokenModificationScript"))
                    ),
                    forSettings(
                            where(key("coreOAuth2Config").contains("accessTokenModificationScript"),
                                    within("pluginsConfig", ServicePathCreationMethod.CREATE_IF_MISSING,
                                            addAttribute("accessTokenModificationScript").with(
                                                    valueOfAttribute("coreOAuth2Config", "accessTokenModificationScript"))),
                            within("coreOAuth2Config", deleteAttributes("accessTokenModificationScript"))
                    )
                    )
            ),
            //---- End Rules ----

            //---- Start Rules for: AME-20751 ----
            forRealmService("SocialIdentityProviders",
                    forInstanceSettings(
                            where(entityIdContains("default/oidcConfig/"),
                                    where(key("acrValues").isNotPresent(),
                                            addAttribute("acrValues").with(Collections.emptyList())),
                                    where(key("encryptedIdTokens").isNotPresent(),
                                            addAttribute("encryptedIdTokens").with(false)),
                                    where(key("issuer").isNotPresent(),
                                            configureOidcIssuerFromWellKnown())))),
            //---- End Rules ---

            //---- Start Rules for: OPENAM-17167 ----
            forRealmService("SocialIdentityProviders",
                    forInstanceSettings(
                            where(entityIdContains("default/linkedinconfig/"),
                                    upgradePrivateKeyJwtAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/oauth2config/"),
                                    upgradePrivateKeyJwtAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/oidcConfig/"),
                                    upgradePrivateKeyJwtAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/vkconfig/"),
                                    upgradePrivateKeyJwtAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/wechatconfig/"),
                                    upgradePrivateKeyJwtAttributes())),
            ),
            //---- End Rules ---

            //---- Start Rules for: OPENAM-17136 ----
            forRealmService("AgentService",
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.sunServiceID == "OAuth2Client" },
                                    within("advancedOAuth2ClientConfig",
                                            where(key("tosURI").isNotPresent(),
                                                    addAttribute("tosURI").with(Collections.emptySet())),
                                            where(key("softwareIdentity").isNotPresent(),
                                                    addAttribute("softwareIdentity").with("")),
                                            where(key("softwareVersion").isNotPresent(),
                                                    addAttribute("softwareVersion").with("")))))),
            //---- End Rules for OPENAM-17136 ----

            //---- Start Rules for: OPENAM-17287 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            within("coreOIDCConfig",
                                    where(key("oidcDiscoveryEndpointEnabled").isNotPresent(),
                                            addAttribute("oidcDiscoveryEndpointEnabled").with(false)))),
                    forSettings(
                            within("coreOIDCConfig",
                                    where(key("oidcDiscoveryEndpointEnabled").isNotPresent(),
                                            addAttribute("oidcDiscoveryEndpointEnabled").with(true))))),

            //---- End Rules ----

            //---- Start Rules for: CLOUD-2917 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_MAY_ACT"),
                            replace("defaultScript").with((String) null),
                    ),
            )),
            //---- End Rules for: CLOUD-2917 ----

            //---- Start Rules for: AME-20992 ----
            forRealmService("AgentService",
                    forAllSettings(
                            forVersionBefore("3.0.0.0",
                                    within("coreOAuth2ClientConfig",
                                            deleteAttributes("backchannel_logout_uri", "backchannel_logout_session_required")
                                    ),
                                    within("coreOpenIDClientConfig",
                                            addAttribute("backchannel_logout_uri").with(
                                                    valueOfAttribute("coreOAuth2ClientConfig", "backchannel_logout_uri")),
                                            addAttribute("backchannel_logout_session_required").with(
                                                    valueOfAttribute("coreOAuth2ClientConfig", "backchannel_logout_session_required"))
                                    )
                            )
                    )
            ),
            //---- End Rules for: AME-20992 ----

            //---- Start Rules for: AME-20876 ----
            forGlobalService("iPlanetAMPlatformService",
                    forDefaultInstanceSettings(
                            forNamedInstanceSettings("server-default",
                                    addToSet("serverconfig")
                                            .with("openam.private.key.jwt.encryption.algorithm.whitelist=RSA-OAEP,RSA-OAEP-256,ECDH-ES")
                            ))),
            //---- End Rules ---

            //---- Start Rules for OPENAM-17395 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    forVersionsBefore(["3.0.0.1"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.clients.response.timeout=10 seconds")),
                    forVersionsBefore(["3.0.0.1"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.clients.reuse.connections.enabled=true")),
                    forVersionsBefore(["3.0.0.1"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.clients.retry.failed.requests.enabled=true")),
                    forVersionsBefore(["3.0.0.1"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.clients.max.connections=64")),
                    forVersionsBefore(["3.0.0.1"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.clients.connection.timeout=10 seconds")),
                    forVersionsBefore(["3.0.0.1"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.clients.pool.ttl=-1"))),
            //---- End Rules for OPENAM-17395 ----
            //---- Start Rules for: AME-20499 ----
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oidcConfig/apple"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oauth2Config/amazon"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oauth2Config/facebook"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oidcConfig/google"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oauth2Config/instagram"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oidcConfig/itsme"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/linkedInConfig/linkedin"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oauth2Config/microsoft"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oauth2Config/salesforce"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/twitterConfig/twitter"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/vkConfig/vkontakte"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/weChatConfig/wechat"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oauth2Config/wordpress"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            forRealmService("SocialIdentityProviders", forDefaultInstanceSettings(
                    where(entityIdIs("default/oidcConfig/yahoo"),
                            where(key("clientSecret").isNotPresent(), deleteInstance())))),
            //---- End Rules for: AME-20499 ----

            //---- Start Rules for upgrading Social Provider Signing and Encryption ----
            forRealmService("SocialIdentityProviders",
                    forInstanceSettings(
                            where(entityIdContains("default/amazonconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/appleconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/facebookconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/googleconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/instagramconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/linkedinconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/microsoftconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/oauth2config/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/oidcConfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/salesforceconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/twitterconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/vkconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/wechatconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/wordpressconfig/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
                    forInstanceSettings(
                            where(entityIdContains("default/yahoo/"),
                                    upgradeSocialProviderSigningAndEncryptionAttributes())),
            ),

            forGlobalService("iPlanetAMPlatformService",
                    forDefaultInstanceSettings(
                            forNamedInstanceSettings("server-default",
                                    updateServerDefaultKeyTransform()
                                            .updateKey("openam.private.key.jwt.encryption.algorithm.whitelist")
                                            .with("openam.oauth2.client.jwt.encryption.algorithm.allow.list")))),
            //---- End Rules ---

            //---- Start Rules for adding the entity id Social Provider form port redirect ----
            forRealmService("SocialIdentityProviders",
                    forInstanceSettings(
                            where(entityIdContains("default/"),
                                    appendSocialProviderFormPostRedirectUriWithEntityId())),
            ),
            //---- End Rules ---

            //---- Start Rules for: OPENAM-17666 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration"),
                            addToSet("whiteList")
                                    .with("org.forgerock.openam.auth.node.api.NodeState"),
                    ),
            )),
            forService("iPlanetAMPolicyService",
                    where(entityIdIs("Subject/LDAPRoles"), deleteInstance())),
            //---- End Rules ----

            //---- Start Rules for OPENAM-17493 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    forVersionsBefore(["3.0.0.2"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.proxy.uri=")),
                    forVersionsBefore(["3.0.0.2"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.proxy.username=")),
                    forVersionsBefore(["3.0.0.2"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.proxy.password="))),
            //---- End Rules for OPENAM-17493 ----

            //---- Start Rules for OPENAM-17157 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    forVersionsBefore(["3.0.0.3"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.idrepo.ldapv3.proxyauth.passwordreset.adminRequest=isAdminPasswordChangeRequest"))),
            //---- End Rules for OPENAM-17157 ----

            //---- Start Rules for OPENAM-17608 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    forVersionsBefore(["3.0.0.4"],
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.httpclienthandler.system.nonProxyHosts=localhost,127.*,[::1],0.0.0.0,[::0]"))),
            //---- End Rules for OPENAM-17608 ----

            //---- Start Rules for OPENAM-17610 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.smtp.system.connect.timeout=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.smtp.system.connect.timeout=10000")),
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.smtp.system.socket.read.timeout=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.smtp.system.socket.read.timeout=10000")),
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.smtp.system.socket.write.timeout=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.smtp.system.socket.write.timeout=10000")),
                    where(key("serverconfig").contains("org.forgerock.openam.smtp.system.socket.write.timeout=1000"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.smtp.system.socket.write.timeout=10000")),
                    where(key("serverconfig").contains("org.forgerock.openam.smtp.system.socket.write.timeout=1000"),
                            removeFromSet("serverconfig")
                                    .with("org.forgerock.openam.smtp.system.socket.write.timeout=1000"))),
            //---- End Rules for OPENAM-17610 ----

            //---- Start Rules for AME-21411 ----
            addNewService("PassthroughAuthenticationNode"),
            //---- End Rules for AME-21411 ----

            //---- Start Rules for OPENAM-16149 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    where(key("serverconfig").doesNotMatchPattern("openam.oauth2.client.jwt.unreasonable.lifetime.limit.minutes=.*"),
                            addToSet("serverconfig")
                                    .with("openam.oauth2.client.jwt.unreasonable.lifetime.limit.minutes=30"))),
            //---- End Rules for OPENAM-16149 ----

            //---- Start Rule for: Remove reference to OAUTH2 EVALUATE SCOPE, Default Script - AME-21302 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_EVALUATE_SCOPE"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for ----

            //---- Start Rules for: OPENAM-17320 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(
                            within("advancedOAuth2Config",
                                    where(key("useForceAuthnForPromptLogin").exists(),
                                            deleteAttributes("useForceAuthnForPromptLogin"))),
                            within("advancedOIDCConfig",
                                    where(key("useForceAuthnForPromptLogin").isNotPresent(),
                                            addAttribute("useForceAuthnForPromptLogin").with(false)))),
                    forSettings(
                            within("advancedOAuth2Config",
                                    where(key("useForceAuthnForPromptLogin").exists(),
                                            deleteAttributes("useForceAuthnForPromptLogin"))),
                            within("advancedOIDCConfig",
                                    where(key("useForceAuthnForPromptLogin").isNotPresent(),
                                            addAttribute("useForceAuthnForPromptLogin").with(false))))),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("advancedOAuth2Config",
                                    where(key("useForceAuthnForPromptLogin").exists(),
                                            deleteAttributes("useForceAuthnForPromptLogin"))),
                            within("advancedOIDCConfig",
                                    where(key("useForceAuthnForPromptLogin").isNotPresent(),
                                            addAttribute("useForceAuthnForPromptLogin").with(false)))),
                    forRealmDefaults(
                            within("advancedOAuth2Config",
                                    where(key("useForceAuthnForPromptLogin").exists(),
                                            deleteAttributes("useForceAuthnForPromptLogin"))),
                            within("advancedOIDCConfig",
                                    where(key("useForceAuthnForPromptLogin").isNotPresent(),
                                            addAttribute("useForceAuthnForPromptLogin").with(false))))
            ),
            //---- End Rules ----

            //---- Start Rule for: Remove reference to OAUTH2 AUTHORIZE ENDPOINT DATA PROVIDER Default Script - AME-21303 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for ----

            // ---- Start Rule for: Remove reference to OAUTH2 VALIDATE SCOPE Default Script - AME-21297 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_VALIDATE_SCOPE"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for AME-21297 ----

            // ---- Start Rule for: Remove reference to SAML2 IDP Attribute Mapper Default Script - AME-21617 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/SAML2_IDP_ATTRIBUTE_MAPPER"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for AME-21617 ----

            // ---- Start Rule for: Remove reference to SAML2 IDP Adapter Default Script - AME-22086 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/SAML2_IDP_ADAPTER"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for AME-22086 ----

            // ---- Start Rule for: Remove reference to Config Provider Script - AME-22015 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/CONFIG_PROVIDER_NODE"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for AME-22015 ----

            //---- Start Rules for: AME-21024 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(isEngineConfiguration(), addToSet("whiteList")
                            .with("org.forgerock.openam.scripting.api.PrefixedScriptPropertyResolver",
                                    "java.util.List", "java.util.Map")
                    )
            )),
            //---- End Rules ----

            //---- Start Rule for: OPENAM-16863 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.authentication.forceAuth.enabled=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.authentication.forceAuth.enabled=true"))),
            //---- End Rule ----

            //---- Start Rules for: AME-21903
            addNewGlobalServiceInstance("sunAMDelegationService", "Privilege", ["default","Privileges" ], "CacheAdmin")
                    .then(addAttribute("listOfPermissions")
                            .with(["CacheAdmin"])),
            addNewGlobalServiceInstance("sunAMDelegationService", "Permission", ["default","Permissions"], "CacheAdmin")
                    .then(addAttribute("actions")
                            .with(["READ","MODIFY","DELEGATE"]))
                    .then(addAttribute("resource")
                            .with(["REALM/rest/1.0/cache/*"])),
            //---- End Rules ----

            // ---- Start Rule for: OPENAM-17951, OPENAM-17832, OPENAM-18024, OPENAM-18305, OPENAM-18465 ----
            forRealmService("AgentService",
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.sunServiceID == "J2EEAgent" },
                                    within("globalJ2EEAgentConfig",
                                            where(key("recheckAmUnavailabilityInSeconds").isNotPresent(),
                                                    addAttribute("recheckAmUnavailabilityInSeconds").with(5)),
                                            where(key("fallforwardModeEnabled").exists(),
                                                    deleteAttributes("fallforwardModeEnabled"))),
                                    within("advancedJ2EEAgentConfig",
                                            where(key("postDataCacheTtl").exists(),
                                                    deleteAttributes("postDataCacheTtl"))))),
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.sunServiceID == "WebAgent" },
                                    within("advancedWebAgentConfig",
                                            where(key("hostnameToIpAddress").isNotPresent(),
                                                    addAttribute("hostnameToIpAddress").with(Collections.emptyList())),
                                            where(key("apacheAuthDirectives").isNotPresent(),
                                                    addAttribute("apacheAuthDirectives").with((String) null)),
                                            where(key("retainSessionCache").isNotPresent(),
                                                    addAttribute("retainSessionCache").with(false)))))),
            //---- End Rule ----

            //---- Start Rules for: AME-21947 ----
            forRealmService("OAuth2Provider",
                    forRealmDefaults(within("pluginsConfig", updateOAuth2PluginsSettings())),
                    forSettings(within("pluginsConfig", updateOAuth2PluginsSettings()))
            ),
            //---- End Rules ----

            //---- Start Rules for: AME-22018 ----
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("parRequestUriLifetime").isNotPresent(),
                                    addAttribute("parRequestUriLifetime").with(90)))),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("advancedOAuth2Config",
                                    where(key("parRequestUriLifetime").isNotPresent(),
                                        addAttribute("parRequestUriLifetime").with(90))))),
            //---- End Rules ----

            //---- Start Rule for: OPENAM-17404 ----
            forRealmService("sunIdentityRepositoryService",
                forVersionBefore("5.0.0.0",
                    forInstanceSettings(
                            within("userconfig", CREATE_IF_MISSING,
                                    where(key("sun-idrepo-ldapv3-config-user-attributes").doesNotContain("retryLimitNodeCount"),
                                            addToSet("userconfig","sun-idrepo-ldapv3-config-user-attributes").with("retryLimitNodeCount"))),
                    )
                ),
            ),
            //---- End Rule ----

            //---- Start Rules for: AME-22248 ----
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("requirePushedAuthorizationRequests").isNotPresent(),
                                    addAttribute("requirePushedAuthorizationRequests").with(false))
                    )
            ),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("advancedOAuth2Config",
                                    where(key("requirePushedAuthorizationRequests").isNotPresent(),
                                            addAttribute("requirePushedAuthorizationRequests").with(false))
                            )
                    )
            ),
            forRealmService("AgentService",
                    forInstanceSettings(
                            where({ config, configProvider -> config.metaData.sunServiceID == "OAuth2Client" },
                                    within("advancedOAuth2ClientConfig",
                                            where(key("require_pushed_authorization_requests").isNotPresent(),
                                                    addAttribute("require_pushed_authorization_requests").with(false))
                                    )))),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-17756 ----
            forService("OAuth2Provider",
                    forRealmDefaults(
                            within("deviceCodeConfig",
                                    where(key("deviceUserCodeLength").isNotPresent(),
                                            addAttribute("deviceUserCodeLength").with(8))),
                            within("deviceCodeConfig",
                                    where(key("deviceUserCodeCharacterSet").isNotPresent(),
                                            addAttribute("deviceUserCodeCharacterSet")
                                                    .with("234567ACDEFGHJKLMNPQRSTWXYZabcdefhijkmnopqrstwxyz"))),
                            within("pluginsConfig",
                                    where(key("userCodeGeneratorClass").isNotPresent(),
                                            addAttribute("userCodeGeneratorClass")
                                                    .with("org.forgerock.oauth2.core.plugins.registry.DefaultUserCodeGenerator"))))
            ),

            //---- Start Rules for: OPENAM-18124 ----
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("nbfClaimRequiredInRequestObject").isNotPresent(),
                                    addAttribute("nbfClaimRequiredInRequestObject").with(false)),
                            where(key("expClaimRequiredInRequestObject").isNotPresent(),
                                    addAttribute("expClaimRequiredInRequestObject").with(false)),
                            where(key("maxDifferenceBetweenRequestObjectNbfAndExp").isNotPresent(),
                                    addAttribute("maxDifferenceBetweenRequestObjectNbfAndExp").with(0)),
                            where(key("maxAgeOfRequestObjectNbfClaim").isNotPresent(),
                                    addAttribute("maxAgeOfRequestObjectNbfClaim").with(0))
                    ),
                    migrateFapiSettingsAcrossServiceSections()
            ),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("advancedOAuth2Config",
                                    where(key("nbfClaimRequiredInRequestObject").isNotPresent(),
                                            addAttribute("nbfClaimRequiredInRequestObject").with(false)),
                                    where(key("expClaimRequiredInRequestObject").isNotPresent(),
                                            addAttribute("expClaimRequiredInRequestObject").with(false)),
                                    where(key("maxDifferenceBetweenRequestObjectNbfAndExp").isNotPresent(),
                                            addAttribute("maxDifferenceBetweenRequestObjectNbfAndExp").with(0)),
                                    where(key("maxAgeOfRequestObjectNbfClaim").isNotPresent(),
                                            addAttribute("maxAgeOfRequestObjectNbfClaim").with(0))
                            ),
                            migrateFapiSettingsAcrossServiceSections()
                    )
            ),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-18438 ----
            forGlobalService("OAuth2Provider",
                    forSettings(
                            where(key("allowUnauthorisedAccessToUserCodeForm").isNotPresent(),
                                    addAttribute("allowUnauthorisedAccessToUserCodeForm")
                                            .with(true))),
            ),
            //---- End Rules ----

            //---- Start Rule for: OPENAM-18589 ----
            forRealmService("selfService",
                    within("forgottenPassword",
                            where(key("forgottenPasswordTokenPaddingLength").isNotPresent(),
                                    addAttribute("forgottenPasswordTokenPaddingLength").with(450)))),
            //---- End Rule ----

            //---- Start Rules for OPENAM-18701 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.ldap.dncache.expire.time=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.ldap.dncache.expire.time=0"))),
            //---- End Rules for OPENAM-16149 ----

            //---- Start Rules for: AME-22077
            forRealmService("UmaProvider",
                    forRealmDefaults(
                            where(key("generalSettings").isNotPresent(),
                                    addAttribute("generalSettings").with([:])),
                            where(key("supportedUmaProfiles").exists(),
                                    within("generalSettings",
                                            where(key("supportedUmaProfiles").isNotPresent(),
                                                    addAttribute("supportedUmaProfiles").with(
                                                            valueOfAttribute("supportedUmaProfiles"))))),
                            within("generalSettings",
                                    where(key("permissionTicketLifetime").isNotPresent(),
                                            addAttribute("permissionTicketLifetime").with(
                                                    valueOfAttribute("permissionTicketLifetime"))),
                                    where(key("deletePoliciesOnDeleteRS").isNotPresent(),
                                            addAttribute("deletePoliciesOnDeleteRS").with(
                                                    valueOfAttribute("deletePoliciesOnDeleteRS"))),
                                    where(key("deleteResourceSetsOnDeleteRS").isNotPresent(),
                                            addAttribute("deleteResourceSetsOnDeleteRS").with(
                                                    valueOfAttribute("deleteResourceSetsOnDeleteRS"))),
                                    where(key("pendingRequestsEnabled").isNotPresent(),
                                            addAttribute("pendingRequestsEnabled").with(
                                                    valueOfAttribute("pendingRequestsEnabled"))),
                                    where(key("emailResourceOwnerOnPendingRequestCreation").isNotPresent(),
                                            addAttribute("emailResourceOwnerOnPendingRequestCreation").with(
                                                    valueOfAttribute("emailResourceOwnerOnPendingRequestCreation"))),
                                    where(key("emailRequestingPartyOnPendingRequestApproval").isNotPresent(),
                                            addAttribute("emailRequestingPartyOnPendingRequestApproval").with(
                                                    valueOfAttribute("emailRequestingPartyOnPendingRequestApproval"))),
                                    where(key("userProfileLocaleAttribute").isNotPresent(),
                                            addAttribute("userProfileLocaleAttribute").with(
                                                    valueOfAttribute("userProfileLocaleAttribute"))),
                                    where(key("resharingMode").isNotPresent(),
                                            addAttribute("resharingMode").with(
                                                    valueOfAttribute("resharingMode"))),
                                    where(key("grantRptConditions").isNotPresent(),
                                            addAttribute("grantRptConditions").with(
                                                    valueOfAttribute("grantRptConditions"))),
                                    where(key("usernameAttribute").isNotPresent(),
                                            addAttribute("usernameAttribute").with(
                                                    valueOfAttribute("usernameAttribute")))),
                            where(key("claimsGathering").isNotPresent(),
                                    addAttribute("claimsGathering").with([:])),
                            within("claimsGathering",
                                    where(key("interactiveClaimsGatheringEnabled").isNotPresent(),
                                            addAttribute("interactiveClaimsGatheringEnabled").with(false)),
                                    where(key("claimsGatheringService").isNotPresent(),
                                            addAttribute("claimsGatheringService").with("[Empty]"))),
                            deleteAttributes("permissionTicketLifetime", "deletePoliciesOnDeleteRS",
                                    "deleteResourceSetsOnDeleteRS", "pendingRequestsEnabled",
                                    "emailResourceOwnerOnPendingRequestCreation",
                                    "emailRequestingPartyOnPendingRequestApproval", "userProfileLocaleAttribute",
                                    "resharingMode", "grantRptConditions", "supportedUmaProfiles", "usernameAttribute")
                    ),
                    forSettings(
                            where(key("generalSettings").isNotPresent(),
                                    addAttribute("generalSettings").with([:])),
                            where(key("supportedUmaProfiles").exists(),
                                    within("generalSettings",
                                            where(key("supportedUmaProfiles").isNotPresent(),
                                                    addAttribute("supportedUmaProfiles").with(
                                                            valueOfAttribute("supportedUmaProfiles"))))),
                            within("generalSettings",
                                    where(key("permissionTicketLifetime").isNotPresent(),
                                            addAttribute("permissionTicketLifetime").with(
                                                    valueOfAttribute("permissionTicketLifetime"))),
                                    where(key("deletePoliciesOnDeleteRS").isNotPresent(),
                                            addAttribute("deletePoliciesOnDeleteRS").with(
                                                    valueOfAttribute("deletePoliciesOnDeleteRS"))),
                                    where(key("deleteResourceSetsOnDeleteRS").isNotPresent(),
                                            addAttribute("deleteResourceSetsOnDeleteRS").with(
                                                    valueOfAttribute("deleteResourceSetsOnDeleteRS"))),
                                    where(key("pendingRequestsEnabled").isNotPresent(),
                                            addAttribute("pendingRequestsEnabled").with(
                                                    valueOfAttribute("pendingRequestsEnabled"))),
                                    where(key("emailResourceOwnerOnPendingRequestCreation").isNotPresent(),
                                            addAttribute("emailResourceOwnerOnPendingRequestCreation").with(
                                                    valueOfAttribute("emailResourceOwnerOnPendingRequestCreation"))),
                                    where(key("emailRequestingPartyOnPendingRequestApproval").isNotPresent(),
                                            addAttribute("emailRequestingPartyOnPendingRequestApproval").with(
                                                    valueOfAttribute("emailRequestingPartyOnPendingRequestApproval"))),
                                    where(key("userProfileLocaleAttribute").isNotPresent(),
                                            addAttribute("userProfileLocaleAttribute").with(
                                                    valueOfAttribute("userProfileLocaleAttribute"))),
                                    where(key("resharingMode").isNotPresent(),
                                            addAttribute("resharingMode").with(
                                                    valueOfAttribute("resharingMode"))),
                                    where(key("grantRptConditions").isNotPresent(),
                                            addAttribute("grantRptConditions").with(
                                                    valueOfAttribute("grantRptConditions"))),
                                    where(key("usernameAttribute").isNotPresent(),
                                            addAttribute("usernameAttribute").with(
                                                    valueOfAttribute("usernameAttribute")))),
                            where(key("claimsGathering").isNotPresent(),
                                    addAttribute("claimsGathering").with([:])),
                            within("claimsGathering",
                                    where(key("interactiveClaimsGatheringEnabled").isNotPresent(),
                                            addAttribute("interactiveClaimsGatheringEnabled").with(false)),
                                    where(key("claimsGatheringService").isNotPresent(),
                                            addAttribute("claimsGatheringService").with("[Empty]"))),
                            deleteAttributes("permissionTicketLifetime", "deletePoliciesOnDeleteRS",
                                    "deleteResourceSetsOnDeleteRS", "pendingRequestsEnabled",
                                    "emailResourceOwnerOnPendingRequestCreation",
                                    "emailRequestingPartyOnPendingRequestApproval", "userProfileLocaleAttribute",
                                    "resharingMode", "grantRptConditions", "supportedUmaProfiles", "usernameAttribute")
                    )
            ),
            //---- End Rules ----

            //---- Start Rules for: AME-22071
            forRealmService("UmaProvider",
                    forRealmDefaults(
                            within("claimsGathering",
                                    where(key("pctLifetime").isNotPresent(),
                                            addAttribute("pctLifetime").with(604800)))),
                    forSettings(
                            within("claimsGathering",
                                    where(key("pctLifetime").isNotPresent(),
                                            addAttribute("pctLifetime").with(604800))))
            ),
            //---- End Rules ----

            //---- Start Rule for: OPENAM-18499 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    forVersionsBefore(["4.0.0.0", "3.2.0.0"],
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.introspect.token.query.param.allowed=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.introspect.token.query.param.allowed=true")))),
            //---- End Rule ----

            //---- Start Rules for: OPENAM-18533 ----
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("requestObjectProcessing").isNotPresent(),
                                    addAttribute("requestObjectProcessing").with("OIDC")),
                    )
            ),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("advancedOAuth2Config",
                                    where(key("requestObjectProcessing").isNotPresent(),
                                            addAttribute("requestObjectProcessing").with("OIDC"))),
                    )
            ),
            //---- End Rules ----

            //---- Start Rules for: OPENAM-17698 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(isEngineConfiguration(), addToSet("whiteList")
                            .with("java.util.Collections\$UnmodifiableRandomAccessList",
                                    "java.util.Collections\$UnmodifiableCollection\$1")
                    )
            )),
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIn(
                            "default/OIDC_CLAIMS/engineConfiguration",
                            "default/OAUTH2_ACCESS_TOKEN_MODIFICATION/engineConfiguration",
                            "default/SOCIAL_IDP_PROFILE_TRANSFORMATION/engineConfiguration",
                            "default/OAUTH2_MAY_ACT/engineConfiguration",
                            "default/OAUTH2_VALIDATE_SCOPE/engineConfiguration",
                            "default/OAUTH2_EVALUATE_SCOPE/engineConfiguration",
                            "default/OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER/engineConfiguration"),
                            addToSet("whiteList")
                                    .with("org.forgerock.oauth.clients.oidc.Claim", "java.util.Locale")
                    )
            )),
            //---- End Rules ----

            //---- Start Rules for OPENAM-19001 ----
            forGlobalService("iPlanetAMNamingService", within("endpointConfig"
                    , deleteAttributes("idsvcsRestUrl"))),
            //---- End Rules for: OPENAM-19001 ----

            //---- Start Rules for: OPENAM-19243
            forRealmService("UmaProvider",
                    forRealmDefaults(
                            within("generalSettings",
                                    where(key("grantResourceOwnerImplicitConsent").isNotPresent(),
                                            addAttribute("grantResourceOwnerImplicitConsent")
                                                    .with(true)))),
                    forSettings(
                            within("generalSettings",
                                    where(key("grantResourceOwnerImplicitConsent").isNotPresent(),
                                            addAttribute("grantResourceOwnerImplicitConsent")
                                                    .with(true))))
            ),
            //---- End Rules ----

            //---- Start Rules for OPENAM-19297 -----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_MAY_ACT/engineConfiguration"),
                            where(key("whiteList").doesNotContain("java.util.Collections\$*"),
                                    addToSet("whiteList")
                                            .with("java.util.Collections\$UnmodifiableSet",
                                                    "java.util.Collections\$UnmodifiableMap"),)
                    ),
            )),
            //---- End Rules ----

            //---- Start Rules for: AME-22684 ----
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("refreshTokenGracePeriod").isNotPresent(),
                                    addAttribute("refreshTokenGracePeriod")
                                            .with(0)))),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("advancedOAuth2Config",
                                    where(key("refreshTokenGracePeriod").isNotPresent(),
                                            addAttribute("refreshTokenGracePeriod")
                                                    .with(0))))),
            //---- End Rules for AME-22684 ----

            //---- Start Rules for OPENAM-18439 ----
            forService("product-Saml2Node", deleteAttributes("sloEnabled", "sloRelayState")),
            //---- End Rules for OPENAM-18439 ----

            //---- Start Rules for SDKS-1472 ----
            addNewService("PushWaitNode"),
            //---- End Rules for SDKS-1472 ----

            //---- Start Rules for OPENAM-19238 ----
            forRealmService("OAuth2Provider",
                    within("coreOAuth2Config",
                            where(key("scopesPolicySet").isNotPresent(),
                                    addAttribute("scopesPolicySet")
                                            .with("oauth2Scopes")))),
            forService("OAuth2Provider",
                    forDefaultInstanceSettings(
                            within("coreOAuth2Config",
                                    where(key("scopesPolicySet").isNotPresent(),
                                            addAttribute("scopesPolicySet")
                                                    .with("oauth2Scopes"))))),
            //---- End Rules for OPENAM-19238 ----

            //---- Start Rule for: OPENAM-18629 ----
            forRealmService("RestSecurityTokenService",
                    forRealmDefaults(
                            within("restStsGeneral", CREATE_IF_MISSING,
                                    where(key("is-remote-sts-instance").isNotPresent(),
                                            addAttribute("is-remote-sts-instance")
                                                    .with(true))),
                    ),
                    forInstanceSettings(
                            within("restStsGeneral", CREATE_IF_MISSING,
                                    where(key("is-remote-sts-instance").isNotPresent(),
                                            addAttribute("is-remote-sts-instance")
                                                    .with(true))),
                    ),

            ),
            //---- End Rule ----
            //---- Start Rules for AME-22851 ----
            forService("IdmIntegrationService", forSettings(
                            where(key("configurationCacheDuration").isNotPresent(),
                                    addAttribute("configurationCacheDuration")
                                            .with(0)))),
            //---- End Rules for AME-22851 ----

            //---- Start Rules for AME-22720 ----
            forGlobalService("iPlanetAMSessionService",
                    forSettings(
                            within("general",
                                    where(key("crossUpgradeReferenceFlag").isNotPresent(),
                                            addAttribute("crossUpgradeReferenceFlag")
                                                    .with(false)))),
            ),
            //---- End Rules for AME-22720 ----

            //---- Start Rules for AME-22943 ----
            forGlobalService("iPlanetAMSessionService",
                    forSettings(
                            within("stateless",
                                    where(key("statelessLogoutByUser").isNotPresent(),
                                            addAttribute("statelessLogoutByUser")
                                                    .with(false)))),
            ),
            //---- End Rules for AME-22943 ----

            //---- Start Rules for OPENAM-19422 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.ldap.keepalive.search.filter=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.ldap.keepalive.search.filter=(objectClass=*)")),
                    where(key("serverconfig").doesNotMatchPattern("org.forgerock.openam.ldap.keepalive.search.base=.*"),
                            addToSet("serverconfig")
                                    .with("org.forgerock.openam.ldap.keepalive.search.base="))
            ),
            //---- End Rules for OPENAM-19422 ----
            //---- Start Rule for: AME-22389 ----
            forAllServices(where(isStructuralConfigFile(), deleteInstance())),
            //---- End Rule ----

            // ---- Start Rule for: OPENAM-19232 ----

            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdMatches("default/(OAUTH2_.*|OIDC_CLAIMS)/engineConfiguration"),
                            addToSet("whiteList").with(
                                    'com.google.common.collect.Sets$1',
                                    'com.sun.identity.common.CaseInsensitiveHashMap',
                                    'com.sun.identity.shared.debug.Debug',
                                    'groovy.json.JsonSlurper',
                                    'groovy.json.internal.LazyMap',
                                    'java.lang.Boolean',
                                    'java.lang.Byte',
                                    'java.lang.Character',
                                    'java.lang.Character$Subset',
                                    'java.lang.Character$UnicodeBlock',
                                    'java.lang.Double',
                                    'java.lang.Float',
                                    'java.lang.Integer',
                                    'java.lang.Long',
                                    'java.lang.Math',
                                    'java.lang.Number',
                                    'java.lang.Object',
                                    'java.lang.Short',
                                    'java.lang.StrictMath',
                                    'java.lang.String',
                                    'java.lang.Void',
                                    'java.net.URI',
                                    'java.util.AbstractMap$SimpleImmutableEntry',
                                    'java.util.ArrayList',
                                    'java.util.ArrayList$Itr',
                                    'java.util.Collections$1',
                                    'java.util.Collections$EmptyList',
                                    'java.util.Collections$SingletonList',
                                    'java.util.Collections$UnmodifiableCollection$1',
                                    'java.util.Collections$UnmodifiableMap',
                                    'java.util.Collections$UnmodifiableRandomAccessList',
                                    'java.util.Collections$UnmodifiableSet',
                                    'java.util.HashMap',
                                    'java.util.HashMap$Entry',
                                    'java.util.HashMap$KeyIterator',
                                    'java.util.HashMap$KeySet',
                                    'java.util.HashMap$Node',
                                    'java.util.HashSet',
                                    'java.util.LinkedHashMap',
                                    'java.util.LinkedHashMap$Entry',
                                    'java.util.LinkedHashMap$LinkedEntryIterator',
                                    'java.util.LinkedHashMap$LinkedEntrySet',
                                    'java.util.LinkedHashSet',
                                    'java.util.LinkedList',
                                    'java.util.List',
                                    'java.util.Locale',
                                    'java.util.Map',
                                    'java.util.TreeMap',
                                    'java.util.TreeSet',
                                    'org.codehaus.groovy.runtime.GStringImpl',
                                    'org.codehaus.groovy.runtime.ScriptBytecodeAdapter',
                                    'org.forgerock.http.Client',
                                    'org.forgerock.http.client.*',
                                    'org.forgerock.http.protocol.*',
                                    'org.forgerock.json.JsonValue',
                                    'org.forgerock.oauth.clients.oidc.Claim',
                                    'org.forgerock.openam.scripting.api.PrefixedScriptPropertyResolver',
                                    'org.forgerock.openam.scripting.api.ScriptedIdentity',
                                    'org.forgerock.openam.scripting.api.http.GroovyHttpClient',
                                    'org.forgerock.openam.scripting.api.http.JavaScriptHttpClient',
                                    'org.forgerock.openam.scripting.api.identity.ScriptedIdentityRepository',
                                    'org.forgerock.openam.scripting.api.identity.ScriptedIdentity',
                                    'org.forgerock.openam.scripting.api.secrets.ScriptedSecrets',
                                    'org.forgerock.util.promise.PromiseImpl'
                            ),
                    ),
            )),

            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/OAUTH2_SCRIPTED_JWT_ISSUER"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for OPENAM-19232 ----

            // ---- Start Rule for: OPENAM-19660 ----
            createEmailServiceInstancesFbc(),

            forService("MailServer", forRealmDefaults(where(entityIdIs("defaultconfig"),
                    replace("port").with((String) null),
                    replace("emailImplClassName").with((String) null),
                    replace("password").with((String) null),
                    replace("username").with((String) null),
                    replace("sslState").with((String) null),
                    replace("hostname").with((String) null),
                    replace("transportType").with((String) null),
                    deleteAttributes("password", "username", "hostname")
            ))),

            forService("MailServer", where(entityIdIs("default"),
                    addAttribute("transportType").with("default-smtp")
            )),

            //---- End Rules for OPENAM-19660 ----

            //---- Start Rules for OPENAM-19557 ----
            forService("IdentityStoreDecisionNode",
                    forInstanceSettings(
                            where(key("useUniversalIdForUsername").isNotPresent(),
                                    addAttribute("useUniversalIdForUsername").with(true)))),
            //---- End Rules for OPENAM-19557 ----

            //---- Start Rules for: OPENAM-22900 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(isEngineConfiguration(),
                            addToSet("whiteList")
                                    .with("org.mozilla.javascript.JavaScriptException")))),
            //---- End Rules for OPENAM-22900 ----

            //---- Start Rules for AME-20656 ----
            forGlobalService("iPlanetAMPlatformService",
                    forDefaultInstanceSettings(
                            forNamedInstanceSettings("server-default",
                                    withinSet("serverconfig")
                                            .replaceValueOfKey("org.forgerock.services.cts.store.max.connections")
                                            .where({ it != "" && Integer.parseInt(it) < 100})
                                            .with("100"))),
                    forInstanceSettings(
                            withinSet("serverconfig")
                                    .replaceValueOfKey("org.forgerock.services.cts.store.max.connections")
                                    .where({ it != "" && Integer.parseInt(it) < 100})
                                    .with("100"))),
            //---- End Rules for AME-20656 ----

            //---- Start Rule for: OPENAM-19488
            forRealmService("iPlanetAMAuthService",
                    forRealmDefaults(
                            within("trees",
                                    where(key("authenticationTreeCookieHttpOnly").isNotPresent(),
                                            addAttribute("authenticationTreeCookieHttpOnly")
                                                    .with(true)))),
                    forSettings(
                            within("trees", CREATE_IF_MISSING,
                                    where(key("authenticationTreeCookieHttpOnly").isNotPresent(),
                                            addAttribute("authenticationTreeCookieHttpOnly")
                                                    .with(false)))
                    )
            ),
            //---- End Rule ----

            //---- Start Rules for: OPENAM-20103 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration"),
                            addToSet("whiteList")
                                    .with("java.security.KeyPair", "java.security.KeyPairGenerator",
                                            "java.security.PrivateKey", "java.security.PublicKey",
                                            "java.security.spec.X509EncodedKeySpec",
                                            "java.security.spec.MGF1ParameterSpec",
                                            "javax.crypto.spec.OAEPParameterSpec", "javax.crypto.spec.PSource")))),
            //---- End Rules for OPENAM-20103 ----

            //---- Start Rules for AME-23234 ----
            forGlobalService("iPlanetAMSessionService",
                    forSettings(
                            within("stateless",
                                    where(key("openam-session-stateless-logout-poll-interval").isNotPresent(),
                                            addAttribute("openam-session-stateless-logout-poll-interval")
                                                    .with(60)))),
            ),
            //---- End Rules for AME-23234 ----

            //---- Start Rules for OPENAM-19811 ----
            forService("LdapDecisionNode",
                    forInstanceSettings(
                            where(key("mixedCaseForPasswordChangeMessages").isNotPresent(),
                                    addAttribute("mixedCaseForPasswordChangeMessages").with(false)))),
            forService("IdentityStoreDecisionNode",
                    forInstanceSettings(
                            where(key("mixedCaseForPasswordChangeMessages").isNotPresent(),
                                    addAttribute("mixedCaseForPasswordChangeMessages").with(false)))),
            //---- End Rules for OPENAM-19811 ----

            // ---- Start Rule for: Remove reference to SAML2 SP Adapter Default Script - AME-21638 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/SAML2_SP_ADAPTER"),
                            replace("defaultScript").with("[Empty]"),
                    ),
            )),
            //---- End Rules for AME-21638 ----

            //---- Start Rules for: AME-24033 ----
            forService("ScriptingService", forDefaultInstanceSettings(
                    where(entityIdIs("default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration"),
                            addToSet("whiteList")
                                    .with("org.forgerock.http.header.*",
                                            "org.forgerock.http.header.authorization.*")))),
            //---- End Rules for AME-24033 ----

            // This is the version that the config is at now. This is required to ensure the correct
            // value is set if the ConfigurationVersionService is not already present.
            setVersion("5.0.0.0"),
            //---- Start Rules for AME-23889 ----
            forRealmService("iPlanetAMAuthService",
                    forRealmDefaults(
                            within("security",
                                    where(key("addClearSiteDataHeader").isNotPresent(),
                                            addAttribute("addClearSiteDataHeader")
                                                    .with(true)))),
                    forSettings(
                            within("security", CREATE_IF_MISSING,
                                    where(key("addClearSiteDataHeader").isNotPresent(),
                                            addAttribute("addClearSiteDataHeader")
                                                    .with(true)))
                    )
            ),
            //---- End Rules for OPENAM-19811 ----

            //---- Start Rules for: OPENAM-20541 ----
            addToScriptingWhitelistForService(["default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration"],
                    ['java.security.KeyPairGenerator$*', 'javax.crypto.spec.PSource$*']),
            //---- End Rule ----

            //---- Start Rules for: AME-23589 ----
            addToScriptingWhitelistForService(["default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration",
                                               "default/AUTHENTICATION_SERVER_SIDE/engineConfiguration",
                                               "default/CONFIG_PROVIDER_NODE/engineConfiguration",
                                               "default/OIDC_CLAIMS/engineConfiguration",
                                               "default/OAUTH2_ACCESS_TOKEN_MODIFICATION/engineConfiguration",
                                               "default/OAUTH2_MAY_ACT/engineConfiguration",
                                               "default/OAUTH2_VALIDATE_SCOPE/engineConfiguration",
                                               "default/OAUTH2_EVALUATE_SCOPE/engineConfiguration",
                                               "default/OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER/engineConfiguration",
                                               "default/OAUTH2_SCRIPTED_JWT_ISSUER/engineConfiguration",
                                               "default/POLICY_CONDITION/engineConfiguration",
                                               "default/SAML2_IDP_ADAPTER/engineConfiguration",
                                               "default/SAML2_IDP_ATTRIBUTE_MAPPER/engineConfiguration",
                                               "default/SOCIAL_IDP_PROFILE_TRANSFORMATION/engineConfiguration"],
                    ["sun.security.ec.ECPrivateKeyImpl"]),
            //---- End Rules for AME-23589 ----

            //---- Start Rules for AME-23793 ----
            addToScriptingWhitelistForService(["default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration"],
                    ["org.forgerock.openam.authentication.callbacks.IdPCallback",
                     "org.forgerock.openam.authentication.callbacks.ValidatedPasswordCallback",
                     "org.forgerock.openam.authentication.callbacks.ValidatedUsernameCallback"]),
            //---- End Rules for AME-23793 ----

            //---- Start Rule for: AME-24191 ----
            forAllServices(where(isSecondPhaseStructuralConfigFile(), deleteInstance())),
            //---- End Rule ----

            //---- Start Rules for: AME-24175 ----
            addToScriptingWhitelistForService(["default/SAML2_IDP_ADAPTER/engineConfiguration"],
                    ["javax.servlet.http.Cookie",
                     "javax.xml.parsers.DocumentBuilder",
                     "javax.xml.parsers.DocumentBuilderFactory",
                     "org.w3c.dom.Document",
                     "org.w3c.dom.Element",
                     "org.xml.sax.InputSource"]),
            //---- End Rules for AME-24175 ----

            //---- Start Rules for AME-23503 ----
            addToScriptingWhitelistForService(["default/SAML2_IDP_ADAPTER/engineConfiguration"],
                    ["com.sun.identity.saml2.assertion.*",
                     "com.sun.identity.saml2.assertion.impl.*",
                     "com.sun.identity.saml2.protocol.*",
                     "com.sun.identity.saml2.protocol.impl.*"]),
            //---- End Rules for AME-23503 ----

            //---- Start Rule for: OPENAM-20383 ----
            forServicesMatching(
                    { it.entityType == "iPlanetAMPlatformService" && it.entityId == "default/com-sun-identity-servers/server-default" },
                    forVersionsBefore(["6.0.0.0"],
                            where(key("serverconfig").doesNotMatchPattern("org.forgerock.am.auth.chains.authindexuser.strict=.*"),
                                    addToSet("serverconfig")
                                            .with("org.forgerock.am.auth.chains.authindexuser.strict=false")))),

            // This is the version that the config is at now. This is required to ensure the correct
            // value is set if the ConfigurationVersionService is not already present.
            setVersion("6.0.0.0"),
            //---- End Rule ----

            //---- Start Rules for: AME-24460 ----
            addToScriptingWhitelistForService([
                    "default/AUTHENTICATION_SERVER_SIDE/engineConfiguration",
                    "default/AUTHENTICATION_TREE_DECISION_NODE/engineConfiguration",
                    "default/CONFIG_PROVIDER_NODE/engineConfiguration",
                    "default/OAUTH2_ACCESS_TOKEN_MODIFICATION/engineConfiguration",
                    "default/OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER/engineConfiguration",
                    "default/OAUTH2_EVALUATE_SCOPE/engineConfiguration",
                    "default/OAUTH2_MAY_ACT/engineConfiguration",
                    "default/OAUTH2_SCRIPTED_JWT_ISSUER/engineConfiguration",
                    "default/OAUTH2_VALIDATE_SCOPE/engineConfiguration",
                    "default/OIDC_CLAIMS/engineConfiguration",
                    "default/POLICY_CONDITION/engineConfiguration"
            ],["org.forgerock.openam.scripting.api.identity.ScriptedIdentity"]),
            //---- End Rules for AME-24460 ----

            createSecretStores(),
    ]
}

/**
 * For use in the Radius server secret upgrade rule and embedded in a modify transform.  This takes a value and returns
 * an secure hashed of the value using a random 20 byte salt and SHA-512 algorithm.
 *
 * Note - this method is embedded in the rules file because it is specific to the rule or rules in this file - this
 * method should not be moved into the upgrader tool because that would mean that changes to the upgrader may affect
 * the results of running this file.
 *
 * @param toSecure the original value
 * @return a secure hash of the provided value
 */
static String securifyString(String toSecure) {
    byte[] salt = new byte[20]
    SecureRandom secureRandom = new SecureRandom()
    secureRandom.nextBytes(salt)
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
    messageDigest.update(salt)
    messageDigest.update(toSecure.getBytes(StandardCharsets.UTF_8))

    return "{SHA-512}" + Base64.getEncoder().encodeToString(messageDigest.digest())
}

static ServiceInstanceCondition isStructuralConfigFile() {
        { config, configProvider ->
                boolean s = Set.of("GlobalConfig", "OrganizationConfig", "Instances", "PluginConfig",
                        "PolicyConfig", "UserConfig", "DynamicConfig").contains(config.key.entityId)
                return s
        }
}

static ServiceInstanceCondition isSecondPhaseStructuralConfigFile() {
        { config, configProvider ->
                boolean isSubrealm = config.key.realm.map({it != "/"}).orElse(false)
                return isSubrealm
                        && config.data.size() == 2 // only contains default data (_id and _type)
                        && ("1.0" == config.key.entityId || (config.key.entityType == "" && config.key.entityId == "services"))
        }
}

static ServiceInstanceCondition isEngineConfiguration() {
        { config, configProvider ->
                config.key.entityId.toString().matches("default/(.*)/engineConfiguration")
        }
}
