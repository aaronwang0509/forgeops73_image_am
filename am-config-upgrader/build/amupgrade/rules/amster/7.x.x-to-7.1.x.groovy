/*
 * Copyright 2020-2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.Conditions.AndCondition
import static org.forgerock.openam.amp.dsl.Conditions.entityIdContains
import static org.forgerock.openam.amp.dsl.Conditions.key
import static org.forgerock.openam.amp.dsl.Conditions.pathParamIsOneOf
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forRealmService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forService
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addAttribute
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addToSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.appendSocialProviderFormPostRedirectUriWithEntityId
import static org.forgerock.openam.amp.dsl.ServiceTransforms.configureOidcIssuerFromWellKnown
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteInstance
import static org.forgerock.openam.amp.dsl.ServiceTransforms.moveKeyAliasToSecretsApi
import static org.forgerock.openam.amp.dsl.ServiceTransforms.removeFromSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.upgradeSocialProviderSigningAndEncryptionAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.where
import static org.forgerock.openam.amp.dsl.ServiceTransforms.within
import static org.forgerock.openam.amp.dsl.fbc.FileBasedConfigTransforms.forInstanceSettings
import static org.forgerock.openam.amp.dsl.valueproviders.ValueProviders.valueOfAttribute
import static org.forgerock.openam.amp.framework.core.secrets.RemoteConsentServiceSecretConstants.ENCRYPTION_KEY_ALIAS
import static org.forgerock.openam.amp.framework.core.secrets.RemoteConsentServiceSecretConstants.ENCRYPTION_SECRET_ID
import static org.forgerock.openam.amp.framework.core.secrets.RemoteConsentServiceSecretConstants.SIGNING_KEY_ALIAS
import static org.forgerock.openam.amp.framework.core.secrets.RemoteConsentServiceSecretConstants.SIGNING_SECRET_ID
import static org.forgerock.openam.amp.rules.CustomRules.addMayActScriptSettings
import static org.forgerock.openam.amp.rules.CustomRules.createSecretStores
import static org.forgerock.openam.amp.dsl.ServiceTransforms.upgradePrivateKeyJwtAttributes

def getRules() {
    return [
            // Update to remove no longer available user attributes
            forRealmService("OpenDJ", within("userconfig",
                    removeFromSet("sun-idrepo-ldapv3-config-user-objectclass").with(
                            "sunFederationManagerDataStore", "sunIdentityServerLibertyPPService"))),
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["OAUTH2_ACCESS_TOKEN_MODIFICATION"]),
                            addToSet("whiteList")
                                    .with("java.util.AbstractMap\$SimpleImmutableEntry",
                                            "org.forgerock.json.JsonValue", "java.util.HashMap\$KeySet",
                                            "java.net.URI", "org.forgerock.oauth2.core.GrantType")),
                    where(pathParamIsOneOf("contexts", ["OIDC_CLAIMS"]),
                            addToSet("whiteList").with("java.util.HashMap\$KeySet",
                                    "java.net.URI", "org.forgerock.oauth2.core.GrantType"))),
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            // Order is important - add before remove otherwise the second where condition fails
                            where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                    addToSet("responseTypeClasses").with("id_token|org.forgerock.openidconnect.IdTokenResponseTypeHandler")),
                            where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                    removeFromSet("responseTypeClasses").with("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"))),
                    within("coreOIDCConfig",
                            where(key("overrideableOIDCClaims").isNotPresent(),
                                    addAttribute("overrideableOIDCClaims")
                                            .with(Collections.emptySet())),
                            where(key("oidcDiscoveryEndpointEnabled").isNotPresent(),
                                    addAttribute("oidcDiscoveryEndpointEnabled")
                                            .with(true))),
                    within("advancedOIDCConfig",
                            where(key("includeAllKtyAlgCombinationsInJwksUri").isNotPresent(),
                                    addAttribute("includeAllKtyAlgCombinationsInJwksUri")
                                            .with(false)))
            ),
            forRealmService("J2eeAgents",
                    within("ssoJ2EEAgentConfig", deleteAttributes("secureCookies")),
                    within("miscJ2EEAgentConfig", deleteAttributes("serviceResolverClass")),
                    within("globalJ2EEAgentConfig", deleteAttributes("debugLogfileDirectory")),
                    within("globalJ2EEAgentConfig", deleteAttributes("localAuditLogfilePath")),
                    within("globalJ2EEAgentConfig", deleteAttributes("agentSessionChangeNotificationsEnabled"))),
            forRealmService("J2EEAgentGroups",
                    within("ssoJ2EEAgentConfig", deleteAttributes("secureCookies")),
                    within("miscJ2EEAgentConfig", deleteAttributes("serviceResolverClass")),
                    within("globalJ2EEAgentConfig", deleteAttributes("debugLogfileDirectory")),
                    within("globalJ2EEAgentConfig", deleteAttributes("localAuditLogfilePath")),
                    within("globalJ2EEAgentConfig", deleteAttributes("agentSessionChangeNotificationsEnabled"))),
            forGlobalService("OAuth2Provider",
                    within("defaults/advancedOAuth2Config",
                            // Order is important - add before remove otherwise the second where condition fails
                            where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                    addToSet("responseTypeClasses").with("id_token|org.forgerock.openidconnect.IdTokenResponseTypeHandler")),
                            where(key("responseTypeClasses").contains("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"),
                                    removeFromSet("responseTypeClasses").with("id_token|org.forgerock.oauth2.core.TokenResponseTypeHandler"))),
                    within("defaults/coreOIDCConfig",
                            where(key("overrideableOIDCClaims").isNotPresent(),
                                    addAttribute("overrideableOIDCClaims")
                                            .with(Collections.emptySet())),
                            where(key("oidcDiscoveryEndpointEnabled").isNotPresent(),
                                    addAttribute("oidcDiscoveryEndpointEnabled")
                                            .with(false))),
                    within("defaults/advancedOIDCConfig",
                            where(key("includeAllKtyAlgCombinationsInJwksUri").isNotPresent(),
                                    addAttribute("includeAllKtyAlgCombinationsInJwksUri")
                                            .with(false)))
            ),
            forGlobalService("RemoteConsentService",
                    within("defaults",
                            moveKeyAliasToSecretsApi(SIGNING_KEY_ALIAS, [SIGNING_SECRET_ID]),
                            moveKeyAliasToSecretsApi(ENCRYPTION_KEY_ALIAS, [ENCRYPTION_SECRET_ID]))),
            forRealmService("RemoteConsentService",
                    moveKeyAliasToSecretsApi(SIGNING_KEY_ALIAS, [SIGNING_SECRET_ID]),
                    moveKeyAliasToSecretsApi(ENCRYPTION_KEY_ALIAS, [ENCRYPTION_SECRET_ID])),
            forRealmService("OAuth2Clients",
                    within("advancedOAuth2ClientConfig",
                            addAttribute("customProperties").with(Collections.emptySet()),
                            addAttribute("tosURI").with(Collections.emptySet()),
                            addAttribute("softwareIdentity").with(""),
                            addAttribute("softwareVersion").with(""))),
            addMayActScriptSettings(),
            forService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            addToSet("grantTypes").with("urn:ietf:params:oauth:grant-type:token-exchange")),
                    within("defaults/advancedOAuth2Config",
                            addToSet("grantTypes").with("urn:ietf:params:oauth:grant-type:token-exchange"))
            ),
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["OAUTH2_MAY_ACT"]),
                            addToSet("whiteList")
                                    .with("org.forgerock.openidconnect.OpenIdConnectToken",
                                            "org.forgerock.oauth2.core.tokenexchange.ExchangeableToken"))),
            forGlobalService("Session",
                    within("stateless",
                            moveKeyAliasToSecretsApi("statelessSigningRsaCertAlias", ["am.global.services.session.clientbased.signing"]),
                            moveKeyAliasToSecretsApi("statelessEncryptionRsaCertAlias", ["am.global.services.session.clientbased.encryption"]))),
            // These rules are specific to OIDCClient
            forRealmService("OIDCClient",
                    where(key("jwtRequestParameterOption").isNotPresent(),
                            addAttribute("jwtRequestParameterOption").with("NONE")),
                    where(key("requestObjectSigningAlg").isNotPresent(),
                            addAttribute("requestObjectSigningAlg").with("")),
                    where(key("requestObjectEncryptionAlg").isNotPresent(),
                            addAttribute("requestObjectEncryptionAlg").with("")),
                    where(key("acrValues").isNotPresent(),
                            addAttribute("acrValues").with(Collections.emptyList())),
                    where(key("encryptedIdTokens").isNotPresent(),
                            addAttribute("encryptedIdTokens").with(false)),
                    where(key("issuer").isNotPresent(),
                            configureOidcIssuerFromWellKnown()),
            ),
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["OAUTH2_ACCESS_TOKEN_MODIFICATION", "OIDC_CLAIMS"]),
                            where(key("whiteList").doesNotContain("java.util.Collections\$*"),
                                    addToSet("whiteList")
                                            .with("java.util.Collections\$UnmodifiableSet",
                                                    "java.util.Collections\$UnmodifiableMap"))),
                    where(pathParamIsOneOf("contexts", ["AUTHENTICATION_TREE_DECISION_NODE"]),
                            addToSet("whiteList").with(
                                    "org.forgerock.openam.auth.node.api.NodeState"))),
            forRealmService("OIDCClient", upgradePrivateKeyJwtAttributes()),
            forRealmService("LinkedInClient", upgradePrivateKeyJwtAttributes()),
            forRealmService("OAuth2Client", upgradePrivateKeyJwtAttributes()),
            forRealmService("VKClient", upgradePrivateKeyJwtAttributes()),
            forRealmService("WeChatClient", upgradePrivateKeyJwtAttributes()),
            forGlobalService("DefaultAdvancedProperties",
                    where(key("openam.private.key.jwt.encryption.algorithm.whitelist").isNotPresent(),
                            addAttribute("openam.private.key.jwt.encryption.algorithm.whitelist")
                                    .with("RSA-OAEP,RSA-OAEP-256,ECDH-ES")),
                    where(key("org.forgerock.openam.httpclienthandler.system.clients.pool.ttl").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.clients.pool.ttl").with(
                                    "-1")),
                    where(key("org.forgerock.openam.httpclienthandler.system.clients.connection.timeout").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.clients.connection.timeout").with(
                                    "10 seconds")),
                    where(key("org.forgerock.openam.httpclienthandler.system.clients.max.connections").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.clients.max.connections").with(
                                    "64")),
                    where(key("org.forgerock.openam.httpclienthandler.system.clients.retry.failed.requests.enabled").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.clients.retry.failed.requests.enabled").with(
                                    true)),
                    where(key("org.forgerock.openam.httpclienthandler.system.clients.reuse.connections.enabled").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.clients.reuse.connections.enabled").with(
                                    true)),
                    where(key("org.forgerock.openam.httpclienthandler.system.clients.response.timeout").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.clients.response.timeout").with(
                                    "10 seconds")),
                    where(key("org.forgerock.openam.httpclienthandler.system.proxy.uri").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.proxy.uri").with(
                                    "")),
                    where(key("org.forgerock.openam.httpclienthandler.system.proxy.username").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.proxy.username").with(
                                    "")),
                    where(key("org.forgerock.openam.httpclienthandler.system.proxy.password").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.proxy.password").with(
                                    "")),
                    where(key("org.forgerock.openam.idrepo.ldapv3.proxyauth.passwordreset.adminRequest").isNotPresent(),
                            addAttribute("org.forgerock.openam.idrepo.ldapv3.proxyauth.passwordreset.adminRequest").with(
                                    "isAdminPasswordChangeRequest")),
                    where(key("org.forgerock.openam.httpclienthandler.system.nonProxyHosts").isNotPresent(),
                            addAttribute("org.forgerock.openam.httpclienthandler.system.nonProxyHosts").with(
                                    "localhost,127.*,[::1],0.0.0.0,[::0]"))),
            //---- Start Rules for: AME-20499 ----
            forRealmService("OIDCClient",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "apple" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OAuth2Client",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "amazon" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OAuth2Client",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "facebook" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OIDCClient",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "google" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OAuth2Client",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "instagram" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("LinkedInClient",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "linkedin" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OAuth2Client",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "microsoft" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OAuth2Client",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "salesforce" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("TwitterClient",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "twitter" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("VKClient",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "vkontakte" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("WeChatClient",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "wechat" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OAuth2Client",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "wordpress" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            forRealmService("OIDCClient",
                    where(new AndCondition({ config, configProvider -> config.key.entityId == "yahoo" }, key("clientSecret").isNotPresent()),
                            deleteInstance())),
            //---- End Rules for: AME-20499 ----

            //---- Start Rules for upgrading Social Provider Signing and Encryption ----
            forRealmService("OIDCClient", upgradeSocialProviderSigningAndEncryptionAttributes()),
            forRealmService("LinkedInClient", upgradeSocialProviderSigningAndEncryptionAttributes()),
            forRealmService("OAuth2Client", upgradeSocialProviderSigningAndEncryptionAttributes()),
            forRealmService("VKClient", upgradeSocialProviderSigningAndEncryptionAttributes()),
            forRealmService("WeChatClient", upgradeSocialProviderSigningAndEncryptionAttributes()),

            forGlobalService("DefaultAdvancedProperties",
                    where(key("openam.oauth2.client.jwt.encryption.algorithm.allow.list").isNotPresent(),
                            addAttribute("openam.oauth2.client.jwt.encryption.algorithm.allow.list")
                                    .with(valueOfAttribute("openam.private.key.jwt.encryption.algorithm.whitelist"))),
                    deleteAttributes("openam.private.key.jwt.encryption.algorithm.whitelist")),
            //---- End Rules ---

            //---- Start Rules for adding the entity id Social Provider form port redirect ----
            forRealmService("OIDCClient", appendSocialProviderFormPostRedirectUriWithEntityId()),
            forRealmService("LinkedInClient", appendSocialProviderFormPostRedirectUriWithEntityId()),
            forRealmService("OAuth2Client", appendSocialProviderFormPostRedirectUriWithEntityId()),
            forRealmService("VKClient", appendSocialProviderFormPostRedirectUriWithEntityId()),
            forRealmService("WeChatClient", appendSocialProviderFormPostRedirectUriWithEntityId()),
            //---- End Rules ---

            createSecretStores(),
    ]
}