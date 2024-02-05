/*
 * Copyright 2021-2022 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.Conditions.entityIdIs
import static org.forgerock.openam.amp.dsl.Conditions.key
import static org.forgerock.openam.amp.dsl.Conditions.pathParamIsOneOf
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forRealmService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.generateSymmetricSecret
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addAttribute
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addToSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.where
import static org.forgerock.openam.amp.dsl.ServiceTransforms.within
import static org.forgerock.openam.amp.dsl.valueproviders.ValueProviders.valueOfAttribute
import static org.forgerock.openam.amp.rules.CustomRules.addNewGlobalScriptSettings
import static org.forgerock.openam.amp.rules.CustomRules.createSecretStores
import static org.forgerock.openam.amp.rules.CustomRules.updateOAuth2PluginsSettings
import static org.forgerock.openam.amp.rules.CustomRules.updateOauth2ClientPluginSettings

def getRules() {
    return [
            //---- Start Rules for: AME-21318 ----
            forRealmService("OAuth2Provider",
                    where(key("pluginsConfig").isNotPresent(),
                            addAttribute("pluginsConfig").with([:])),
                    within("pluginsConfig",
                            where(key("scopeImplementationClass").isNotPresent(),
                                    addAttribute("scopeImplementationClass").with(
                                            valueOfAttribute("advancedOAuth2Config", "scopeImplementationClass")))),
                    within("advancedOAuth2Config", deleteAttributes("scopeImplementationClass"))
            ),
            forGlobalService("OAuth2Provider",
                    within("defaults",
                            where(key("pluginsConfig").isNotPresent(),
                                    addAttribute("pluginsConfig").with([:]))),
                    within("defaults/pluginsConfig",
                            where(key("scopeImplementationClass").isNotPresent(),
                                    addAttribute("scopeImplementationClass").with(
                                            valueOfAttribute("defaults/advancedOAuth2Config", "scopeImplementationClass")))),
                    within("defaults/advancedOAuth2Config", deleteAttributes("scopeImplementationClass"))
            ),
            //---- End Rules ----

            //---- Start Rules for OPENAM-17610
            forGlobalService("DefaultAdvancedProperties",
                    where(key("org.forgerock.openam.smtp.system.connect.timeout").isNotPresent(),
                            addAttribute("org.forgerock.openam.smtp.system.connect.timeout").with(
                                    "10000")),
                    where(key("org.forgerock.openam.smtp.system.socket.read.timeout").isNotPresent(),
                            addAttribute("org.forgerock.openam.smtp.system.socket.read.timeout").with(
                                    "10000")),
                    where(key("org.forgerock.openam.smtp.system.socket.write.timeout").isNotPresent(),
                            addAttribute("org.forgerock.openam.smtp.system.socket.write.timeout").with(
                                    "10000"))
            ),
            //---- End Rules ----
            //---- Start Rules for OPENAM-16149
            forGlobalService("DefaultAdvancedProperties",
                    where(key("openam.oauth2.client.jwt.unreasonable.lifetime.limit.minutes").isNotPresent(),
                            addAttribute("openam.oauth2.client.jwt.unreasonable.lifetime.limit.minutes").with(
                                    "30"))
            ),
            //---- End Rules ----
            //---- Start Rules for: AME-21304 ----
            forRealmService("OAuth2Provider",
                    where(key("pluginsConfig").isNotPresent(),
                            addAttribute("pluginsConfig").with([:])),
                    within("pluginsConfig",
                            where(key("oidcClaimsScript").isNotPresent(),
                                    addAttribute("oidcClaimsScript").with(
                                            valueOfAttribute("coreOIDCConfig", "oidcClaimsScript")))),
                    within("coreOIDCConfig", deleteAttributes("oidcClaimsScript"))
            ),
            forGlobalService("OAuth2Provider",
                    within("defaults",
                            where(key("pluginsConfig").isNotPresent(),
                                    addAttribute("pluginsConfig").with([:]))),
                    within("defaults/pluginsConfig",
                            where(key("oidcClaimsScript").isNotPresent(),
                                    addAttribute("oidcClaimsScript").with(
                                            valueOfAttribute("defaults/coreOIDCConfig", "oidcClaimsScript")))),
                    within("defaults/coreOIDCConfig", deleteAttributes("oidcClaimsScript"))
            ),
            // ---- Start Rules for: AME-21305 ----
            forRealmService("OAuth2Provider",
                    where(key("pluginsConfig").isNotPresent(),
                            addAttribute("pluginsConfig").with([:])),
                    within("pluginsConfig",
                            where(key("accessTokenModificationScript").isNotPresent(),
                                    addAttribute("accessTokenModificationScript").with(
                                            valueOfAttribute("coreOAuth2Config", "accessTokenModificationScript")))),
                    within("coreOAuth2Config", deleteAttributes("accessTokenModificationScript"))
            ),
            forGlobalService("OAuth2Provider",
                    within("defaults",
                            where(key("pluginsConfig").isNotPresent(),
                                    addAttribute("pluginsConfig").with([:]))),
                    within("defaults/pluginsConfig",
                            where(key("accessTokenModificationScript").isNotPresent(),
                                    addAttribute("accessTokenModificationScript").with(
                                            valueOfAttribute("defaults/coreOAuth2Config", "accessTokenModificationScript")))),
                    within("defaults/coreOAuth2Config", deleteAttributes("accessTokenModificationScript"))
            ),
            //---- End Rules ----

            //---- Start Rule for: Add OAUTH2 EVALUATE SCOPE Script - AME-21302 ----
            addNewGlobalScriptSettings("da56fe60-8b38-4c46-a405-d6b306d4b336", "/7_2_0_config/global/GlobalScripts"),
            //---- End Rule ----

            //---- Start Rule for: Add OAUTH2 VALIDATE VALIDATE Script - AME-21631 ----
            addNewGlobalScriptSettings("25e6c06d-cf70-473b-bd28-26931edc476b", "/7_2_0_config/global/GlobalScripts"),
            //---- End Rule ----

            //---- Start Rule for: Add SAML2 IDP Attribute Mapper Script - AME-21617 ----
            addNewGlobalScriptSettings("c4f22465-2368-4e27-8013-e6399974fd48", "/7_2_0_config/global/GlobalScripts"),
            //---- End Rule ----

            //---- Start Rule for: Add SAML2 IDP Adapter Script - AME-22086 ----
            addNewGlobalScriptSettings("248b8a56-df81-4b1b-b4ba-45d994f6504c", "/7_2_0_config/global/GlobalScripts"),
            //---- End Rule ----

            //---- Start Rule for: Add Config Provider Script - AME-22015 ----
            addNewGlobalScriptSettings("5e854779-6ec1-4c39-aeba-0477e0986646", "/7_2_0_config/global/GlobalScripts"),
            //---- End Rule ----

            //---- Start Rules for: OPENAM-17320 ----
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("useForceAuthnForPromptLogin").exists(),
                                    deleteAttributes("useForceAuthnForPromptLogin"))),
                    within("advancedOIDCConfig",
                            where(key("useForceAuthnForPromptLogin").isNotPresent(),
                                    addAttribute("useForceAuthnForPromptLogin")
                                            .with(false)))
            ),
            forGlobalService("OAuth2Provider",
                    within("defaults/advancedOAuth2Config",
                            where(key("useForceAuthnForPromptLogin").exists(),
                                    deleteAttributes("useForceAuthnForPromptLogin"))),
                    within("defaults/advancedOIDCConfig",
                            where(key("useForceAuthnForPromptLogin").isNotPresent(),
                                    addAttribute("useForceAuthnForPromptLogin")
                                            .with(false)))
            ),
            //---- End Rules ----

            //---- Start Rule for: Add OAUTH2 AUTHORIZE ENDPOINT DATA PROVIDER Script - AME-21303 ----
            addNewGlobalScriptSettings("3f93ef6e-e54a-4393-aba1-f322656db28a", "/7_2_0_config/global/GlobalScripts"),
            //---- End Rule ----

            //---- Start Rules for: AME-21024 ----
            forGlobalService("ScriptingEngineConfiguration",
                    where(entityIdIs("engineConfiguration"),
                            addToSet("whiteList")
                                    .with("org.forgerock.openam.scripting.api.PrefixedScriptPropertyResolver",
                                            "java.util.List", "java.util.Map"))),
            //---- End Rule ----

            //---- Start Rule for: OPENAM-16863
            forGlobalService("DefaultAdvancedProperties",
                    where(key("org.forgerock.openam.authentication.forceAuth.enabled").isNotPresent(),
                            addAttribute("org.forgerock.openam.authentication.forceAuth.enabled").with(
                                    true))
            ),
            //---- End Rule ----

            //---- Start Rule for: OPENAM-17040 ----
            forRealmService("Applications",
                    where(key("applicationType").is("umaApplicationType"),
                            addToSet("subjects").with("Uma"),
                            addToSet("conditions").with("ClientId", "Expiration"))),
            //---- End Rule ----

            //---- Start Rule for: OPENAM-17951, OPENAM-18465, OPENAM-19147 ----
            forRealmService("J2eeAgents",
                    within("advancedJ2EEAgentConfig",
                            where(key("postDataCacheTtl").exists(),
                                    deleteAttributes("postDataCacheTtl"))),
                    within("globalJ2EEAgentConfig",
                            where(key("recheckAmUnavailabilityInSeconds").isNotPresent(),
                                    addAttribute("recheckAmUnavailabilityInSeconds").with(5)),
                            where(key("fallforwardModeEnabled").exists(),
                                    deleteAttributes("fallforwardModeEnabled"))),
                    within("applicationJ2EEAgentConfig",
                            where(key("loginFormUri").exists(),
                                    deleteAttributes("loginFormUri")))),
            forRealmService("J2EEAgentGroups",
                    within("advancedJ2EEAgentConfig",
                            where(key("postDataCacheTtl").exists(),
                                    deleteAttributes("postDataCacheTtl"))),
                    within("globalJ2EEAgentConfig",
                            where(key("recheckAmUnavailabilityInSeconds").isNotPresent(),
                                    addAttribute("recheckAmUnavailabilityInSeconds").with(5)),
                            where(key("fallforwardModeEnabled").exists(),
                                    deleteAttributes("fallforwardModeEnabled"))),
                    within("applicationJ2EEAgentConfig",
                            where(key("loginFormUri").exists(),
                                    deleteAttributes("loginFormUri")))),
            //---- End Rule ----

            //---- Start Rule for: OPENAM-17832, OPENAM-18024, OPENAM-18305 ----
            forRealmService("WebAgents",
                    within("advancedWebAgentConfig",
                            where(key("hostnameToIpAddress").isNotPresent(),
                                    addAttribute("hostnameToIpAddress").with(Collections.emptyList())),
                            where(key("apacheAuthDirectives").isNotPresent(),
                                    addAttribute("apacheAuthDirectives").with((String) null)),
                            where(key("retainSessionCache").isNotPresent(),
                                    addAttribute("retainSessionCache").with(false)))),
            forRealmService("WebAgentGroups",
                    within("advancedWebAgentConfig",
                            where(key("hostnameToIpAddress").isNotPresent(),
                                    addAttribute("hostnameToIpAddress").with(Collections.emptyList())),
                            where(key("apacheAuthDirectives").isNotPresent(),
                                    addAttribute("apacheAuthDirectives").with((String) null)),
                            where(key("retainSessionCache").isNotPresent(),
                                    addAttribute("retainSessionCache").with(false)))),
            //---- End Rule ----

            //---- Start Rules for: AME-21946 ----
            forRealmService("OAuth2Provider",
                    within("pluginsConfig", updateOAuth2PluginsSettings()),
            ),
            forGlobalService("OAuth2Provider",
                    within("defaults/pluginsConfig", updateOAuth2PluginsSettings())),
            //---- End Rules ----

            //---- Start Rules for: AME-22018 ----
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("parRequestUriLifetime").isNotPresent(),
                                    addAttribute("parRequestUriLifetime").with(90)))),
            forGlobalService("OAuth2Provider",
                    within("defaults/advancedOAuth2Config",
                            where(key("parRequestUriLifetime").isNotPresent(),
                                    addAttribute("parRequestUriLifetime").with(90)))),
            //---- End Rules ----

            //---- Start Rules for OPENAM-17756 ----
            forGlobalService("OAuth2Provider",
                    within("defaults/deviceCodeConfig",
                            where(key("deviceUserCodeLength").isNotPresent(),
                                    addAttribute("deviceUserCodeLength").with(
                                            8))),
                    within("defaults/deviceCodeConfig",
                            where(key("deviceUserCodeCharacterSet").isNotPresent(),
                                    addAttribute("deviceUserCodeCharacterSet").with(
                                            "234567ACDEFGHJKLMNPQRSTWXYZabcdefhijkmnopqrstwxyz"))),
                    within("defaults/pluginsConfig",
                            where(key("userCodeGeneratorClass").isNotPresent(),
                                    addAttribute("userCodeGeneratorClass").with(
                                            "org.forgerock.oauth2.core.plugins.registry.DefaultUserCodeGenerator"))),
            ),
            //---- End Rules OPENAM-17756 ---

            //---- Start Rules for OPENAM-18438 ----
            forGlobalService("OAuth2Provider",
                    where(key("allowUnauthorisedAccessToUserCodeForm").isNotPresent(),
                            addAttribute("allowUnauthorisedAccessToUserCodeForm").with(
                                    true)),
            ),

            //---- Start Rules for: AME-22077
            forRealmService("UmaProvider",
                    where(key("generalSettings").isNotPresent(),
                            addAttribute("generalSettings").with([:])),
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
                                            valueOfAttribute("grantRptConditions")))),
                    deleteAttributes("permissionTicketLifetime", "deletePoliciesOnDeleteRS",
                            "deleteResourceSetsOnDeleteRS", "pendingRequestsEnabled",
                            "emailResourceOwnerOnPendingRequestCreation",
                            "emailRequestingPartyOnPendingRequestApproval", "userProfileLocaleAttribute",
                            "resharingMode", "grantRptConditions")
            ),
            forGlobalService("UmaProvider",
                    within("defaults",
                            where(key("generalSettings").isNotPresent(),
                                    addAttribute("generalSettings").with([:]))),
                    within("defaults/generalSettings",
                            where(key("permissionTicketLifetime").isNotPresent(),
                                    addAttribute("permissionTicketLifetime").with(
                                            valueOfAttribute("defaults", "permissionTicketLifetime"))),
                            where(key("deletePoliciesOnDeleteRS").isNotPresent(),
                                    addAttribute("deletePoliciesOnDeleteRS").with(
                                            valueOfAttribute("defaults", "deletePoliciesOnDeleteRS"))),
                            where(key("deleteResourceSetsOnDeleteRS").isNotPresent(),
                                    addAttribute("deleteResourceSetsOnDeleteRS").with(
                                            valueOfAttribute("defaults", "deleteResourceSetsOnDeleteRS"))),
                            where(key("pendingRequestsEnabled").isNotPresent(),
                                    addAttribute("pendingRequestsEnabled").with(
                                            valueOfAttribute("defaults", "pendingRequestsEnabled"))),
                            where(key("emailResourceOwnerOnPendingRequestCreation").isNotPresent(),
                                    addAttribute("emailResourceOwnerOnPendingRequestCreation").with(
                                            valueOfAttribute("defaults", "emailResourceOwnerOnPendingRequestCreation"))),
                            where(key("emailRequestingPartyOnPendingRequestApproval").isNotPresent(),
                                    addAttribute("emailRequestingPartyOnPendingRequestApproval").with(
                                            valueOfAttribute("defaults", "emailRequestingPartyOnPendingRequestApproval"))),
                            where(key("userProfileLocaleAttribute").isNotPresent(),
                                    addAttribute("userProfileLocaleAttribute").with(
                                            valueOfAttribute("defaults", "userProfileLocaleAttribute"))),
                            where(key("resharingMode").isNotPresent(),
                                    addAttribute("resharingMode").with(
                                            valueOfAttribute("defaults", "resharingMode"))),
                            where(key("grantRptConditions").isNotPresent(),
                                    addAttribute("grantRptConditions").with(
                                            valueOfAttribute("defaults", "grantRptConditions")))),
                    within("defaults", deleteAttributes("permissionTicketLifetime", "deletePoliciesOnDeleteRS",
                            "deleteResourceSetsOnDeleteRS", "pendingRequestsEnabled",
                            "emailResourceOwnerOnPendingRequestCreation",
                            "emailRequestingPartyOnPendingRequestApproval", "userProfileLocaleAttribute",
                            "resharingMode", "grantRptConditions"))
            ),
            generateSymmetricSecret("am.services.uma.pct.encryption", 32),
            //---- End Rules ----

            //---- Start Rule for: OPENAM-22011 ----
            forRealmService("OAuth2Clients", updateOauth2ClientPluginSettings()),
            //---- End Rule ----

            //---- Start Rules for OPENAM-18701
            forGlobalService("DefaultAdvancedProperties",
                    where(key("org.forgerock.openam.ldap.dncache.expire.time").isNotPresent(),
                            addAttribute("org.forgerock.openam.ldap.dncache.expire.time").with(
                                    "0"))
            ),
            //---- End Rules ----

            //---- Start Rule for: OPENAM-18499
            forGlobalService("DefaultAdvancedProperties",
                    where(key("org.forgerock.openam.introspect.token.query.param.allowed").isNotPresent(),
                            addAttribute("org.forgerock.openam.introspect.token.query.param.allowed").with(
                                    true))
            ),
            //---- End Rule ----

            //---- Start Rules for: OPENAM-17698 ----
            forGlobalService("ScriptingEngineConfiguration",
                    where(entityIdIs("engineConfiguration"),
                            addToSet("whiteList")
                                    .with("java.util.Collections\$UnmodifiableRandomAccessList",
                                            "java.util.Collections\$UnmodifiableCollection\$1"))),
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["OIDC_CLAIMS", "OAUTH2_ACCESS_TOKEN_MODIFICATION",
                                                        "SOCIAL_IDP_PROFILE_TRANSFORMATION", "OAUTH2_MAY_ACT",
                                                        "OAUTH2_VALIDATE_SCOPE", "OAUTH2_EVALUATE_SCOPE",
                                                        "OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER"]),
                            addToSet("whiteList")
                                    .with("org.forgerock.oauth.clients.oidc.Claim", "java.util.Locale"))),
            //---- End Rule ----

            //---- Start Rules for OPENAM-19001 ----
            forGlobalService("Naming", within("endpointConfig",
                    where(key("idsvcsRestUrl").exists(), deleteAttributes("idsvcsRestUrl")))),
            //---- End Rules for: OPENAM-19001 ----

            //---- Start Rules for OPENAM-19297 ----
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["OAUTH2_MAY_ACT"]),
                            addToSet("whiteList")
                                    .with("java.util.Collections\$UnmodifiableSet",
                                            "java.util.Collections\$UnmodifiableMap"))),
            //---- End Rules for: OPENAM-19297 ----

            //---- Start Rules for OPENAM-18439 ----
            forService("SAML2Authentication", deleteAttributes("sloEnabled", "sloRelayState")),
            //---- End Rules for OPENAM-18439 ----

            //---- Start Rules for: OPENAM-18629 ----
            forRealmService("RESTSecurityTokenServices",
                    within("restStsGeneral",
                            where(key("is-remote-sts-instance").isNotPresent(),
                                    addAttribute("is-remote-sts-instance").with(true)))),
            //---- End Rules ----

            //---- Start Rule for: OPENAM-20383
            forGlobalService("DefaultAdvancedProperties",
                    where(key("org.forgerock.am.auth.chains.authindexuser.strict").isNotPresent(),
                            addAttribute("org.forgerock.am.auth.chains.authindexuser.strict").with(
                                    false))
            ),
            //---- End Rule ----

            createSecretStores()

    ]
}
