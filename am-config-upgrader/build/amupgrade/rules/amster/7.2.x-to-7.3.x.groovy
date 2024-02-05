/*
 * Copyright 2022-2023 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.Conditions.entityIdIs
import static org.forgerock.openam.amp.dsl.Conditions.key
import static org.forgerock.openam.amp.dsl.Conditions.pathParamIsOneOf
import static org.forgerock.openam.amp.dsl.Conditions.pathParamMatches
import static org.forgerock.openam.amp.dsl.ConfigTransforms.addToScriptingWhitelistForGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forRealmService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forService
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addAttribute
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addToSet
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.replace
import static org.forgerock.openam.amp.dsl.ServiceTransforms.within
import static org.forgerock.openam.amp.dsl.ServiceTransforms.where
import static org.forgerock.openam.amp.rules.CustomRules.addNewGlobalScriptSettings
import static org.forgerock.openam.amp.rules.CustomRules.createEmailServiceInstancesAmster
import static org.forgerock.openam.amp.rules.CustomRules.createSecretStores

def getRules() {
    return [
            //---- Start Rule for:  OPENAM-19232 ----
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamMatches("contexts", "(OAUTH2_.*|OIDC_CLAIMS)"),
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
            ),
            addNewGlobalScriptSettings("400e48ba-3f13-4144-ac7b-f824ea8e98c5", "/7_3_0_config/global/GlobalScripts"),
            //---- End Rules for: OPENAM-19232 ----

            //---- Start Rules for AME-22851 ----
            forGlobalService("IdmIntegrationService",
                    where(key("configurationCacheDuration").isNotPresent(),
                            addAttribute("configurationCacheDuration")
                                    .with(0))),
            //---- End Rules for AME-22851 ----

            //---- Start Rules for: OPENAM-22900 ----
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", [
                            "AUTHENTICATION_TREE_DECISION_NODE",
                            "CONFIG_PROVIDER_NODE",
                            "SOCIAL_IDP_PROFILE_TRANSFORMATION",
                            "AUTHENTICATION_SERVER_SIDE",
                            "SAML2_IDP_ATTRIBUTE_MAPPER",
                            "SAML2_IDP_ADAPTER",
                            "OIDC_CLAIMS",
                            "OAUTH2_ACCESS_TOKEN_MODIFICATION",
                            "OAUTH2_MAY_ACT",
                            "OAUTH2_VALIDATE_SCOPE",
                            "OAUTH2_EVALUATE_SCOPE",
                            "OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER",
                            "OAUTH2_SCRIPTED_JWT_ISSUER",
                            "SOCIAL_IDP_PROFILE_TRANSFORMATION"
                    ]),
                            addToSet("whiteList")
                                    .with("org.mozilla.javascript.JavaScriptException"))),
            //---- End Rules for OPENAM-22900 ----

            //---- Start Rules for OPENAM-19422 ----
            forGlobalService("DefaultAdvancedProperties",
                    where(key("org.forgerock.openam.ldap.keepalive.search.filter").isNotPresent(),
                            addAttribute("org.forgerock.openam.ldap.keepalive.search.filter").with(
                                    "(objectClass=*)")),
                    where(key("org.forgerock.openam.ldap.keepalive.search.base").isNotPresent(),
                            addAttribute("org.forgerock.openam.ldap.keepalive.search.base").with(
                                    ""))
            ),
            //---- End Rules for OPENAM-19422 ----

            //---- Start Rules for AME-20656 ----
            forGlobalService("DefaultCtsDataStoreProperties",
                within("amconfig.org.forgerock.services.cts.store.common.section",
                        where(key("org.forgerock.services.cts.store.max.connections").isLessThan(100),
                                replace("org.forgerock.services.cts.store.max.connections").with("100")))
            ),
            forGlobalService("CtsDataStoreProperties",
                    within("amconfig.org.forgerock.services.cts.store.common.section",
                            where(key("org.forgerock.services.cts.store.max.connections").isLessThan(100),
                                    replace("org.forgerock.services.cts.store.max.connections").with("100")))
            ),
            //---- End Rules for AME-20656 ----

            //---- Start Rules for: OPENAM-18629 ----
            forRealmService("RESTSecurityTokenServices",
                    within("restStsGeneral",
                            where(key("is-remote-sts-instance").isNotPresent(),
                                    addAttribute("is-remote-sts-instance").with(true)))),
            //---- End Rules ----

            // ---- Start Rule for: OPENAM-19660 ----
            createEmailServiceInstancesAmster(),

            forGlobalService("EmailService", within("defaults",
                    deleteAttributes("password", "username", "hostname", "sslState", "hostname", "username",
                            "port", "emailImplClassName")
            )),

            forGlobalService("EmailService", within("defaults",
                    where(key("transportType").isNotPresent(),
                            addAttribute("transportType").with("[Empty]")),
            )),

            forRealmService("EmailService", where(entityIdIs("EmailService"),
                    addAttribute("transportType").with("default-smtp")
            )),

            //---- End Rules for OPENAM-19660 ----

            //---- Start Rule for: OPENAM-19488
            forGlobalService("Authentication",
                    within("defaults/trees",
                            where(key("authenticationTreeCookieHttpOnly").isNotPresent(),
                                    addAttribute("authenticationTreeCookieHttpOnly")
                                            .with(true)))),
            forRealmService("Authentication",
                    within("trees",
                            where(key("authenticationTreeCookieHttpOnly").isNotPresent(),
                                    addAttribute("authenticationTreeCookieHttpOnly")
                                            .with(false)))),
            //---- End Rule ----

            //---- Start Rules for: OPENAM-20103 ----
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["AUTHENTICATION_TREE_DECISION_NODE"]),
                            addToSet("whiteList")
                                    .with("java.security.KeyPair", "java.security.KeyPairGenerator",
                                            "java.security.PrivateKey", "java.security.PublicKey",
                                            "java.security.spec.X509EncodedKeySpec",
                                            "java.security.spec.MGF1ParameterSpec",
                                            "javax.crypto.spec.OAEPParameterSpec", "javax.crypto.spec.PSource"))),
            //---- End Rules for OPENAM-20103 ----

            //---- Start Rules for OPENAM-19811 ----
            forService("LDAPDecision",
                    where(key("mixedCaseForPasswordChangeMessages").isNotPresent(),
                        addAttribute("mixedCaseForPasswordChangeMessages").with(false))),
            forService("IdentityStoreDecisionNode",
                    where(key("mixedCaseForPasswordChangeMessages").isNotPresent(),
                            addAttribute("mixedCaseForPasswordChangeMessages").with(false))),
            //---- End Rules for OPENAM-19811 ----

            //---- Start Rules for AME-21638 ----
            addNewGlobalScriptSettings("69f06e63-128c-4e2f-af52-079a8a6f448b", "/7_3_0_config/global/GlobalScripts"),
            //---- End Rules for AME-21638 ----

            //---- Start Rules for: AME-24033 ----
            forGlobalService("ScriptingEngineConfiguration",
                    where(pathParamIsOneOf("contexts", ["AUTHENTICATION_TREE_DECISION_NODE"]),
                            addToSet("whiteList")
                                    .with("org.forgerock.http.header.*",
                                            "org.forgerock.http.header.authorization.*"))),
            //---- End Rules for AME-24033 ----

            //---- Start Rule for: AME-23889
            forGlobalService("Authentication",
                    within("defaults/security",
                            where(key("addClearSiteDataHeader").isNotPresent(),
                                    addAttribute("addClearSiteDataHeader")
                                            .with(true)))),
            forRealmService("Authentication",
                    within("security",
                            where(key("addClearSiteDataHeader").isNotPresent(),
                                    addAttribute("addClearSiteDataHeader")
                                            .with(true)))),
            //---- End Rule ----

            //---- Start Rules for: OPENAM-20541 ----
            addToScriptingWhitelistForGlobalService(["AUTHENTICATION_TREE_DECISION_NODE"],
                    ['java.security.KeyPairGenerator$*', 'javax.crypto.spec.PSource$*']),
            //---- End Rule ----

            //---- Start Rules for: AME-23589 ----
            addToScriptingWhitelistForGlobalService(["AUTHENTICATION_TREE_DECISION_NODE",
                                                     "AUTHENTICATION_SERVER_SIDE",
                                                     "CONFIG_PROVIDER_NODE",
                                                     "OIDC_CLAIMS",
                                                     "OAUTH2_ACCESS_TOKEN_MODIFICATION",
                                                     "OAUTH2_MAY_ACT",
                                                     "OAUTH2_VALIDATE_SCOPE",
                                                     "OAUTH2_EVALUATE_SCOPE",
                                                     "OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER",
                                                     "OAUTH2_SCRIPTED_JWT_ISSUER",
                                                     "POLICY_CONDITION",
                                                     "SAML2_IDP_ADAPTER",
                                                     "SAML2_IDP_ATTRIBUTE_MAPPER",
                                                     "SOCIAL_IDP_PROFILE_TRANSFORMATION"],
                    ["sun.security.ec.ECPrivateKeyImpl"]),
            //---- End Rules for AME-23589 ----

            //---- Start Rules for AME-23793 ----
            addToScriptingWhitelistForGlobalService(["AUTHENTICATION_TREE_DECISION_NODE"],
                    ["org.forgerock.openam.authentication.callbacks.IdPCallback",
                     "org.forgerock.openam.authentication.callbacks.ValidatedPasswordCallback",
                     "org.forgerock.openam.authentication.callbacks.ValidatedUsernameCallback"]),
            //---- End Rules for AME-23793 ----

            //---- Start Rules for: AME-24175 ----
            addToScriptingWhitelistForGlobalService(["SAML2_IDP_ADAPTER"],
                    ["javax.servlet.http.Cookie",
                     "javax.xml.parsers.DocumentBuilder",
                     "javax.xml.parsers.DocumentBuilderFactory",
                     "org.w3c.dom.Document",
                     "org.w3c.dom.Element",
                     "org.xml.sax.InputSource"]),
            //---- End Rules for AME-24175 ----

            //---- Start Rules for AME-23503 ----
            addToScriptingWhitelistForGlobalService(["SAML2_IDP_ADAPTER"],
                    ["com.sun.identity.saml2.assertion.*",
                     "com.sun.identity.saml2.assertion.impl.*",
                     "com.sun.identity.saml2.protocol.*",
                     "com.sun.identity.saml2.protocol.impl.*"]),
            //---- End Rules for AME-23503 ----

            //---- Start Rules for: AME-24460 ----
            addToScriptingWhitelistForGlobalService([
                    "AUTHENTICATION_SERVER_SIDE",
                    "AUTHENTICATION_TREE_DECISION_NODE",
                    "CONFIG_PROVIDER_NODE",
                    "OAUTH2_ACCESS_TOKEN_MODIFICATION",
                    "OAUTH2_AUTHORIZE_ENDPOINT_DATA_PROVIDER",
                    "OAUTH2_EVALUATE_SCOPE",
                    "OAUTH2_MAY_ACT",
                    "OAUTH2_SCRIPTED_JWT_ISSUER",
                    "OAUTH2_VALIDATE_SCOPE",
                    "OIDC_CLAIMS",
                    "POLICY_CONDITION"
            ], ["org.forgerock.openam.scripting.api.identity.ScriptedIdentity"]),
            //---- End Rules for AME-24460 ----

            createSecretStores()
    ]
}
