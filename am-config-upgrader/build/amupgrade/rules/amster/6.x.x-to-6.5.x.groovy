/*
 * Copyright 2018-2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.ConfigTransforms.forGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forRealmService
import static org.forgerock.openam.amp.dsl.ServiceTransforms.addAttribute
import static org.forgerock.openam.amp.dsl.ServiceTransforms.copyKeyAliasMapEntryToSecretsApi
import static org.forgerock.openam.amp.dsl.ServiceTransforms.deleteAttributes
import static org.forgerock.openam.amp.dsl.ServiceTransforms.moveKeyAliasMapToSecretsApi
import static org.forgerock.openam.amp.dsl.ServiceTransforms.moveKeyAliasToSecretsApi
import static org.forgerock.openam.amp.dsl.ServiceTransforms.moveSymmetricKeyToSecretsApi
import static org.forgerock.openam.amp.dsl.ServiceTransforms.replace
import static org.forgerock.openam.amp.dsl.ServiceTransforms.where
import static org.forgerock.openam.amp.dsl.ServiceTransforms.within
import static org.forgerock.openam.amp.dsl.Conditions.key
import static org.forgerock.openam.amp.framework.core.secrets.Secret.Format.BASE64
import static org.forgerock.openam.amp.rules.CustomRules.createSecretStores

def getRules() {
    return [
            forGlobalService("OAuth2Provider",
                    within("defaults/advancedOAuth2Config",
                            where(key("codeVerifierEnforced").is((Object) true),
                                    replace("codeVerifierEnforced").with("true")),
                            where(key("codeVerifierEnforced").is((Object) false),
                                    replace("codeVerifierEnforced").with("false")))
            ),

            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            where(key("codeVerifierEnforced").is((Object) true),
                                    replace("codeVerifierEnforced").with("true")),
                            where(key("codeVerifierEnforced").is((Object) false),
                                    replace("codeVerifierEnforced").with("false")))
            ),

            forGlobalService("AdvancedProperties", deleteAttributes("com.iplanet.am.buildDate",
                    "com.iplanet.am.buildRevision", "com.iplanet.am.buildVersion", "com.iplanet.am.version")),

            forRealmService("OAuth2Clients",
                    within("advancedOAuth2ClientConfig",
                        addAttribute("grantTypes").with([
                                "authorization_code", "implicit", "password", "client_credentials", "refresh_token",
                                "urn:ietf:params:oauth:grant-type:uma-ticket",
                                "urn:ietf:params:oauth:grant-type:device_code",
                                "urn:ietf:params:oauth:grant-type:saml2-bearer"
                        ].toSet()))),
            forGlobalService("PersistentCookieModule",
                    within("defaults",
                            moveSymmetricKeyToSecretsApi("hmacKey",
                                    "am.default.authentication.modules.persistentcookie.signing", BASE64))),
            forRealmService("PersistentCookieModule",
                    moveSymmetricKeyToSecretsApi("hmacKey",
                            "am.authentication.modules.persistentcookie.%s.signing", BASE64)),
            forGlobalService("Authentication",
                    within("defaults/security",
                            moveKeyAliasToSecretsApi("keyAlias",
                                    ["am.default.authentication.modules.persistentcookie.encryption"]))),
            forRealmService("Authentication",
                    within("security",
                            moveKeyAliasToSecretsApi("keyAlias",
                                    ["am.default.authentication.modules.persistentcookie.encryption"]))),
            forGlobalService("OAuth2Provider",
                    moveSymmetricKeyToSecretsApi("idTokenAuthenticitySecret",
                            "am.services.oauth2.jwt.authenticity.signing", BASE64),
                    moveKeyAliasToSecretsApi("agentIdTokenSigningKeyAlias",
                            ["am.global.services.oauth2.oidc.agent.idtoken.signing"])),
            forGlobalService("OAuth2Provider",
                    within("defaults/advancedOAuth2Config",
                            moveSymmetricKeyToSecretsApi("tokenSigningHmacSharedSecret",
                                    "am.services.oauth2.stateless.signing.HMAC", BASE64),
                            moveKeyAliasToSecretsApi("keypairName",
                                    ["am.services.oauth2.stateless.signing.RSA", "am.services.oauth2.oidc.signing.RSA",
                                     "am.applications.agents.remote.consent.request.signing.RSA"]),
                            moveKeyAliasToSecretsApi("tokenEncryptionKeyAlias",
                                    ["am.services.oauth2.stateless.token.encryption"]),
                            moveKeyAliasMapToSecretsApi("tokenSigningECDSAKeyAlias",
                                    ["am.services.oauth2.stateless.signing.", "am.services.oauth2.oidc.signing.",
                                     "am.applications.agents.remote.consent.request.signing."])),
                    within("defaults/coreOIDCConfig",
                            copyKeyAliasMapEntryToSecretsApi("tokenEncryptionSigningKeyAlias", "RSA-OAEP-256",
                                    "am.services.oauth2.remote.consent.response.decryption"),
                            moveKeyAliasMapToSecretsApi("tokenEncryptionSigningKeyAlias",
                                    ["am.services.oauth2.oidc.decryption."]))),
            forRealmService("OAuth2Provider",
                    within("advancedOAuth2Config",
                            moveSymmetricKeyToSecretsApi("tokenSigningHmacSharedSecret",
                                    "am.services.oauth2.stateless.signing.HMAC", BASE64),
                            moveKeyAliasToSecretsApi("keypairName",
                                    ["am.services.oauth2.stateless.signing.RSA", "am.services.oauth2.oidc.signing.RSA",
                                     "am.applications.agents.remote.consent.request.signing.RSA"]),
                            moveKeyAliasToSecretsApi("tokenEncryptionKeyAlias",
                                    ["am.services.oauth2.stateless.token.encryption"]),
                            moveKeyAliasMapToSecretsApi("tokenSigningECDSAKeyAlias",
                                    ["am.services.oauth2.stateless.signing.", "am.services.oauth2.oidc.signing.",
                                     "am.applications.agents.remote.consent.request.signing."])),
                    within("coreOIDCConfig",
                            copyKeyAliasMapEntryToSecretsApi("tokenEncryptionSigningKeyAlias", "RSA-OAEP-256",
                                    "am.services.oauth2.remote.consent.response.decryption"),
                            moveKeyAliasMapToSecretsApi("tokenEncryptionSigningKeyAlias",
                                    ["am.services.oauth2.oidc.decryption."]))),
            createSecretStores()
    ]
}
