/*
 * Copyright 2017-2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.ConfigTransforms.*
import static org.forgerock.openam.amp.dsl.ServiceTransforms.*

def getRules() {
    return [
            forGlobalService("ClientDetection", deleteInstance()),
            forService("OAuth2Module", deleteInstance()), //FIXME AME-14675
            forRealmService("PolicyConfiguration", deleteAttributes("rolesBaseDn", "rolesSearchScope")),
            forGlobalService("PolicyConfiguration", within("defaults", deleteAttributes("rolesBaseDn", "rolesSearchScope"))),
            forGlobalService("IdRepository", within("defaults", deleteAttributes("sunCoexistenceAttributeMapping"))),
            forRealmService("IdRepository", deleteAttributes("sunCoexistenceAttributeMapping")),
            forGlobalService("OAuth2Provider", addAttribute("statelessGrantTokenUpgradeCompatibilityMode").with(true)),
            forGlobalService("Authentication", addToSet("authenticators").with(
                    "org.forgerock.openam.authentication.modules.social.SocialAuthOAuth2",
                    "org.forgerock.openam.authentication.modules.social.SocialAuthVK",
                    "org.forgerock.openam.authentication.modules.social.SocialAuthWeChat",
                    "org.forgerock.openam.authentication.modules.social.SocialAuthWeChatMobile",
                    "org.forgerock.openam.authentication.modules.social.SocialAuthOpenID",
                    "org.forgerock.openam.authentication.modules.social.SocialAuthInstagram",
                    "org.forgerock.openam.authentication.modules.jwtpop.JwtProofOfPossession",
                    "org.forgerock.openam.authentication.modules.edge.EdgeRegistration",
                    "org.forgerock.openam.authentication.modules.edge.EdgeAuthentication")),
            forGlobalService("UmaProvider", within("defaults", deleteAttributes("requireTrustElevation", "rptLifetime"))),
            forRealmService("UmaProvider", deleteAttributes("requireTrustElevation", "rptLifetime")),
            forRealmService("Applications",
                    where({ config, configProvider -> config.key.entityId != "sunAMDelegationService" },
                            addToSet("conditions").with("Transaction") // TODO: check whether this should apply to umars
                    )
            ),
            forGlobalService("IdRepositoryUser",
                    where({ config, configProvider -> config.key.entityId == "amService-URLAccessAgent" },
                            deleteInstance()
                    )
            ),
            forGlobalService("ScriptingEngineConfiguration",
                    where({ config, configProvider -> config.key.pathParams.get("contexts").equals("OIDC_CLAIMS") },
                            addToSet("whiteList").with(
                                    "java.util.Collections\$EmptyList",
                                    "java.util.ArrayList\$Itr",
                                    "java.util.LinkedHashMap\$LinkedEntryIterator",
                                    "java.util.Collections\$SingletonList",
                                    "org.forgerock.oauth2.core.exceptions.InvalidRequestException",
                                    "org.forgerock.openidconnect.Claim",
                                    "java.util.Collections\$1",
                                    "java.util.Collections\$EmptyList",
                                    "org.forgerock.openidconnect.ssoprovider.OpenIdConnectSSOToken"
                            ),
                            removeFromSet("whiteList").with(
                                    "org.forgerock.http.protocol.Cookie"
                            )
                    )
            ),
            forGlobalService("SecurityProperties",
                    within("amconfig.header.encryption", deleteAttributes("com.iplanet.am.service.secret"))),
            forGlobalService("DefaultAdvancedProperties", deleteAttributes("com.sun.identity.appendSessionCookieInURL"))
    ]
}
