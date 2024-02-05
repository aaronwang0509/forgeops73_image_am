/*
 * Copyright 2018-2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.ConfigTransforms.*
import static org.forgerock.openam.amp.dsl.ServiceTransforms.*
import static org.forgerock.openam.amp.dsl.Conditions.*

def getRules() {
    def URL_RESOURCE_TYPE_UUID = "76656a38-5f8e-401b-83aa-4ccb74ce88d2"
    return [

            forGlobalService("Authentication", removeFromSet("authenticators").with(
                    "org.forgerock.openam.authentication.modules.edge.EdgeRegistration",
                    "org.forgerock.openam.authentication.modules.edge.EdgeAuthentication")),
            forGlobalService("DefaultSdkProperties",
                    within("amconfig.header.datastore",
                            deleteAttributes("com.sun.identity.sm.ldap.enableProxy")),
                    within("amconfig.header.cachingreplica",
                            deleteAttributes(
                                    "com.iplanet.am.replica.num.retries",
                                    "com.iplanet.am.replica.delay.between.retries"))),
            forGlobalService("EdgeAuthenticationModule", deleteInstance()),
            forGlobalService("EdgeRegistrationModule", deleteInstance()),
            forGlobalService("AuthLevelDecision", deleteInstance()),
            forGlobalService("ChoiceCollector", deleteInstance()),
            forGlobalService("DataStoreDecision", deleteInstance()),
            forGlobalService("InnerTreeEvaluator", deleteInstance()),
            forGlobalService("ModifyAuthLevel", deleteInstance()),
            forGlobalService("PasswordCollector", deleteInstance()),
            forGlobalService("RemoveSessionProperties", deleteInstance()),
            forGlobalService("ScriptedDecision", deleteInstance()),
            forGlobalService("SetSessionProperties", deleteInstance()),
            forGlobalService("UsernameCollector", deleteInstance()),
            forGlobalService("ZeroPageLoginCollector", deleteInstance()),

            forRealmService("RemoteConsentAgent", where(
                    key("remoteConsentResponseEncryptionAlgorithm").is("RSA128")
                            | (key("remoteConsentResponseEncryptionAlgorithm").is("RSA-OAEP")),
                    replace("remoteConsentResponseEncryptionAlgorithm").with("RSA-OAEP-256"))),
            forRealmService("RemoteConsentAgent", where(
                    key("remoteConsentRequestEncryptionAlgorithm").is("RSA128")
                            | (key("remoteConsentRequestEncryptionAlgorithm").is("RSA-OAEP")),
                    replace("remoteConsentRequestEncryptionAlgorithm").with("RSA-OAEP-256"))),
            forRealmService("RemoteConsentAgent", where(key("remoteConsentResponseSigningAlg").is("NONE"),
                    replace("remoteConsentResponseSigningAlg").with("RSA-OAEP-256"))),
            forRealmService("EdgeAuthenticationModule", deleteInstance()),
            forRealmService("EdgeRegistrationModule", deleteInstance()),
            forRealmService("ResourceTypes",
                    where({ config, configProvider -> config.key.entityId == "UrlResourceType" },
                            replace("_id").with(URL_RESOURCE_TYPE_UUID),
                            replace("uuid").with(URL_RESOURCE_TYPE_UUID),
                            setEntityId(URL_RESOURCE_TYPE_UUID)
                    )
            ),
            forRealmService("Policies",
                    where(key("resourceTypeUuid").is("UrlResourceType"),
                        replace("resourceTypeUuid").with(URL_RESOURCE_TYPE_UUID))),
            forRealmService("Applications",
                    where(key("resourceTypeUuids").contains("UrlResourceType"),
                        removeFromSet("resourceTypeUuids").with("UrlResourceType"),
                        addToSet("resourceTypeUuids").with(URL_RESOURCE_TYPE_UUID))),
            forRealmService("DatabaseRepositoryEarlyAccess", deleteInstance()),
            forRealmService("Files", deleteInstance()),
            forGlobalService("DefaultAdvancedProperties", deleteAttributes("com.sun.identity.urlchecker.dorequest"))
    ]
}
