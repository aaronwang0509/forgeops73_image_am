/*
 * Copyright 2019 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */
package org.forgerock.openam.amp

import static org.forgerock.openam.amp.dsl.ConfigTransforms.forGlobalService
import static org.forgerock.openam.amp.dsl.ConfigTransforms.forRealmService
import static org.forgerock.openam.amp.dsl.ServiceTransforms.named
import static org.forgerock.openam.amp.dsl.ServiceTransforms.replace
import static org.forgerock.openam.amp.dsl.ServiceTransforms.where
import static org.forgerock.openam.amp.dsl.ServiceTransforms.within
import static org.forgerock.openam.amp.dsl.Conditions.key

def getRules() {

    return [
            forGlobalService("DefaultSecurityProperties",
                    named("move keystory keys to new directory structure",
                            within("amconfig.header.securitykey",
                                    replace("com.sun.identity.saml.xmlsig.keystore").with("%BASE_DIR%/security/keystores/keystore.jceks"),
                                    replace("com.sun.identity.saml.xmlsig.storepass").with("%BASE_DIR%/security/secrets/default/.storepass"),
                                    replace("com.sun.identity.saml.xmlsig.keypass").with("%BASE_DIR%/security/secrets/default/.keypass")
                            )
                    )
            ),
            forGlobalService("AmsterModule",
                    named("move global Amster authorized keys to new directory structure",
                            within("defaults",
                                replace("authorizedKeys").with("%BASE_DIR%/security/keys/amster/authorized_keys")))
            ),
            forRealmService("AmsterModule",
                    named("move realm Amster authorized keys to new directory structure",
                        replace("authorizedKeys").with("%BASE_DIR%/security/keys/amster/authorized_keys")
                    )
            ),
            forGlobalService("AuthenticatorOATH",
                    named("Move default oauth device encryption keystore to new directory structure",
                            within("defaults",
                                    replace("authenticatorOATHDeviceSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks"))
                    )
            ),
            forRealmService("AuthenticatorOATH",
                    named("move oauth device encryption keystore to new directory structure",
                        replace("authenticatorOATHDeviceSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks")
                    )
            ),
            forGlobalService("AuthenticatorPush",
                    named("move default push device encryption keystore to new directory structure",
                            within("defaults",
                                    replace("authenticatorPushDeviceSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks"))
                    )
            ),
            forRealmService("AuthenticatorPush",
                    named("move push device encryption keystore to new directory structure",
                        replace("authenticatorPushDeviceSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks")
                    )
            ),
            forGlobalService("AuthenticatorWebAuthn",
                    named("move default web authentication device encryption to new directory structure",
                            within("defaults",
                                replace("authenticatorWebAuthnDeviceSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks")))
            ),
            forRealmService("AuthenticatorWebAuthn",
                    named("move web authn device encryption keystore to new directory structure",
                        replace("authenticatorWebAuthnDeviceSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks")
                    )
            ),
            forGlobalService("DeviceIDService",
                    named("move default device ID device encryption keystore to new directory structure",
                            within("defaults",
                                    replace("deviceIdSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks"))
                    )
            ),
            forRealmService("DeviceIDService",
                    named("move device ID device encryption keystore to new directory structure",
                        replace("deviceIdSettingsEncryptionKeystore").with("%BASE_DIR%/security/keystores/keystore.jks")
                    )
            ),
            forGlobalService("Logging",
                    named("move file logging to new directory structure", within("file",
                            where(key("location").is("%BASE_DIR%/%SERVER_URI%/log/"),
                                    replace("location").with("%BASE_DIR%/var/log/")))),
                    named("move certificate store to new directory structure", within("general",
                            where(key("certificateStore").is("%BASE_DIR%/%SERVER_URI%/Logger.jks"),
                                    replace("certificateStore").with("%BASE_DIR%/var/audit/Logger.jks"))))
            ),
            forGlobalService("Monitoring",
                    named("move monitoring file to new directory structure",
                            where(key("authfilePath").is("%BASE_DIR%/%SERVER_URI%/openam_mon_auth"),
                                    replace("authfilePath").with("%BASE_DIR%/security/openam_mon_auth")))
            ),
            forGlobalService("DefaultAdvancedProperties",
                    named("move installation directory to new directory structure",
                            where(key("com.iplanet.am.installdir").is("%BASE_DIR%/%SERVER_URI%"),
                                replace("com.iplanet.am.installdir").with("%BASE_DIR%")))
            ),
            forGlobalService("DefaultGeneralProperties",
                    named("move debug directory to new directory structure",
                            within("amconfig.header.debug",
                                    where(key("com.iplanet.services.debug.directory").is("%BASE_DIR%/%SERVER_URI%/debug"),
                                            replace("com.iplanet.services.debug.directory").with("%BASE_DIR%/var/debug"))))
            ),
            forGlobalService("DefaultSessionProperties",
                    named("move session statistics logging to new directory structure",
                            within("amconfig.header.sessionlogging",
                                    where(key("com.iplanet.services.stats.directory").is("%BASE_DIR%/%SERVER_URI%/stats"),
                                            replace("com.iplanet.services.stats.directory").with("%BASE_DIR%/var/stats"))))
            ),
            forGlobalService("FileSystemSecretStore",
                    named("move secrets directory to new directory structure",
                            replace("directory").with("%BASE_DIR%/security/secrets/encrypted"))
            ),

            forGlobalService("Json",
                    named("move json config location to new directory structure",
                            within("jsonConfig",
                                    where(key("location").is("%BASE_DIR%/%SERVER_URI%/log/"),
                                            replace("location").with("%BASE_DIR%/log/audit/"))))
            ),
            forGlobalService("KeyStoreSecretStore",
                    named("move global jceks keystore to new directory structure",
                            replace("file").with("%BASE_DIR%/security/keystores/keystore.jceks"))
            ),
            forGlobalService("SessionProperties",
                    named("move global session statisticts directory to new directory structure",
                            within("amconfig.header.sessionlogging/com.iplanet.services.stats.directory",
                                    where(key("value").is("%BASE_DIR%/%SERVER_URI%/stats"),
                                            replace("value").with("%BASE_DIR%/var/stats"))))
            )

    ]
}
