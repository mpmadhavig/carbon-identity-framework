/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.security;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.MessageContext;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.registry.core.Association;
import org.wso2.carbon.registry.core.Collection;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.registry.core.service.TenantRegistryLoader;
import org.wso2.carbon.security.keystore.service.KeyStoreData;
import org.wso2.carbon.security.util.KeyStoreMgtUtil;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SecurityServiceHolder {

    private static RegistryService registryService;

    private static RealmService realmService;

    private static ConfigurationContextService ccService;

    private static TenantRegistryLoader tenantRegistryLoader;

    private static Map<String, Resource> policyResourceMap = new HashMap<>();

    private static Key key;

    private SecurityServiceHolder() {

    }

    public static Key getKey() {

        return key;
    }

    public static void setKey(String alias, boolean isSuperTenant) throws SecurityConfigException {

        SecurityServiceHolder.key = getPrivateKey(alias, isSuperTenant);
    }

    public static RegistryService getRegistryService() {
        return registryService;
    }

    public static void setRegistryService(RegistryService registryService) {
        SecurityServiceHolder.registryService = registryService;
    }

    public static Registry getRegistry() throws Exception {
        if (registryService == null) {
            throw new SecurityConfigException("Registry Service is null");
        }

        return registryService.getConfigSystemRegistry();

    }

    public static RealmService getRealmService() throws Exception {
        if (realmService == null) {
            throw new SecurityConfigException("The main user realm is null");
        }
        return realmService;
    }

    public static void setRealmService(RealmService realmService) {
        SecurityServiceHolder.realmService = realmService;
    }

    public static ConfigurationContext getConfigurationContext() throws Exception {
        if (ccService == null) {
            throw new SecurityConfigException("CC service is null");
        }
        return ccService.getClientConfigContext();
    }

    public static void setConfigurationContextService(ConfigurationContextService ccService) {
        SecurityServiceHolder.ccService = ccService;
    }

    public static void addPolicyResource(String location, Resource resource) {
        policyResourceMap.put(location, resource);
    }

    public static TenantRegistryLoader getTenantRegistryLoader() {
        return tenantRegistryLoader;
    }

    public static void setTenantRegistryLoader(TenantRegistryLoader tenantRegistryLoader) {
        SecurityServiceHolder.tenantRegistryLoader = tenantRegistryLoader;
    }

    public static Map<String, Resource> getPolicyResourceMap() {
        return policyResourceMap;
    }

    private static Key getPrivateKey(String alias, boolean isSuperTenant) throws SecurityConfigException {

        KeyStoreData[] keystores = new KeyStoreData[0];
        try {
            keystores = getKeyStores(isSuperTenant);
        } catch (RegistryException e) {
            throw new RuntimeException(e);
        }
        KeyStore keyStore = null;
        String privateKeyPassowrd = null;

        try {

            for (int i = 0; i < keystores.length; i++) {
                if (KeyStoreUtil.isPrimaryStore(keystores[i].getKeyStoreName())) {
                    KeyStoreManager keyMan = KeyStoreManager.getInstance(-1234);
                    keyStore = keyMan.getPrimaryKeyStore();
                    ServerConfiguration serverConfig = ServerConfiguration.getInstance();
                    privateKeyPassowrd = serverConfig
                            .getFirstProperty(RegistryResources.SecurityManagement.SERVER_PRIVATE_KEY_PASSWORD);
                    return keyStore.getKey(alias, privateKeyPassowrd.toCharArray());
                }
            }
        } catch (Exception e) {
            String msg = "Error has encounted while loading the key for the given alias " + alias;
            // log.error(msg, e);
            throw new SecurityConfigException(msg);
        }
        return null;
    }

    private static KeyStoreData[] getKeyStores(boolean isSuperTenant) throws SecurityConfigException, RegistryException {
        CarbonUtils.checkSecurity();
        KeyStoreData[] names = new KeyStoreData[0];
        Registry registry = SecurityServiceHolder.getRegistryService().getGovernanceSystemRegistry();
        try {
            if (registry.resourceExists(SecurityConstants.KEY_STORES)) {
                Collection collection = (Collection) registry.get(SecurityConstants.KEY_STORES);
                String[] ks = collection.getChildren();
                List<KeyStoreData> lst = new ArrayList<>();
                for (int i = 0; i < ks.length; i++) {
                    String fullname = ks[i];

                    if (RegistryResources.SecurityManagement.PRIMARY_KEYSTORE_PHANTOM_RESOURCE
                            .equals(fullname)) {
                        continue;
                    }

                    Resource store = registry.get(ks[i]);
                    int lastIndex = fullname.lastIndexOf("/");
                    String name = fullname.substring(lastIndex + 1);
                    String type = store.getProperty(SecurityConstants.PROP_TYPE);
                    String provider = store.getProperty(SecurityConstants.PROP_PROVIDER);

                    KeyStoreData data = new KeyStoreData();
                    data.setKeyStoreName(name);
                    data.setKeyStoreType(type);
                    data.setProvider(provider);

                    String alias = store.getProperty(SecurityConstants.PROP_PRIVATE_KEY_ALIAS);
                    if (alias != null) {
                        data.setPrivateStore(true);
                    } else {
                        data.setPrivateStore(false);
                    }

                    // Dump the generated public key to the file system for sub tenants
                    if (!isSuperTenant) {
                        Association[] associations = registry.getAssociations(
                                ks[i], SecurityConstants.ASSOCIATION_TENANT_KS_PUB_KEY);
                        if (associations != null && associations.length > 0) {
                            Resource pubKeyResource = registry.get(associations[0].getDestinationPath());
                            String fileName = generatePubCertFileName(ks[i],
                                    pubKeyResource.getProperty(
                                            SecurityConstants.PROP_TENANT_PUB_KEY_FILE_NAME_APPENDER));
                            if (MessageContext.getCurrentMessageContext() != null) {
                                String pubKeyFilePath = KeyStoreMgtUtil.dumpCert(
                                        MessageContext.getCurrentMessageContext().getConfigurationContext(),
                                        (byte[]) pubKeyResource.getContent(), fileName);
                                data.setPubKeyFilePath(pubKeyFilePath);
                            }
                        }
                    }
                    lst.add(data);

                }
                names = new KeyStoreData[lst.size() + 1];
                Iterator<KeyStoreData> ite = lst.iterator();
                int count = 0;
                while (ite.hasNext()) {
                    names[count] = ite.next();
                    count++;
                }

                if (isSuperTenant) {
                    KeyStoreData data = new KeyStoreData();
                    ServerConfiguration config = ServerConfiguration.getInstance();
                    String fileName = config
                            .getFirstProperty(RegistryResources.SecurityManagement.SERVER_PRIMARY_KEYSTORE_FILE);
                    String type = config
                            .getFirstProperty(RegistryResources.SecurityManagement.SERVER_PRIMARY_KEYSTORE_TYPE);
                    String name = KeyStoreUtil.getKeyStoreFileName(fileName);
                    data.setKeyStoreName(name);
                    data.setKeyStoreType(type);
                    data.setProvider(" ");
                    data.setPrivateStore(true);

                    names[count] = data;
                }

            }
            return names;
        } catch (RegistryException e) {
            String msg = "Error when getting keyStore data";
            // log.error(msg, e);
            throw new SecurityConfigException(msg, e);
        }
    }

    private static String generatePubCertFileName(String ksLocation, String uuid) {
        String tenantName = ksLocation.substring(ksLocation.lastIndexOf("/"));
        for (KeystoreUtils.StoreFileType fileType: KeystoreUtils.StoreFileType.values()) {
            String fileExtension = KeystoreUtils.StoreFileType.getExtension(fileType);
            if (tenantName.endsWith(fileExtension)) {
                tenantName = tenantName.replace(fileExtension, "");
            }
        }
        return tenantName + "-" + uuid + ".cert";
    }

}
