/*
 * Copyright (c) 2015-2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.storage.SessionDataStorageOptimizationClientException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.storage.SessionDataStorageOptimizationException;
import org.wso2.carbon.identity.application.authentication.framework.exception.session.storage.SessionDataStorageOptimizationServerException;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.Serializable;
import java.util.Iterator;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.Config.SESSION_DATA_STORAGE_OPTIMIZATION_ENABLED;

/**
 * This class is used to cache the data about the
 * authentication request sent from a servlet.
 */
public class AuthenticationContextCache extends
        AuthenticationBaseCache<AuthenticationContextCacheKey, AuthenticationContextCacheEntry> {

    private static final String AUTHENTICATION_CONTEXT_CACHE_NAME = "AuthenticationContextCache";
    private static final Log log = LogFactory.getLog(AuthenticationContextCache.class);
    private static volatile AuthenticationContextCache instance;
    private final boolean isTemporarySessionDataPersistEnabled;
    private final boolean isSessionDataStorageOptimizationEnabled;

    /**
     * Private constructor which will not allow to create objects of this class from outside.
     */
    private AuthenticationContextCache() {
        super(AUTHENTICATION_CONTEXT_CACHE_NAME, true);
        if (IdentityUtil.getProperty("JDBCPersistenceManager.SessionDataPersist.Temporary") != null) {
            isTemporarySessionDataPersistEnabled = Boolean.parseBoolean(
                    IdentityUtil.getProperty("JDBCPersistenceManager.SessionDataPersist.Temporary"));
        } else {
            isTemporarySessionDataPersistEnabled = false;
        }
        if (IdentityUtil.getProperty(SESSION_DATA_STORAGE_OPTIMIZATION_ENABLED) != null) {
            isSessionDataStorageOptimizationEnabled = Boolean.parseBoolean(IdentityUtil.getProperty(
                    SESSION_DATA_STORAGE_OPTIMIZATION_ENABLED));
        } else {
            isSessionDataStorageOptimizationEnabled = true;
        }
    }

    /**
     * Singleton method.
     *
     * @return AuthenticationContextCache
     */
    public static AuthenticationContextCache getInstance() {
        if (instance == null) {
            synchronized (AuthenticationContextCache.class) {
                if (instance == null) {
                    instance = new AuthenticationContextCache();
                }
            }
        }
        return instance;
    }

    /**
     * Add a cache entry.
     *
     * @param key   Key which cache entry is indexed.
     * @param entry Actual object where cache entry is placed.
     */
    public void addToCache(AuthenticationContextCacheKey key, AuthenticationContextCacheEntry entry) {

        super.addToCache(key, entry);
        if (isTemporarySessionDataPersistEnabled) {
            int tenantId = MultitenantConstants.INVALID_TENANT_ID;
            String tenantDomain = entry.getContext().getTenantDomain();
            if (tenantDomain != null) {
                tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            }

            if (entry.getContext() != null && entry.getContext().getProperties() != null) {
                Iterator it = entry.getContext().getProperties().entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry<String, Object> item = (Map.Entry<String, Object>) it.next();
                    if (!(item.getValue() instanceof Serializable)) {
                        it.remove();
                    }
                }
                if (log.isDebugEnabled()) {
                    String message = "[ Context Id : " + key.getContextId() +
                            ", Cache type : " + AUTHENTICATION_CONTEXT_CACHE_NAME +
                            ", Operation : STORE ]";
                    log.debug("Authentication context is stored with details " + message);
                }
                if (isSessionDataStorageOptimizationEnabled && entry.getContext() != null) {
                    try {
                        AuthenticationContextLoader.getInstance().optimizeAuthenticationContext(entry.getContext());
                    } catch (SessionDataStorageOptimizationClientException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("Client error occurred while optimizing the Authentication context with " +
                                    "context id: " + entry.getContext().getContextIdentifier(), e);
                        }
                        return;
                    } catch (SessionDataStorageOptimizationServerException e) {
                        log.error("Server error occurred while optimizing the Authentication context with " +
                                "context id: " + entry.getContext().getContextIdentifier(), e);
                        return;
                    } catch (SessionDataStorageOptimizationException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("Error occurred while optimizing the Authentication context with " +
                                    "context id: " + entry.getContext().getContextIdentifier(), e);
                        }
                        return;
                    }
                }
                SessionDataStore.getInstance().storeSessionData(key.getContextId(), AUTHENTICATION_CONTEXT_CACHE_NAME,
                        entry, tenantId);
                try {
                    AuthenticationContextLoader.getInstance().loadAuthenticationContext(entry.getContext());
                } catch (SessionDataStorageOptimizationClientException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Client error occurred while loading optimized authentication context"
                                + " with context id: " + entry.getContext().getContextIdentifier(), e);
                    }
                } catch (SessionDataStorageOptimizationServerException e) {
                    log.error("Server error occurred while loading optimized authentication " +
                            "context with context id: " + entry.getContext().getContextIdentifier(), e);
                } catch (SessionDataStorageOptimizationException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while loading optimized authentication " +
                                "context with context id: " + entry.getContext().getContextIdentifier(), e);
                    }
                }
            }
        }
    }

    /**
     * Retrieves a cache entry.
     *
     * @param key CacheKey
     * @return Cached entry.
     */
    public AuthenticationContextCacheEntry getValueFromCache(AuthenticationContextCacheKey key) {
        AuthenticationContextCacheEntry entry = super.getValueFromCache(key);
        if (log.isDebugEnabled() && entry != null) {
            log.debug("Found a valid AuthenticationContextCacheEntry corresponding to the session data key : " +
                    key.getContextId() + " from the cache. ");
        }
        if (entry == null && isTemporarySessionDataPersistEnabled) {
            entry = (AuthenticationContextCacheEntry) SessionDataStore.getInstance().
                    getSessionData(key.getContextId(), AUTHENTICATION_CONTEXT_CACHE_NAME);
            if (log.isDebugEnabled()) {
                log.debug("Found a valid AuthenticationContextCacheEntry corresponding to the session data key : " +
                        key.getContextId() + " from the data store. ");
            }

            // Update the cache again with the new value.
            super.addToCache(key, entry);
        }
        if (entry != null) {
            try {
                AuthenticationContextLoader.getInstance().loadAuthenticationContext(entry.getContext());
            } catch (SessionDataStorageOptimizationClientException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Client error occurred while loading optimized authentication context " +
                            "with context id: " + entry.getContext().getContextIdentifier(), e);
                }
                entry = null;
            } catch (SessionDataStorageOptimizationServerException e) {
                log.error("Server error occurred while loading optimized authentication context " +
                        "with context id: " + entry.getContext().getContextIdentifier(), e);
                entry = null;
            } catch (SessionDataStorageOptimizationException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while loading optimized authentication context " +
                            "with context id: " + entry.getContext().getContextIdentifier(), e);
                }
                entry = null;
            }
        }
        return entry;
    }

    /**
     * Clears a cache entry.
     *
     * @param key Key to clear cache.
     */
    public void clearCacheEntry(AuthenticationContextCacheKey key) {
        super.clearCacheEntry(key);
        if (isTemporarySessionDataPersistEnabled) {
            SessionDataStore.getInstance().clearSessionData(key.getContextId(), AUTHENTICATION_CONTEXT_CACHE_NAME);
        }
    }
}
