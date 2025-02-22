/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.common.cache;

import org.wso2.carbon.identity.application.common.model.UserDefinedLocalAuthenticatorConfig;
import org.wso2.carbon.identity.core.cache.CacheEntry;

import java.util.List;

/**
 * Cache Entry for all user defined local application authenticators.
 */
public class AuthenticatorsCacheEntry extends CacheEntry {

    private static final long serialVersionUID = 7829131001232944017L;

    private List<UserDefinedLocalAuthenticatorConfig> userDefinedLocalAuthenticators;

    public AuthenticatorsCacheEntry(List<UserDefinedLocalAuthenticatorConfig> userDefinedLocalAuthenticators) {

        this.userDefinedLocalAuthenticators = userDefinedLocalAuthenticators;
    }

    public List<UserDefinedLocalAuthenticatorConfig> getUserDefinedLocalAuthenticators() {

        return userDefinedLocalAuthenticators;
    }

    public void setAuthenticatorConfig(List<UserDefinedLocalAuthenticatorConfig> userDefinedLocalAuthenticators) {

        this.userDefinedLocalAuthenticators = userDefinedLocalAuthenticators;
    }
}
