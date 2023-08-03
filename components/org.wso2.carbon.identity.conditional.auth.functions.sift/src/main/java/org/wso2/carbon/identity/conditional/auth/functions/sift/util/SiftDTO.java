/**
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.sift.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import ua_parser.Client;
import ua_parser.Parser;

/**
 * Data transfer object for the Sift event payload.
 */
public class SiftDTO {

    private static final Log LOG = LogFactory.getLog(SiftDTO.class);
    private final JsAuthenticationContext context;
    private final JsServletRequest request;
    private String type;
    private int tenantId;
    private String userId;
    private String internalUserId;
    private String userEmail;
    private String ip;
    private long eventTime;
    private String userAgent;
    private String acceptLanguage;
    private String os;
    private String osVersion;
    private String deviceManufacturer;
    private String appName;
    private String customBrowserName;
    private String customBrowserVersion;
//    private String appVersion;
//    private String clientLanguage;
//    private String deviceModel;
//    private String deviceUniqueID; //iOS - IFV identifier, Android - Android ID
//    private String contentLanguage;
//    private String socialLoginType;
//    private String loginStatus;
//    private String failureReason;
//    private String accountType; //check availability and if required
//    private String brandName; //what and why
//    private String siteCountry; //what and why
//    private String siteDomain;

    public SiftDTO(JsServletRequest request, JsAuthenticationContext context) {

        this.context = context;
        this.request = request;
        init();
    }

    public String getType() {

        return type;
    }

    public int getTenantId() {

        return tenantId;
    }

    public String getUserId() {

        return userId;
    }

    public String getInternalUserId() {

        return internalUserId;
    }

    public String getUserEmail() {

        return userEmail;
    }

    public String getIp() {

        return ip;
    }

    public long getEventTime() {

        return eventTime;
    }

    public String getUserAgent() {

        return userAgent;
    }

    public String getAcceptLanguage() {

        return acceptLanguage;
    }

    public String getOs() {

        return os;
    }

    public String getOsVersion() {

        return osVersion;
    }

    public String getDeviceManufacturer() {

        return deviceManufacturer;
    }

    public String getAppName() {

        return appName;
    }

    public String getCustomBrowserName() {

        return customBrowserName;
    }

    public String getCustomBrowserVersion() {

        return customBrowserVersion;
    }

    private void init() {

        if (context.getContext().getSubject() != null) {
            if (context.getContext().isLogoutRequest()) {
                type = "logout";
            } else {
                type = "login";
            }
            try {
                this.internalUserId = context.getContext().getSubject().getUserId();
                this.userId = context.getContext().getSubject().getAuthenticatedSubjectIdentifier();
                // TODO: 2023-06-30 If this differs according to the db, shouldn't we consider all?
                this.tenantId = IdentityTenantUtil.getTenantId(context.getContext().getSubject().getTenantDomain());
            } catch (UserIdNotFoundException e) {
                LOG.error("User info not found");
            }

            // TODO: 2023-06-30 Check if i can get the ip from the context
            this.ip = IdentityUtil.getClientIpAddress(request.getWrapped().getWrapped());

            try {
                this.userEmail = getEmailValueForUsername(userId);
            } catch (Exception e) {
                LOG.error("Unable to get user email");
            }

            this.userAgent = request.getWrapped().getWrapped().getHeader("User-Agent");
            this.acceptLanguage = request.getWrapped().getWrapped().getHeader("Accept-Language");

            Parser uaParser = new Parser();
            Client userAgentParser = uaParser.parse(userAgent);
            this.deviceManufacturer = userAgentParser.device.family;
            this.os = userAgentParser.os.family;
            this.osVersion = concatenateVersionString(userAgentParser.os.major, userAgentParser.os.minor,
                    userAgentParser.os.patch, userAgentParser.os.patchMinor);
            this.customBrowserName = userAgentParser.userAgent.family;
            this.customBrowserVersion =
                    concatenateVersionString(userAgentParser.userAgent.major, userAgentParser.userAgent.minor,
                            userAgentParser.userAgent.patch, null);

            // TODO: 2023-07-06 Can we create a timestamp - context.getContext().parameters.entrySet() - datamap - authstarttime
            this.eventTime = System.currentTimeMillis();
            // TODO: 2023-08-02 Check if it always returns the client app name
            this.appName = context.getContext().getServiceProviderName();

        } else {
            LOG.error("Subject is null");
        }
    }

    /**
     * Concatenate the version string.
     */
    private String concatenateVersionString(String majorVersion, String minorVersion, String patchVersion,
                                            String patchMinorVersion) {

        StringBuilder result = new StringBuilder();
        if (!StringUtils.isBlank(majorVersion)) {
            result.append(majorVersion);
            if (!StringUtils.isBlank(minorVersion)) {
                result.append(".").append(minorVersion);
                if (!StringUtils.isBlank(patchVersion)) {
                    result.append(".").append(patchVersion);
                    if (!StringUtils.isBlank(patchMinorVersion)) {
                        result.append(".").append(patchMinorVersion);
                    }
                }
            }
        }
        return result.toString();
    }

    /**
     * Get the email claim value for the given username.
     *
     * @param username Fully qualified username of the user.
     * @return Email claim value.
     */
    private String getEmailValueForUsername(String username) {

        UserRealm userRealm;
        String tenantAwareUsername;
        String email = null;
        try {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = IdentityTenantUtil.getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (userRealm != null) {
                email = userRealm.getUserStoreManager()
                        .getUserClaimValue(tenantAwareUsername, "http://wso2.org/claims/emailaddress", null);
            } else {
                LOG.error("Cannot find the user realm for the given tenant domain : " + tenantDomain);
            }
        } catch (UserStoreException e) {
            LOG.error("Cannot find the email claim for username : " + username, e);
        }
        return email;
    }
}
