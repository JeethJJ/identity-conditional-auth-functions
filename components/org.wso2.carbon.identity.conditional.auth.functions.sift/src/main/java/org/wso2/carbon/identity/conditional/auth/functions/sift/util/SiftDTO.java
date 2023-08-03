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

public class SiftDTO {

    private static final Log LOG = LogFactory.getLog(SiftDTO.class);
    private final JsAuthenticationContext context;
    private final JsServletRequest request;
    //    private UniqueIDUserStoreManager uniqueIDUserStoreManager;
    private String type;
    private int tenantId;
    //User infomation
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
