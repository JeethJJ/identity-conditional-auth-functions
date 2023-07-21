package org.wso2.carbon.identity.conditional.auth.functions.sift.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.conditional.auth.functions.sift.internal.SiftAuthFunctionsServiceHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

public class SiftDTO {

    private final JsAuthenticationContext context;
    private final JsServletRequest request;
    private UniqueIDUserStoreManager uniqueIDUserStoreManager;
    private String type;
    private int tenantId;

    //User infomation
    private String userId;
    private String sessionIdForSift;
    private String internalUserId;
    private String userEmail;
    private String ip;
    private String socialLoginType;
    private String loginStatus;
    private String failureReason;
    private String accountType; //check availability and if required
    private String brandName; //what and why
    private String siteCountry; //what and why
    private String siteDomain;
    private String eventTime;

    //browser,os and device information
    private String userAgent;
    private String acceptLanguage;
    private String contentLanguage;
    private String os;
    private String osVersion;
    private String deviceManufacturer;
    private String deviceModel;
    private String deviceUniqueID; //iOS - IFV identifier, Android - Android ID
    private String appName;
    private String appVersion;
    private String clientLanguage;

    private static final Log LOG = LogFactory.getLog(SiftDTO.class);

    //other custom info (Whatever available)


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

    public String getSessionIdForSift() {

        return sessionIdForSift;
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

    public String getLoginStatus() {

        return loginStatus;
    }

    public String getEventTime() {

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

    public String getDeviceModel() {

        return deviceModel;
    }

    public String getDeviceUniqueID() {

        return deviceUniqueID;
    }

    public String getAppName() {

        return appName;
    }

    public String getAppVersion() {

        return appVersion;
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

            // TODO: 2023-07-06 session id to identify anonymous situation
            // TODO: 2023-07-06 Do we have an anonymous situation
//        this.sessionIdForSift =

            // TODO: 2023-06-30 Check if i can get the ip from the context
            this.ip = IdentityUtil.getClientIpAddress(request.getWrapped().getWrapped());

            // TODO: 2023-07-06 find how to get status
//            this.loginStatus = context.getContext().;

            try {
                uniqueIDUserStoreManager = getUniqueIdEnabledUserStoreManager(tenantId);
                this.userEmail = uniqueIDUserStoreManager.getUserClaimValueWithID(userId,
                        "http://wso2.org/claims/emailaddress", null);
            } catch (UserStoreException e) {
                LOG.error("Unable to get user email");
            }

            // TODO: 2023-07-06 Can we create a timestamp - that is what was done for lastLoginTime in  AUTHENTICATION SUCCESS event handler
//        this.eventTime = ((HashMap.Node) ((HashMap)((HashMap.Node)((HashMap)context.parameters).entrySet().toArray()[12]).getValue()).entrySet().toArray()[3]).value;

            // TODO: 2023-07-06  organise user agent
            this.userAgent = request.getWrapped().getWrapped().getHeader("User-Agent");
            this.acceptLanguage = request.getWrapped().getWrapped().getHeader("Accept-Language");

            // TODO: 2023-07-05 No content language header in the request
//            this.contentLanguage = request.getWrapped().getWrapped().getHeader("Content-Language");

            // TODO: 2023-07-05 os is contained in the user agent
            this.os = request.getWrapped().getWrapped().getHeader("User-Agent");
            this.osVersion = request.getWrapped().getWrapped().getHeader("User-Agent");
            this.deviceManufacturer = request.getWrapped().getWrapped().getHeader("User-Agent");
            this.deviceModel = request.getWrapped().getWrapped().getHeader("User-Agent");
            // TODO: 2023-07-06 find the device uniqueid
//            this.deviceUniqueID = request.getWrapped().getWrapped().getHeader("User-Agent");

            // TODO: 2023-07-06 find existing place
            this.appName = request.getWrapped().getWrapped().getHeader("User-Agent");
            this.appVersion = request.getWrapped().getWrapped().getHeader("User-Agent");
            this.clientLanguage = request.getWrapped().getWrapped().getHeader("User-Agent");
        }else {
            LOG.error("Subject is null");
        }

    }

    private UniqueIDUserStoreManager getUniqueIdEnabledUserStoreManager(int tenantId) throws UserStoreException {

        RealmService realmService = SiftAuthFunctionsServiceHolder.getInstance().getRealmService();
        UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        if (!(userStoreManager instanceof UniqueIDUserStoreManager)) {
            LOG.error("Error while getting user store.");
        }
        return (UniqueIDUserStoreManager) userStoreManager;
    }
}
