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

package org.wso2.carbon.identity.conditional.auth.functions.sift;

import com.siftscience.EventRequest;
import com.siftscience.SiftClient;
import com.siftscience.exception.SiftException;
import com.siftscience.model.Browser;
import com.siftscience.model.LoginFieldSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.conditional.auth.functions.sift.util.SiftDTO;

/**
 * Implementation of the {@link EventPublishToSiftOnLoginFunction}.
 */
public class EventPublishToSiftOnLoginFunctionImpl implements EventPublishToSiftOnLoginFunction {

    private static final Log LOG = LogFactory.getLog(EventPublishToSiftOnLoginFunctionImpl.class);
    SiftClient client;
    SiftDTO siftDTO;

    @Override
    public void publishLoginEventInfo(JsAuthenticationContext context, JsServletRequest request, String loginStatus,
                                      String siftApiKey, String siftAccountID) {

        client = new SiftClient(siftApiKey, siftAccountID);
        EventRequest loginRequest = client.buildRequest(getLoginFieldSetObject(context, request, loginStatus));
        try {
            // TODO: 2023-07-13 should we check all the types of responses (error codes)
            loginRequest.send();
            LOG.info("Sift event published successfully");
        } catch (SiftException e) {
            LOG.error("Sift error response: " + e.getSiftResponse());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * This method is used to build the login field set object.
     *
     * @param context     Authentication context.
     * @param request     Login request.
     * @param loginStatus Login status.
     * @return LoginFieldSet object for sift.
     */
    private LoginFieldSet getLoginFieldSetObject(JsAuthenticationContext context, JsServletRequest request,
                                                 String loginStatus) {

        siftDTO = new SiftDTO(request, context);
        // Build the request object.
        return new LoginFieldSet()
                .setUserId(siftDTO.getUserId())
                .setUserEmail(siftDTO.getUserEmail())
                .setLoginStatus(loginStatus)
                .setIp(siftDTO.getIp())
                .setBrowser(new Browser()
                        .setUserAgent(siftDTO.getUserAgent())
                        .setAcceptLanguage(siftDTO.getAcceptLanguage())
                )
                .setTime(siftDTO.getEventTime())
                .setCustomField("browser_name", siftDTO.getCustomBrowserName())
                .setCustomField("browser_version", siftDTO.getCustomBrowserVersion())

                // TODO: 2023-08-03 remove the custom fields for the below attributes and add them to app object.
                .setCustomField("app_name", siftDTO.getAppName())
                .setCustomField("device_manufacturer", siftDTO.getDeviceManufacturer())
                .setCustomField("os", siftDTO.getOs())
                .setCustomField("os_version", siftDTO.getOsVersion());
    }
}
