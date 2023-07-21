package org.wso2.carbon.identity.conditional.auth.functions.sift;

import com.siftscience.EventRequest;
import com.siftscience.EventResponse;
import com.siftscience.SiftClient;
import com.siftscience.exception.SiftException;
import com.siftscience.model.App;
import com.siftscience.model.Browser;
import com.siftscience.model.LoginFieldSet;
import java.io.IOException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.conditional.auth.functions.sift.util.SiftDTO;

/**
 * Implementation of the {@link CallSiftOnLoginFunction}
 */
public class CallSiftOnLoginFunctionImpl implements CallSiftOnLoginFunction {

    private static final Log LOG = LogFactory.getLog(CallSiftOnLoginFunctionImpl.class);
    double riskScore = 0.0;
    SiftClient client;
    SiftDTO siftDTO;
    EventResponse response = null;

    @Override
    public double getSiftRiskScoreForLogin(JsAuthenticationContext context, JsServletRequest request,
                                           String loginStatus, String predictionType, String siftApiKey,
                                           String siftAccountID) {

        client = new SiftClient(siftApiKey, siftAccountID);
        EventRequest loginRequest = client.buildRequest(getLoginFieldSetObject(context, request, loginStatus));

        try {
            // TODO: 2023-07-13 should we check all the types of responses (error codes)
            response = loginRequest.withScores(predictionType).send();
            riskScore = response.getAbuseScore(predictionType).getScore();
            LOG.info("Sift score for user: " + siftDTO.getUserId() + " is: " + riskScore);
        } catch (SiftException e) {
            LOG.error("Sift error response: " + e.getSiftResponse());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return (riskScore);
    }

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
//                .setApp(new App()
//                        .setAppName(siftDTO.getAppName())
//                        .setDeviceManufacturer(siftDTO.getDeviceManufacturer())
//                        .setOperatingSystem(siftDTO.getOs())
//                        .setOperatingSystemVersion(siftDTO.getOsVersion())
//                )
                // Custom fields.
                .setCustomField("browser_name", siftDTO.getCustomBrowserName())
                .setCustomField("browser_version", siftDTO.getCustomBrowserVersion())

                // TODO: 2023-08-03 remove the custom fields for the below attributes and add them to app object.
                .setCustomField("app_name", siftDTO.getAppName())
                .setCustomField("device_manufacturer", siftDTO.getDeviceManufacturer())
                .setCustomField("os", siftDTO.getOs())
                .setCustomField("os_version", siftDTO.getOsVersion());
    }
}
