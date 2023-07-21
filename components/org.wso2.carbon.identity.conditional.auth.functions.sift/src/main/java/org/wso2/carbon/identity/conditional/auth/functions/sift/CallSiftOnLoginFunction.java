package org.wso2.carbon.identity.conditional.auth.functions.sift;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.utils.ServerException;

/**
 * Interface for the Sift login authentication functions.
 */
@FunctionalInterface
public interface CallSiftOnLoginFunction {

    double getSiftRiskScoreForLogin(JsAuthenticationContext context, JsServletRequest request, String loginStatus, String predictionType) throws
            UserIdNotFoundException, ServerException;

}
