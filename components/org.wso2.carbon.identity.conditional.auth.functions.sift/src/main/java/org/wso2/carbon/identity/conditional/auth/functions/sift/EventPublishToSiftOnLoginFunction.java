package org.wso2.carbon.identity.conditional.auth.functions.sift;

import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsAuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.js.JsServletRequest;

/**
 * Interface for the Sift login authentication functions.
 */
@FunctionalInterface
public interface EventPublishToSiftOnLoginFunction {

    void publishLoginEventInfo(JsAuthenticationContext context, JsServletRequest request, String loginStatus,
                               String siftApiKey, String siftAccountID);
}
