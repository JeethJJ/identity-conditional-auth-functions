package org.wso2.carbon.identity.conditional.auth.functions.sift.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.identity.conditional.auth.functions.sift.CallSiftOnLoginFunction;
import org.wso2.carbon.identity.conditional.auth.functions.sift.CallSiftOnLoginFunctionImpl;
import org.wso2.carbon.identity.conditional.auth.functions.sift.EventPublishToSiftOnLoginFunction;
import org.wso2.carbon.identity.conditional.auth.functions.sift.EventPublishToSiftOnLoginFunctionImpl;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handle ELK related conditional auth functions.
 */
@Component(
        name = "identity.conditional.auth.functions.sift",
        immediate = true
)
public class SiftAuthFunctionsServiceComponent {

    public static final String FUNC_CALL_SIFT = "getSiftRiskScoreForLogin";
    public static final String FUNC_CALL_SIFT_EVENT_PUBLISH = "publishLoginEventInfo";
    private static final Log LOG = LogFactory.getLog(SiftAuthFunctionsServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            JsFunctionRegistry jsFunctionRegistry = SiftAuthFunctionsServiceHolder.getInstance()
                    .getJsFunctionRegistry();

            CallSiftOnLoginFunction getSiftRiskScoreForLogin = new CallSiftOnLoginFunctionImpl();
            EventPublishToSiftOnLoginFunction publishLoginEventInfo = new EventPublishToSiftOnLoginFunctionImpl();
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIFT,
                    getSiftRiskScoreForLogin);
            jsFunctionRegistry.register(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIFT_EVENT_PUBLISH,
                    publishLoginEventInfo);
        } catch (Throwable e) {
            LOG.error("Error while activating AnalyticsFunctionsServiceComponent.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        JsFunctionRegistry jsFunctionRegistry = SiftAuthFunctionsServiceHolder.getInstance()
                .getJsFunctionRegistry();
        if (jsFunctionRegistry != null) {
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIFT);
            jsFunctionRegistry.deRegister(JsFunctionRegistry.Subsystem.SEQUENCE_HANDLER, FUNC_CALL_SIFT_EVENT_PUBLISH);
        }
    }

    @Reference(
            service = JsFunctionRegistry.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetJsFunctionRegistry"
    )
    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        SiftAuthFunctionsServiceHolder.getInstance().setJsFunctionRegistry(jsFunctionRegistry);
    }

    public void unsetJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        SiftAuthFunctionsServiceHolder.getInstance().setJsFunctionRegistry(null);
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent
                                                                  identityCoreInitializedEvent) {

    /* Reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started. */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent
                                                                    identityCoreInitializedEvent) {

    /* Reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started. */
    }

    @Reference(
            name = "identity.governance.service",
            service = IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService"
    )
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Identity Governance service is set form functions.");
        }
        // Do nothing. Wait for the service before registering the governance connector.
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Identity Governance service is unset from functions.");
        }
        // Do nothing.
    }

    @Reference(
            name = "server.configuration.service",
            service = ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerConfigurationService"
    )
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Setting the serverConfigurationService.");
        }
        SiftAuthFunctionsServiceHolder.getInstance().setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Unsetting the ServerConfigurationService.");
        }
        SiftAuthFunctionsServiceHolder.getInstance().setServerConfigurationService(null);
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        SiftAuthFunctionsServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        SiftAuthFunctionsServiceHolder.getInstance().setRealmService(null);
    }
}
