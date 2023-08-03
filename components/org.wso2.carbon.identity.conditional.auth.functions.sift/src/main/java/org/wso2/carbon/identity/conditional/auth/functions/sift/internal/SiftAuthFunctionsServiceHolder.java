package org.wso2.carbon.identity.conditional.auth.functions.sift.internal;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.identity.application.authentication.framework.JsFunctionRegistry;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Class to hold services discovered via OSGI on this component.
 */
public class SiftAuthFunctionsServiceHolder {

    private static final SiftAuthFunctionsServiceHolder instance = new SiftAuthFunctionsServiceHolder();

    private RealmService realmService;
    private RegistryService registryService;
    private JsFunctionRegistry jsFunctionRegistry;
    private ServerConfigurationService serverConfigurationService;

    private SiftAuthFunctionsServiceHolder() {

    }

    public static SiftAuthFunctionsServiceHolder getInstance() {

        return instance;
    }

    public ServerConfigurationService getServerConfigurationService() {

        return serverConfigurationService;
    }

    public void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public RegistryService getRegistryService() {

        return registryService;
    }

    public void setRegistryService(RegistryService registryService) {

        this.registryService = registryService;
    }

    public JsFunctionRegistry getJsFunctionRegistry() {

        return jsFunctionRegistry;
    }

    public void setJsFunctionRegistry(JsFunctionRegistry jsFunctionRegistry) {

        this.jsFunctionRegistry = jsFunctionRegistry;
    }
}
