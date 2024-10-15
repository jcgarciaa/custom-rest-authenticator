package sample.authenticator.rest.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import sample.authenticator.rest.CustomRestAuthenticator;

@Component(
    name = "custom.rest.authenticator",
    immediate = true
)
public class CustomRestAuthenticatorServiceComponent {
    private static final Log log = LogFactory.getLog(CustomRestAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            CustomRestAuthenticator customAuthenticator = new CustomRestAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), customAuthenticator, null);
            log.info("Custom Rest Authenticator bundle is activated");
        } catch (Throwable e) {
            log.fatal(" Error while activating custom federated authenticator ", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Custom Rest Authenticator bundle is deactivated");
        }
    }

}
