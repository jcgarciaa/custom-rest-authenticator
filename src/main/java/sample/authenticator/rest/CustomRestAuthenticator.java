package sample.authenticator.rest;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CustomRestAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String userName = request.getParameter(CustomRestAuthenticatorConstants.USERNAME);
        String password = request.getParameter(CustomRestAuthenticatorConstants.PASSWORD);
        return userName != null && password != null;
    }

    @Override
    public String getFriendlyName() {
        return "custom-rest-authenticator";
    }

    @Override
    public String getName() {
        return "CustomRestAuthenticator";
    }

    @Override
    public List<Property> getConfigurationProperties() {
        // Get the required configuration properties.
        List<Property> configProperties = new ArrayList<>();

        Property clientId = new Property();
        clientId.setName(CustomRestAuthenticatorConstants.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter OAuth2/OpenID Connect client identifier value");
        clientId.setType("string");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(CustomRestAuthenticatorConstants.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("Enter OAuth2/OpenID Connect client secret value");
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(2);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property tokenEpUrl = new Property();
        tokenEpUrl.setName(CustomRestAuthenticatorConstants.OAUTH2_TOKEN_URL);
        tokenEpUrl.setDisplayName("Token Endpoint URL");
        tokenEpUrl.setRequired(true);
        tokenEpUrl.setDescription("Enter token API URL value");
        tokenEpUrl.setType("string");
        tokenEpUrl.setDisplayOrder(3);
        configProperties.add(tokenEpUrl);

        Property authnEpUrl = new Property();
        authnEpUrl.setName(CustomRestAuthenticatorConstants.OAUTH2_AUTHN_URL);
        authnEpUrl.setDisplayName("Authentication Endpoint URL");
        authnEpUrl.setRequired(true);
        authnEpUrl.setDescription("Enter authentication API URL value");
        authnEpUrl.setType("string");
        authnEpUrl.setDisplayOrder(4);
        configProperties.add(authnEpUrl);

        return configProperties;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        // This is the default WSO2 IS login page. If you can create your custom login page you can use that instead.
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier());

        try {
            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) + "&authenticators=FIDP:LOCAL" + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        if (authenticatorProperties == null) {
            throw new AuthenticationFailedException("Error while retrieving properties. Authenticator Properties cannot be null");
        }

        String clientId = authenticatorProperties.get(CustomRestAuthenticatorConstants.CLIENT_ID);
        String clientSecret = authenticatorProperties.get(CustomRestAuthenticatorConstants.CLIENT_SECRET);
        String tokenEndpoint = authenticatorProperties.get(CustomRestAuthenticatorConstants.OAUTH2_TOKEN_URL);
        String authnEndpoint = authenticatorProperties.get(CustomRestAuthenticatorConstants.OAUTH2_AUTHN_URL);

        String token = getToken(tokenEndpoint, clientId, clientSecret);
        String username = request.getParameter(CustomRestAuthenticatorConstants.USERNAME);
        String password = request.getParameter(CustomRestAuthenticatorConstants.PASSWORD);

        // removing tenant domain from username
        if (username.contains("@")) {
            username = username.substring(0, username.indexOf("@"));
        }

        authenticateUser(authnEndpoint, token, username, password);
        AuthenticatedUser authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(username);
        context.setSubject(authenticatedUser);
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        String state = request.getParameter(CustomRestAuthenticatorConstants.OAUTH2_PARAM_STATE);

        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    private String getToken(String tokenEndpoint, String clientId, String clientSecret) throws AuthenticationFailedException {
        PostMethod postMethod = new PostMethod(tokenEndpoint);
        postMethod.addParameter("client_id", clientId);
        postMethod.addParameter("client_secret", clientSecret);

        try {
            HttpClient httpClient = new HttpClient();
            int responseStatus = httpClient.executeMethod(postMethod);
            if (responseStatus != 200) {
                throw new AuthenticationFailedException("Authentication Failed");
            }

            String response = postMethod.getResponseBodyAsString();
            JSONObject obj = new JSONObject(response);
            return obj.getString(CustomRestAuthenticatorConstants.ACCESS_TOKEN);
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed", e);
        }
    }

    private void authenticateUser(String authnEndpoint, String token, String username, String password) throws AuthenticationFailedException {
        PostMethod postMethod = new PostMethod(authnEndpoint);
        postMethod.addRequestHeader(CustomRestAuthenticatorConstants.AUTHORIZATION_HEADER, "Bearer " + token);
        postMethod.addParameter("msisdn", username);
        postMethod.addParameter("password", password);

        try {
            HttpClient httpClient = new HttpClient();
            int responseStatus = httpClient.executeMethod(postMethod);
            if (responseStatus != 200) {
                throw new AuthenticationFailedException("Authentication Failed. Invalid credentials");
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException("Authentication Failed", e);
        }
    }

}
