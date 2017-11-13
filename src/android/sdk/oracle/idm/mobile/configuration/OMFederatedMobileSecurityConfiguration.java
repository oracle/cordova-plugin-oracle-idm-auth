/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

import android.content.Context;

import java.net.URL;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.GenericsUtils;

import static oracle.idm.mobile.OMMobileSecurityService.OM_PROP_USERNAME_PARAM_NAME;

/**
 * OMFederatedMobileSecurityConfiguration class contains the extra configuration
 * that is specific to federated authentication scenario. An instance of this
 * class can be created to initialize OMMobileSecurityService object using
 * {@link OMMobileSecurityService#OMMobileSecurityService(Context, Map, OMMobileSecurityServiceCallback)}}
 * .
 * */
public class OMFederatedMobileSecurityConfiguration extends
        OMMobileSecurityConfiguration
{
    private static final String TAG = OMFederatedMobileSecurityConfiguration.class.getSimpleName();

    private BrowserMode browserMode = BrowserMode.EMBEDDED;
    private URL loginSuccessUrl;
    private URL loginFailureUrl;
    private int loginTimeOut = 120;// In seconds
    private Set<String> usernameParamNames;
    private String userAgentHeaderString;
    private boolean parseTokenRelayResponse;

    public OMFederatedMobileSecurityConfiguration(Map<String, Object> configProperties) throws OMMobileSecurityException {
        super(configProperties);
        try
        {
            this.authenticationScheme = OMAuthenticationScheme.FEDERATED;

            parseLoginURL(configProperties);
            parseLogoutURL(configProperties);
            parseRequiredTokens(configProperties);

            Object browserMode = configProperties
                    .get(OMMobileSecurityService.OM_PROP_BROWSER_MODE);
            if (browserMode instanceof BrowserMode) {
                this.browserMode = (BrowserMode) browserMode;
            } else if (browserMode instanceof String) {
                this.browserMode = BrowserMode.valueOfBrowserMode((String) browserMode);
            }
            if (this.browserMode == BrowserMode.EXTERNAL) {
                throw new IllegalArgumentException(
                        "Federated authentication using External Browser is not supported now.");
            }

            Object loginSuccessUrl = configProperties
                    .get(OMMobileSecurityService.OM_PROP_LOGIN_SUCCESS_URL);
            if (loginSuccessUrl instanceof URL)
            {
                this.loginSuccessUrl = (URL) loginSuccessUrl;
            }
            else if (loginSuccessUrl instanceof String)
            {
                this.loginSuccessUrl = new URL((String) loginSuccessUrl);
            }
            else
            {
                throw new IllegalArgumentException("Login Success url is invalid");
            }

            Object loginFailureUrl = configProperties
                    .get(OMMobileSecurityService.OM_PROP_LOGIN_FAILURE_URL);
            if (loginFailureUrl instanceof URL)
            {
                this.loginFailureUrl = (URL) loginFailureUrl;
            }
            else if (loginFailureUrl instanceof String)
            {
                this.loginFailureUrl = new URL((String) loginFailureUrl);
            }
            else
            {
                throw new IllegalArgumentException("Login Failure url is invalid");
            }

            Object loginTimeOutObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_LOGIN_TIMEOUT_VALUE);

            if (loginTimeOutObj != null && loginTimeOutObj instanceof Integer)
            {
                this.loginTimeOut = (Integer) loginTimeOutObj;
            }

            Object usernameParamNameObj = configProperties
                    .get(OM_PROP_USERNAME_PARAM_NAME);
            if (usernameParamNameObj != null
                    && usernameParamNameObj instanceof Set<?>)
            {
                this.usernameParamNames = GenericsUtils
                        .castToSet((Set<?>) usernameParamNameObj, String.class);
                checkElementsEmpty(usernameParamNames, OM_PROP_USERNAME_PARAM_NAME);
            }

            Object customUserAgentHeaderObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_CUSTOM_USER_AGENT_HEADER);
            if (customUserAgentHeaderObj != null
                    && customUserAgentHeaderObj instanceof String)
            {
                userAgentHeaderString = (String) customUserAgentHeaderObj;
            }

            Object parseTokenRelayResponseObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_PARSE_TOKEN_RELAY_RESPONSE);

            if (parseTokenRelayResponseObj != null
                    && parseTokenRelayResponseObj instanceof Boolean) {
                this.parseTokenRelayResponse = (Boolean) parseTokenRelayResponseObj;
            }

            parseIdleTimeout(configProperties);
            parseSessionTimeout(configProperties);
            isInitialized = true;
        } catch (Exception e) {
            OMLog.error(TAG, e.getMessage(), e);
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void initialize(Context context, OMConnectionHandler handler) throws OMMobileSecurityException {
        // Initialization is already taken care in the constructor
    }

    public BrowserMode getBrowserMode()
    {
        return browserMode;
    }

    public URL getLoginSuccessUrl()
    {
        return loginSuccessUrl;
    }

    public URL getLoginFailureUrl()
    {
        return loginFailureUrl;
    }

    public int getLoginTimeOut()
    {
        return loginTimeOut;
    }

    public Set<String> getUsernameParamNames()
    {
        return usernameParamNames;
    }

    public String getUserAgentHeaderString()
    {
        return userAgentHeaderString;
    }

    public boolean parseTokenRelayResponse() {
        return parseTokenRelayResponse;
    }

}
