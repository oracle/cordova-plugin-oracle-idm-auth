/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OAuthConnectionsUtil;
import oracle.idm.mobile.auth.OAuthMSToken;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.logging.OMLog;

/**
 * OMOAuthMobileSecurityConfiguration class contains the extra configuration
 * that is specific to OAuth2.0 authentication scenario. An instance of this
 * class can be created to initialize OMMobileSecurityService object using
 * OMMobileSecurityConfiguration
 */
public class OMOAuthMobileSecurityConfiguration extends
        OMMobileSecurityConfiguration {
    private static final String TAG = OMOAuthMobileSecurityConfiguration.class
            .getName();
    protected URL mOAuthTokenEndpoint;
    protected URL mOAuthAuthorizationEndpoint;
    protected String mOAuthClientID;
    protected String mOAuthRedirectEndpoint;
    // by default keeping the browser mode to be external if not specified .
    protected BrowserMode mOAuthBrowserMode = BrowserMode.EXTERNAL;
    protected Set<String> mOAuthScopes;
    protected OAuthAuthorizationGrantType mOAuthzGrantType;
    protected String mOAuthClientSecret;
    protected boolean mIncludeClientAuthHeader;
    protected OAuthMSToken mClientAssertionToken;
    protected boolean mEnablePKCE;
    private boolean isClientRegistrationRequired;
    private String mLoginHint = "defaultUser";
    protected String mClientRegistrationEndpoint;


    @SuppressWarnings("unchecked")
    OMOAuthMobileSecurityConfiguration(Map<String, Object> configProperties, boolean additionalInitRequired) throws OMMobileSecurityException {
        super(configProperties);
        try {
            this.applicationProfile = new OMApplicationProfile(applicationId,
                    null);
            this.authenticationScheme = OMAuthenticationScheme.OAUTH20;
            Object oAuthZGrantObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE);
            if (oAuthZGrantObj instanceof OAuthAuthorizationGrantType) {
                this.mOAuthzGrantType = (OAuthAuthorizationGrantType) oAuthZGrantObj;
            } else if (oAuthZGrantObj instanceof String) {
                this.mOAuthzGrantType = OAuthAuthorizationGrantType.valueOfGrantType((String) oAuthZGrantObj);
            } else {
                throw new IllegalArgumentException(
                        "Authorization grant type can not be null");
            }

            Object redirectEndpointObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_REDIRECT_ENDPOINT);

            if (redirectEndpointObj instanceof String) {
                this.mOAuthRedirectEndpoint = (String) redirectEndpointObj;
            } else {
                // for resource owner grant and other 2-legged flows we grant
                // type we don't need redirect end
                // point. However, we need this for other implicit and
                // authorization_code.

                if ((mOAuthzGrantType == OAuthAuthorizationGrantType.IMPLICIT || mOAuthzGrantType == OAuthAuthorizationGrantType.AUTHORIZATION_CODE))
                    throw new IllegalArgumentException(
                            "OAuth Redirect end point can not be null");
            }
            Object browserMode = configProperties
                    .get(OMMobileSecurityService.OM_PROP_BROWSER_MODE);
            if (browserMode instanceof BrowserMode) {
                this.mOAuthBrowserMode = (BrowserMode) browserMode;
            } else if (browserMode instanceof String) {
                this.mOAuthBrowserMode = BrowserMode.valueOfBrowserMode((String) browserMode);
            }
            String clientAssertionValue = (String) configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_CLIENT_ASSERTION_JWT);
            if (TextUtils.isEmpty(clientAssertionValue)) {
                clientAssertionValue = (String) configProperties
                        .get(OMMobileSecurityService.OM_PROP_OAUTH_CLIENT_ASSERTION_SAML2);
                if (!TextUtils.isEmpty(clientAssertionValue)) {
                    mClientAssertionToken = new OAuthMSToken(
                            OMSecurityConstants.OM_OAUTH_CLIENT_ASSERTION_TOKEN,
                            clientAssertionValue);
                    mClientAssertionToken
                            .setClientAssertionType(OAuthConnectionsUtil.OAUTH_TOKEN_TYPE_SAML2_CLIENT_ASSERTION);
                }
            } else {
                mClientAssertionToken = new OAuthMSToken(
                        OMSecurityConstants.OM_OAUTH_CLIENT_ASSERTION_TOKEN,
                        clientAssertionValue);
                mClientAssertionToken
                        .setClientAssertionType(OAuthConnectionsUtil.OAUTH_TOKEN_TYPE_JWT_CLIENT_ASSERTION);
            }
            Object clientIDObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_CLIENT_ID);
            if (clientIDObj instanceof String) {
                this.mOAuthClientID = (String) clientIDObj;
            } else {
                throw new IllegalArgumentException(
                        "OAuth Client ID can not be null");
            }

            Object scopeObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_SCOPE);
            if (scopeObj != null) {
                if (scopeObj instanceof Set<?>) {
                    this.mOAuthScopes = new HashSet<String>(
                            (Set<String>) scopeObj);
                    this.mOAuthScopes.remove(null);
                }
                // not making scopes mandatory as RFC 6749 does not mandates it.
                // however the user/app will get an error from the server, if
                // the server expects the scopes in the request.
            }
            Object clientSecretObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_CLIENT_SECRET);
            if (clientSecretObj != null && (clientSecretObj instanceof String)) {
                this.mOAuthClientSecret = (String) clientSecretObj;
            }

            Object clientAuthHeaderReq = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_INCLUDE_CLIENT_AUTH_HEADER);

            if (clientAuthHeaderReq instanceof Boolean) {
                this.mIncludeClientAuthHeader = (Boolean) clientAuthHeaderReq;
            }

            // if provided, will be used in all the requests for OAuth.
            String identityName = (String) configProperties
                    .get(OMMobileSecurityService.OM_PROP_IDENTITY_DOMAIN_NAME);
            if (identityName != null && identityName.length() != 0) {
                this.identityDomain = identityName;
            }

            // If provided and we don't have any value for identity domain then
            // we update the UI to collect the same.
            Object collectIdentityDomainObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_COLLECT_IDENTITY_DOMAIN);

            if (collectIdentityDomainObj != null
                    && collectIdentityDomainObj instanceof Boolean) {
                this.collectIdentityDomain = (Boolean) collectIdentityDomainObj;
            }
            Object identityDomainHeaderNameObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_IDENTITY_DOMAIN_HEADER_NAME);

            if (identityDomainHeaderNameObj != null
                    && identityDomainHeaderNameObj instanceof String) {
                this.mIdentityDomainHeaderName = (String) identityDomainHeaderNameObj;
            }
            Object identityDomainInHeaderObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER);

            if (identityDomainInHeaderObj != null
                    && identityDomainInHeaderObj instanceof Boolean) {
                this.mIdentityDomainInHeader = (Boolean) identityDomainInHeaderObj;
            }

            //check if dynamic registration is required.
            Object requireDynamicRegObj = configProperties.get(OMMobileSecurityService.OM_PROP_IDCS_REGISTER_CLIENT);
            if (requireDynamicRegObj instanceof Boolean) {
                isClientRegistrationRequired = (Boolean) requireDynamicRegObj;
                OMLog.debug(TAG, "Require Dynamic Client Registration : " + isClientRegistrationRequired);
            }

            Object loginHintObj = configProperties.get(OMMobileSecurityService.OM_PROP_LOGIN_HINT);
            if (loginHintObj instanceof String) {
                String loginHint = (String) loginHintObj;
                if (!TextUtils.isEmpty(loginHint)) {
                    //set only when app gives us a non null or non empty value.
                    mLoginHint = loginHint;
                }
                OMLog.debug(TAG, "Login Hint provided : " + loginHint);
            }

            if (isClientRegistrationRequired) {
                Object registerEPObj = configProperties.get(OMMobileSecurityService.OM_PROP_IDCS_REGISTER_ENDPOINT);
                if (registerEPObj instanceof String) {
                    mClientRegistrationEndpoint = (String) registerEPObj;
                } else if (registerEPObj instanceof URL) {
                    mClientRegistrationEndpoint = ((URL) registerEPObj).toString();
                }
            }
            parseIdleTimeout(configProperties);
            parseForCustomAuthHeaders(configProperties);
            parseAuthzHeaderInLogout(configProperties);
            if (mOAuthzGrantType == OAuthAuthorizationGrantType.RESOURCE_OWNER) {
                parseOfflinePreferences(configProperties);
                parseRememberCredentials(configProperties, FLAG_ENABLE_REMEMBER_USERNAME);
            }
            if (mOAuthzGrantType == OAuthAuthorizationGrantType.AUTHORIZATION_CODE) {
                Object pkcePrefObj = configProperties.get(OMMobileSecurityService.OM_PROP_OAUTH_ENABLE_PKCE);
                if (pkcePrefObj instanceof Boolean) {
                    mEnablePKCE = (Boolean) pkcePrefObj;
                }
                OMLog.debug(TAG, "Grant type = Authorization_code. PKCE Enabled = " + mEnablePKCE);
            }
            if (!additionalInitRequired) {
                OMLog.info(TAG, "Additional Initialization not required");
                initOAuthConfig(configProperties);
                isInitialized = true;
            } else {
                OMLog.info(TAG, "Additional Initialization required");
                //Opend ID Use case.
            }
        } catch (Exception e) {
            throw new IllegalArgumentException(e);//TODO change this
        }
    }

    /* package */ void initOAuthConfig(Map<String, Object> configProperties) throws MalformedURLException {
        {
            OMLog.info(TAG, "Additional Initialization not required");
            Object tokenEndpointObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_TOKEN_ENDPOINT);

            if (tokenEndpointObj instanceof URL) {
                this.mOAuthTokenEndpoint = (URL) tokenEndpointObj;
            } else if (tokenEndpointObj instanceof String) {
                this.mOAuthTokenEndpoint = new URL((String) tokenEndpointObj);
            } else {
                // only implicit grant type does not require token endpoint.
                if (mOAuthzGrantType != OAuthAuthorizationGrantType.IMPLICIT) {
                    throw new IllegalArgumentException(
                            "Token end point can not be null in the "
                                    + mOAuthzGrantType.name() + " grant type.");
                }
            }

            Object authZEndpointObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_OAUTH_AUTHORIZATION_ENDPOINT);

            if (authZEndpointObj instanceof URL) {
                this.mOAuthAuthorizationEndpoint = (URL) authZEndpointObj;
            } else if (authZEndpointObj instanceof String) {
                this.mOAuthAuthorizationEndpoint = new URL(
                        (String) authZEndpointObj);
            } else {
                // resource owner grant type does not need the authorization end
                // point so lets not make it mandatory in this case.
                // However it is mandatory for both implicit and
                // authorization_code grant types.
                if ((mOAuthzGrantType == OAuthAuthorizationGrantType.AUTHORIZATION_CODE || mOAuthzGrantType == OAuthAuthorizationGrantType.IMPLICIT))
                    throw new IllegalArgumentException(
                            "Authorization End point can not be null for the "
                                    + mOAuthzGrantType.name() + " grant type.");
            }
            if (mOAuthzGrantType == OAuthAuthorizationGrantType.AUTHORIZATION_CODE
                    || mOAuthzGrantType == OAuthAuthorizationGrantType.IMPLICIT) {
                authenticationUrl = mOAuthAuthorizationEndpoint;
            } else {
                authenticationUrl = mOAuthTokenEndpoint;
            }

            // check if logout url is provided.
            Object logoutUrlObj = configProperties
                    .get(OMMobileSecurityService.OM_PROP_LOGOUT_URL);
            if (logoutUrlObj != null) {
                if (logoutUrlObj instanceof URL) {
                    this.logoutUrl = (URL) logoutUrlObj;
                } else if (logoutUrlObj instanceof String) {
                    this.logoutUrl = new URL((String) logoutUrlObj);
                } else {
                    throw new IllegalArgumentException("Invalid logout URL");
                }
            }
            isInitialized = true;
        }
    }

    @Override
    public void initialize(Context context, OMConnectionHandler handler
    ) throws OMMobileSecurityException {
        // taken care during initialization of the configuration object.

    }

    public boolean isPKCEEnabled() {
        return mEnablePKCE;
    }

    public URL getOAuthTokenEndpoint() {
        return mOAuthTokenEndpoint;
    }

    public URL getOAuthAuthorizationEndpoint() {
        return mOAuthAuthorizationEndpoint;
    }

    public String getOAuthClientID() {
        return mOAuthClientID;
    }

    public String getOAuthRedirectEndpoint() {
        return mOAuthRedirectEndpoint;
    }

    public String getClientRegistrationEndpoint() {
        return mClientRegistrationEndpoint;
    }

    public BrowserMode getOAuthBrowserMode() {
        return mOAuthBrowserMode;
    }

    public Set<String> getOAuthScopes() {
        return mOAuthScopes;
    }

    public OAuthAuthorizationGrantType getOAuthzGrantType() {
        return mOAuthzGrantType;
    }

    public String getOAuthClientSecret() {
        return mOAuthClientSecret;
    }

    public boolean includeClientAuthHeader() {
        return mIncludeClientAuthHeader;
    }

    public boolean isConfidentialClient() {
        if (!TextUtils.isEmpty(mOAuthClientSecret)) {
            Log.d(TAG, "Confidential Client!");
            return true;
        }
        return false;
    }

    public OAuthMSToken getOAuthClientAssertion() {
        return mClientAssertionToken;
    }

    public boolean isClientRegistrationRequired() {
        return isClientRegistrationRequired;
    }

    public String getLoginHint() {
        return mLoginHint;
    }
}
