/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

/**
 * Mobile Security Configuration for OpenIDConnect1.0
 *
 */

public class OMOICMobileSecurityConfiguration extends OMOAuthMobileSecurityConfiguration {

    private static final String TAG = OMOICMobileSecurityConfiguration.class.getSimpleName();
    public static final String WELL_KNOWN_CONFIGURATION = "./well-known/idcs-configuration";
    private static final String OPEN_ID_CONFIGURATION = "openid-configuration";
    private static final String ISSUER = "issuer";
    private static final String AUTHORIZATION_ENDPOINT = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT = "token_endpoint";
    private static final String USER_INFO_ENDPOINT = "userinfo_endpoint";
    private static final String REVOCATION_ENDPOINT = "revocation_endpoint";
    private static final String INTROSPECT_ENDPOINT = "introspect_endpoint";
    private static final String END_SESSION_ENDPOINT = "end_session_endpoint";
    private static final String REGISTRATION_ENDPOINT = "registration_endpoint";
    private static final String JWKS_URI = "jwks_uri";
    private static final String SCOPES_SUPPORTED = "scopes_supported";
    private static final String RESPONSE_TYPES_SUPPORTED = "response_types_supported";
    private static final String SUBJECT_TYPES_SUPPORTED = "subject_types_supported";
    private static final String ID_TOKEN_SIGNING_ALG_SUPPORTED = "id_token_signing_alg_values_supported";
    private static final String CLAIMS_SUPPORTED = "claims_supported";
    private static final String GRANT_TYPES_SUPPORTED = "grant_types_supported";
    private static final String TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = "token_endpoint_auth_methods_supported";
    private static final String TOKEN_ENDPOINT_AUTH_SIGNING_ALG_SUPPORTED = "token_endpoint_auth_signing_alg_values_supported";
    private static final String USER_INFO_SIGNING_ALG_SUPPORTED = "userinfo_signing_alg_values_supported";
    private static final String UI_LOCALES_SUPPORTED = "ui_locales_supported";
    private static final String CLAIMS_PARAMETER_SUPPORTED = "claims_parameter_supported";
    private static final String HTTP_LOGOUT_SUPPORTED = "http_logout_supported";
    private static final String LOGOUT_SESSION_SUPPORTED = "logout_session_supported";
    private static final String REQUEST_PARAMETER_SUPPORTED = "request_parameter_supported";
    private static final String REQUEST_URI_PARAMETER_SUPPORTED = "request_uri_parameter_supported";
    private static final String REQUIRE_REQUEST_URI_REGISTRATION = "require_request_uri_registration";

    private URL mConfigURL;
    private JSONObject mConfigJSON;

    //payload
    private String mIssuer;

    private URL mUserInfoEndpoint;
    private URL mIntrospectEndpoint;
    private URL mEndSessionEndpoint;
    private URL mRevocationEndpoint;
    private URL mSigningCertEndpoint;
    private URL mRegisterEndpoint;

    private Set<String> mSupportedScopes;
    private Set<String> mSupportedClaims;
    private Set<String> mSupportedGranTypes;
    private Set<String> mSupportedSingingAlgs;
    private Set<String> mSupportedSubjectTypes;
    private Set<String> mSupportedResponseTypes;

    private boolean isHttpLogoutSupported;
    private boolean isClaimsParamSupported;
    private boolean isRequestParamSupported;
    private boolean isLogoutSessionSupported;
    private boolean isRequestUriParamSupported;
    private boolean isRequireRequestUriRegistration;


    OMOICMobileSecurityConfiguration(Map<String, Object> configProperties) throws OMMobileSecurityException {
        super(configProperties, true);

        boolean additionalInfoRequired = false;
        authenticationScheme = OMAuthenticationScheme.OPENIDCONNECT10;
        Object configURLObj = configProperties.get(OMMobileSecurityService.OM_PROP_OPENID_CONNECT_CONFIGURATION_URL);
        if (configURLObj instanceof String) {
            try {
                mConfigURL = new URL((String) configURLObj);
                additionalInfoRequired = true;
                authenticationUrl = mConfigURL;
            } catch (MalformedURLException e) {
                throw new OMMobileSecurityException(OMErrorCode.OPENID_CONFIGURATION_FAILED, e);
            }
        } else if (configURLObj instanceof URL) {
            mConfigURL = (URL) configURLObj;
            authenticationUrl = mConfigURL;
        }

        Object configJSON = configProperties.get(OMMobileSecurityService.OM_PROP_OPENID_CONNECT_CONFIGURATION);
        if (configJSON instanceof String) {
            try {
                mConfigJSON = new JSONObject((String) configJSON);
                additionalInfoRequired = true;
            } catch (JSONException e) {
                throw new OMMobileSecurityException(OMErrorCode.OPENID_CONFIGURATION_FAILED, e);
            }
        } else if (configJSON instanceof JSONObject) {
            mConfigJSON = (JSONObject) configJSON;
        } else {
            //check if we have a configuration or not
            if (mConfigURL == null) {
                //if neither config URL nor config JSON provided lets check for the endpoint
                try {
                    initOAuthConfig(configProperties);
                } catch (MalformedURLException e) {
                    throw new OMMobileSecurityException(OMErrorCode.OPENID_CONFIGURATION_FAILED, "Provide either the configuration/configuration URL/OpenID Endpoints");
                }
            }
        }
    }

    private void populateDetails(JSONObject json) throws JSONException, OMMobileSecurityException, MalformedURLException {
        OMLog.debug(TAG, "populateDetails");
        JSONObject openIDConfigJSON = json.optJSONObject(OPEN_ID_CONFIGURATION);
        if (openIDConfigJSON != null) {
            mIssuer = openIDConfigJSON.optString(ISSUER);
            mOAuthAuthorizationEndpoint = new URL(openIDConfigJSON.optString(AUTHORIZATION_ENDPOINT));
            authenticationUrl = mOAuthAuthorizationEndpoint;
            mOAuthTokenEndpoint = new URL(openIDConfigJSON.optString(TOKEN_ENDPOINT));
            mUserInfoEndpoint = new URL(openIDConfigJSON.optString(USER_INFO_ENDPOINT));
            mRevocationEndpoint = new URL(openIDConfigJSON.optString(REVOCATION_ENDPOINT));
            mIntrospectEndpoint = new URL(openIDConfigJSON.optString(INTROSPECT_ENDPOINT));
            mEndSessionEndpoint = new URL((openIDConfigJSON.optString(END_SESSION_ENDPOINT)));
            logoutUrl = mEndSessionEndpoint;
            mSigningCertEndpoint = new URL(openIDConfigJSON.optString(JWKS_URI));
            JSONArray scopesJSONArray = openIDConfigJSON.optJSONArray(SCOPES_SUPPORTED);
            mSupportedScopes = jsonArrayToSet(scopesJSONArray);
            JSONArray responseTypesJSONArray = openIDConfigJSON.optJSONArray(RESPONSE_TYPES_SUPPORTED);
            mSupportedResponseTypes = jsonArrayToSet(responseTypesJSONArray);
            JSONArray subjectTypeJSONArray = openIDConfigJSON.optJSONArray(SUBJECT_TYPES_SUPPORTED);
            mSupportedSubjectTypes = jsonArrayToSet(subjectTypeJSONArray);
            JSONArray idTokenSigningJSONArray = openIDConfigJSON.optJSONArray(ID_TOKEN_SIGNING_ALG_SUPPORTED);
            mSupportedSingingAlgs = jsonArrayToSet(idTokenSigningJSONArray);
            JSONArray claimsJSONArray = openIDConfigJSON.optJSONArray(CLAIMS_SUPPORTED);
            mSupportedClaims = jsonArrayToSet(claimsJSONArray);
            JSONArray grantsJSONArray = openIDConfigJSON.optJSONArray(GRANT_TYPES_SUPPORTED);
            mSupportedGranTypes = jsonArrayToSet(grantsJSONArray);
            isClaimsParamSupported = openIDConfigJSON.optBoolean(CLAIMS_PARAMETER_SUPPORTED);
            isHttpLogoutSupported = openIDConfigJSON.optBoolean(HTTP_LOGOUT_SUPPORTED);
            isLogoutSessionSupported = openIDConfigJSON.optBoolean(LOGOUT_SESSION_SUPPORTED);
            isRequestParamSupported = openIDConfigJSON.optBoolean(REQUEST_PARAMETER_SUPPORTED);
            isRequestUriParamSupported = openIDConfigJSON.optBoolean(REQUEST_URI_PARAMETER_SUPPORTED);
            mClientRegistrationEndpoint = openIDConfigJSON.optString(REGISTRATION_ENDPOINT);
            isInitialized = true;
        } else
            throw new OMMobileSecurityException(OMErrorCode.OPENID_CONFIGURATION_FAILED, "PAYLOAD_DATA_NOT_CORRECT");

    }

    private Set<String> jsonArrayToSet(JSONArray array) throws JSONException {
        if (array != null) {
            Set<String> set = new HashSet<String>();
            for (int i = 0; i < array.length(); i++) {
                set.add(array.getString(i));
            }
            return set;
        }
        return null;
    }

    @Override
    public void initialize(Context context, OMConnectionHandler handler) throws OMMobileSecurityException {
        OMLog.debug(TAG, "initialize");
        try {
            if (mConfigURL != null) {
                String discoveryURL = mConfigURL.toString();
                OMLog.debug(TAG, "Downloading openID well known configuration from URL: " + discoveryURL);
                OMHTTPResponse response = handler.httpGet(new URL(discoveryURL), null);
                if (response != null && (response.getResponseCode() / 100 == 2)) {
                    populateDetails(new JSONObject(response.getResponseStringOnSuccess()));
                } else {
                    throw new OMMobileSecurityException(OMErrorCode.OPENID_FETCH_CONFIGURATION_FAILED);
                }
                try {
                    this.logoutSuccessUrl = new URL(getOAuthRedirectEndpoint());
                } catch (MalformedURLException e) {
                    OMLog.debug(TAG, e.getMessage());
                    try {
                        this.logoutSuccessUri = new URI(getOAuthRedirectEndpoint());
                    } catch (URISyntaxException e1) {
                        OMLog.error(TAG, e.getMessage(), e);
                    }
                }
            }
        } catch (MalformedURLException | JSONException e) {
            throw new OMMobileSecurityException(OMErrorCode.OPENID_FETCH_CONFIGURATION_FAILED, e);
        }
    }

    public URL getConfigURL() {
        return mConfigURL;
    }

    public String getIssuer() {
        return mIssuer;
    }

    public URL getTokenEndpoint() {
        return mOAuthTokenEndpoint;
    }

    public URL getUserInfoEndpoint() {
        return mUserInfoEndpoint;
    }

    public URL getIntrospectEndpoint() {
        return mIntrospectEndpoint;
    }

    public URL getEndSessionEndpoint() {
        return mEndSessionEndpoint;
    }

    public URL getRevocationEndpoint() {
        return mRevocationEndpoint;
    }

    public URL getSigningCertEndpoint() {
        return mSigningCertEndpoint;
    }

    public URL getAuthorizationEndpoint() {
        return mOAuthAuthorizationEndpoint;
    }

    public Set<String> getSupportedScopes() {
        return mSupportedScopes;
    }

    public Set<String> getSupportedClaims() {
        return mSupportedClaims;
    }

    public Set<String> getSupportedGrantTypes() {
        return mSupportedGranTypes;
    }

    public Set<String> getSupportedSigningAlgs() {
        return mSupportedSingingAlgs;
    }

    public Set<String> getSupportedSubjectTypes() {
        return mSupportedSubjectTypes;
    }

    public Set<String> getSupportedResponseTypes() {
        return mSupportedResponseTypes;
    }

    public boolean isHttpLogoutSupported() {
        return isHttpLogoutSupported;
    }

    public boolean isClaimsParamSupported() {
        return isClaimsParamSupported;
    }

    public boolean isRequestParamSupported() {
        return isRequestParamSupported;
    }

    public boolean isLogoutSessionSupported() {
        return isLogoutSessionSupported;
    }

    public boolean isRequestUriParamSupported() {
        return isRequestUriParamSupported;
    }

    public boolean isRequireRequestUriRegistration() {
        return isRequireRequestUriRegistration;
    }

}
