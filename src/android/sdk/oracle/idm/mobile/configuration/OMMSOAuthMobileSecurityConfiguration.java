/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

import android.content.Context;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants.ConnectionConstants;
import oracle.idm.mobile.auth.IdentityContext;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.credentialstore.OMCredentialStore;

/**
 * This class is responsible representing the Mobile security configuration for
 * Mobile and Social OAuth flows.
 *
 */
public final class OMMSOAuthMobileSecurityConfiguration extends
        OMOAuthMobileSecurityConfiguration {
    private static final String TAG = OMMSOAuthMobileSecurityConfiguration.class
            .getName();

    private static final String APP_PROFILE_URI = "/appprofiles/";
    private static final String DEVICE_OS = "device_os";
    private static final String OS_VERSION = "os_ver";
    static final String AUTHORIZATION_SERVICE = "oauthAuthZService";
    static final String TOKEN_SERVICE = "oauthTokenService";
    static final String ALLOWED_GRANT_TYPES = "allowedGrantTypes";
    static final String SERVER_SIDE_SSO = "server_side_sso";
    private URL mClientProfileService;
    private List<String> mOAuthAllowedGrantTypes;
    private boolean mServerSideSSOEnabled;
    private URL serverUrl;


    OMMSOAuthMobileSecurityConfiguration(Map<String, Object> configProp) throws OMMobileSecurityException {
        super(configProp, true);
        Object clientProfileServiceObj = configProp
                .get(OMMobileSecurityService.OM_PROP_OAM_OAUTH_SERVICE_ENDPOINT);
        if (clientProfileServiceObj instanceof String) {
            try {
                mClientProfileService = new URL(
                        (String) clientProfileServiceObj);
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException(e);
            }
        } else if (clientProfileServiceObj instanceof URL) {
            mClientProfileService = (URL) clientProfileServiceObj;
        } else {
            throw new IllegalArgumentException(
                    "value of OM_PROP_OAM_OAUTH_SERVICE_ENDPOINT should be of type String or URL");
        }
        try {
            String protocol = mClientProfileService.getProtocol();
            String host = mClientProfileService.getHost();
            int port = mClientProfileService.getPort();
            StringBuilder urlBuilder = new StringBuilder();
            urlBuilder.append(protocol).append("://").append(host);
            if (port != -1) {
                urlBuilder.append(":").append(port);
            }

            serverUrl = new URL(urlBuilder.toString());
            authenticationUrl = mClientProfileService;
        } catch (MalformedURLException e) {
            Log.e(TAG, e.getLocalizedMessage(), e);
            throw new IllegalArgumentException(e);
        }
    }

    private String downloadClientServiceProfile(Context context, OMCredentialStore credStore)
            throws IOException, OMMobileSecurityException {
        String serviceProfileEndpoint = getServiceProfileUrl();
        OMHTTPResponse profileResponse;
        String profileResponseString = null;
        // make request to download the OAuth client profile.

        HashMap<String, String> headers = new HashMap<String, String>();
        headers.put(ConnectionConstants.CONTENT_TYPE.getValue(),
                ConnectionConstants.JSON_CONTENT_TYPE.getValue());

        IdentityContext idContext = getIdentityContext(context, credStore);
        String deviceOS = DEVICE_OS + "="
                + URLEncoder.encode(idContext.getOSType(), "UTF-8");
        String osVersion = OS_VERSION + "="
                + URLEncoder.encode(idContext.getOSVersion(), "UTF-8");
        String queryString = deviceOS + "&" + osVersion;
        String appProfileUrl = serviceProfileEndpoint + "?" + queryString;
        final OMConnectionHandler connectionHandler = new OMConnectionHandler(context);
        profileResponse = connectionHandler.httpGet(new URL(appProfileUrl), headers);
        if (profileResponse != null) {
            if (profileResponse.isSuccess()) {
                profileResponseString = profileResponse.getResponseStringOnSuccess();
            } else {
                profileResponseString = profileResponse.getResponseStringOnFailure();
            }
            Log.d(TAG, " downloadClientServiceProfile OAuth Client service profile  is " + profileResponseString);
        }
        return profileResponseString;
    }

    @Override
    public void initialize(Context context, OMConnectionHandler handler) throws OMMobileSecurityException {
        if (mClientProfileService != null
                && mClientProfileService.toString().trim().length() != 0) {
            try {
                OMCredentialStore credStore = new OMCredentialStore(context, null, null);
                String serviceProfileResponse = downloadClientServiceProfile(context, credStore);
                if (serviceProfileResponse != null) {
                    populateResponse(serviceProfileResponse);
                } else {
                    throw new OMMobileSecurityException(OMErrorCode.OAUTH_SETUP_FAILED);
                }
            } catch (IOException e) {
                Log.e(TAG, e.getLocalizedMessage(), e);
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
            } catch (JSONException e) {
                Log.e(TAG, e.getLocalizedMessage(), e);
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
            }
        } else {
            throw new OMMobileSecurityException(OMErrorCode.OAUTH_SETUP_FAILED);
        }
    }

    /**
     * parses the response string which will be json representation. this API
     * will initialize the class members accordingly.
     *
     * @throws JSONException
     * @throws MalformedURLException
     */

    private void populateResponse(String jsonResponse) throws JSONException,
            MalformedURLException, OMMobileSecurityException {
        JSONObject serviceProfileJSON = new JSONObject(jsonResponse);
        JSONArray allowedGrantTypesJSON = serviceProfileJSON
                .optJSONArray(ALLOWED_GRANT_TYPES);
        if (allowedGrantTypesJSON != null && allowedGrantTypesJSON.length() > 0) {
            for (int i = 0; i < allowedGrantTypesJSON.length(); i++) {
                String grantTypeString = allowedGrantTypesJSON.optString(i);
                if (grantTypeString != null) {
                    getOAuthAllowedGrantTypes().add(grantTypeString);
                }
            }
        }

        JSONObject mobileAppConfigJSON = serviceProfileJSON
                .optJSONObject(MOBILE_APP_CONFIG);
        if (mobileAppConfigJSON != null) {
            JSONArray claimAttributesJSON = mobileAppConfigJSON
                    .optJSONArray(CLAIM_ATTRIBUTES_MSOAUTH);
            if (claimAttributesJSON != null && claimAttributesJSON.length() > 0) {
                for (int i = 0; i < claimAttributesJSON.length(); i++) {
                    String claimValue = claimAttributesJSON.optString(i);
                    if (claimValue != null) {
                        getIdentityClaimAttributes().add(claimValue);
                    }
                }
            }
        }

        this.mServerSideSSOEnabled = serviceProfileJSON
                .optBoolean(SERVER_SIDE_SSO);

        if (serverUrl != null) {
            String tokenEndpoint = serviceProfileJSON.optString(TOKEN_SERVICE);

            if (tokenEndpoint != null) {
                // since the service end point is already available, make use of
                // that to form the complete endpoint
                mOAuthTokenEndpoint = new URL(serverUrl + tokenEndpoint);
            }

            String authorizationEnpoint = serviceProfileJSON
                    .optString(AUTHORIZATION_SERVICE);
            if (authorizationEnpoint != null) {
                // since the service end point is already available, make use of
                // that to form the complete endpoint
                mOAuthAuthorizationEndpoint = new URL(serverUrl
                        + authorizationEnpoint);
            }

            if (mOAuthzGrantType == OAuthAuthorizationGrantType.AUTHORIZATION_CODE
                    || mOAuthzGrantType == OAuthAuthorizationGrantType.IMPLICIT) {
                this.authenticationUrl = mOAuthAuthorizationEndpoint;
            } else {
                this.authenticationUrl = mOAuthTokenEndpoint;
            }
        } else {
            throw new OMMobileSecurityException(OMErrorCode.OAUTH_SETUP_FAILED);
        }
        this.authenticationScheme = OMAuthenticationScheme.OAUTH20;
    }

    /**
     * Returns if the current client has SERVER SIDE SSO enabled or not.
     *
     * @return
     */
    public boolean getServerSSOMode() {
        return mServerSideSSOEnabled;
    }

    private String getServiceProfileUrl() {
        String serviceEP = mClientProfileService.toString();
        if (serviceEP.charAt(serviceEP.length() - 1) == '/') {
            serviceEP = serviceEP.substring(0, (serviceEP.length() - 1));
            Log.d(TAG, "Chopped the extra / char from the service URL!");
        }
        return serviceEP + APP_PROFILE_URI + mOAuthClientID;
    }

    /**
     * Returns the list of all the supported grant type for the OAuth client.
     *
     * @return
     */
    public List<String> getOAuthAllowedGrantTypes() {
        if (mOAuthAllowedGrantTypes == null) {
            mOAuthAllowedGrantTypes = new ArrayList<String>();
        }
        return mOAuthAllowedGrantTypes;
    }
}
