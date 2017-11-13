/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.logging.OMLog;

/**
 * This class represents the client registration token/secret from the IDCS server after doing dynamic client registration of the client.
 * <p>
 * <p>
 *
 * @hide Created by ajulka on 12/5/16.
 */

public class IDCSClientRegistrationToken extends OAuthToken {

    private static final String TAG = IDCSClientRegistrationToken.class.getSimpleName();

    private String mClientID;
    private String mClientName;
    private String mClientSecret;
    private List<String> mRedirectUris;
    private List<String> mGrantTypes;
    private String mScope;
    private String mDeviceID;
    private String mAndroidPackageName;
    private String mAndroidSigningCert;


    /**
     * IDCSClientRegistrationToken
     *
     * @param type
     * @param value
     */
    //If application gives us the assertion.
    public IDCSClientRegistrationToken(String type, String value) {
        mTokenType = type;
        this.value = value;
    }


    public IDCSClientRegistrationToken(String tokenResponse) throws OMMobileSecurityException {
        if (tokenResponse == null || tokenResponse.isEmpty()) {
            throw new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_TOKEN_EMPTY);
        }
        try {
            parseToken(tokenResponse);
        } catch (JSONException e) {
            throw new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_PARSING_FAILED, e);
        }
        OMLog.debug(TAG, "Created IDCS Client Registration Token");
    }


    private void parseToken(String tokenString) throws JSONException {
        name = OMSecurityConstants.CLIENT_REGISTRATION_TOKEN;
        //for now the token type is JWT Token.
        mTokenType = OAuthConnectionsUtil.OAUTH_TOKEN_TYPE_JWT_CLIENT_ASSERTION;
        JSONObject tokenJSON = new JSONObject(tokenString);
        mClientID = tokenJSON.optString(OMSecurityConstants.CLIENT_ID);
        mClientName = tokenJSON.optString(OMSecurityConstants.CLIENT_NAME);
        mClientSecret = tokenJSON.optString(OMSecurityConstants.CLIENT_SECRET);
        value = mClientSecret;
        long expiresAt = tokenJSON.optLong(OMSecurityConstants.CLIENT_SECRET_EXPIRES_AT);// SENDS IN SECONDS
        expiryTime = new Date(expiresAt * 1000);
        JSONArray redirectUrisJSON = tokenJSON.optJSONArray(OMSecurityConstants.REDIRECT_URIS);
        if (redirectUrisJSON != null) {
            mRedirectUris = new ArrayList<>();
            populateArray(mRedirectUris, redirectUrisJSON);
        }
        JSONArray grantTypeJSON = tokenJSON.optJSONArray(OMSecurityConstants.GRANT_TYPES);
        if (grantTypeJSON != null) {
            mGrantTypes = new ArrayList<>();
            populateArray(mGrantTypes, grantTypeJSON);
        }
        mDeviceID = tokenJSON.optString(OMSecurityConstants.DEVICE_ID);
        mAndroidPackageName = tokenJSON.optString(OMSecurityConstants.ANDROID_PACKAGE_NAME);
        mAndroidSigningCert = tokenJSON.optString(OMSecurityConstants.ANDROID_SIGNING_CERT_FINGERPRINT);
    }

    @Override
    public boolean isTokenExpired() {
        return super.isTokenExpired();
    }

    private void populateArray(List<String> targetCollection, JSONArray array) throws JSONException {
        for (int i = 0; i < array.length(); i++) {
            if (array.get(i) instanceof String) {
                //additional safety.
                targetCollection.add((String) array.get(i));
            }
        }
    }

    public String getClientID() {
        return mClientID;
    }

    public String getClientName() {
        return mClientName;
    }

    public String getClientSecret() {
        return mClientSecret;
    }

    public List<String> getRedirectUris() {
        return mRedirectUris;
    }

    public List<String> getGrantTypes() {
        return mGrantTypes;
    }

    public String getScope() {
        return mScope;
    }

    public String getDeviceID() {
        return mDeviceID;
    }

    public String getAndroidPackageName() {
        return mAndroidPackageName;
    }

    public String getAndroidSigningCert() {
        return mAndroidSigningCert;
    }


    public String toString() {
        JSONObject tokenJSON = new JSONObject();
        try {
            tokenJSON.put(OMSecurityConstants.CLIENT_ID, mClientID);
            tokenJSON.put(OMSecurityConstants.CLIENT_NAME, mClientName);
            tokenJSON.put(OMSecurityConstants.CLIENT_SECRET, mClientSecret);
            tokenJSON.put(OMSecurityConstants.CLIENT_SECRET_EXPIRES_AT, expiryTime.getTime());
            //redirect URIS
            tokenJSON.put(OMSecurityConstants.REDIRECT_URIS, getListJSON(mRedirectUris));
            //grant types
            tokenJSON.put(OMSecurityConstants.GRANT_TYPES, getListJSON(mGrantTypes));
            tokenJSON.put(OMSecurityConstants.DEVICE_ID, mDeviceID);
            tokenJSON.put(OMSecurityConstants.ANDROID_PACKAGE_NAME, mAndroidPackageName);
            tokenJSON.put(OMSecurityConstants.ANDROID_SIGNING_CERT_FINGERPRINT, mAndroidSigningCert);
            return tokenJSON.toString();
        } catch (JSONException e) {
            OMLog.debug(TAG, "toString() failed", e);
            return null;
        }

    }

    private JSONArray getListJSON(List<String> list) throws JSONException {
        JSONArray array = new JSONArray();
        if (list != null && list.size() > 0) {
            int count = 0;
            for (String item : list) {
                array.put(count++, item);
            }
        }
        return array;
    }

    public void setClientID(String clientID) {
        mClientID = clientID;
    }
}
