/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Calendar;
import java.util.Date;
import java.util.Set;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OAuthConnectionsUtil.OAuthResponseParameters;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.EMPTY_STRING;

/**
 * This class is representation of an OAuth2.0 token.
 *
 */
public class OAuthToken extends OMToken {
    private static final long serialVersionUID = 8126307042768550597L;
    private static final String TAG = OAuthToken.class.getName();
    protected Set<String> mScopes;
    protected String mRefreshTokenValue;
    protected String mTokenType;
    protected String mTokenID;
    protected String mIdToken;


    protected OAuthToken() {

    }

    /**
     * This will create an OAuth token object from a JSON String which contains
     * all the token related information.
     * <p>
     * Please note: We should pass a valid string other wise all the field of
     * the token object will be empty.
     *
     * @param tokenString
     * @throws JSONException
     */
    public OAuthToken(String tokenString) throws JSONException {
        super();
        parseForStandardToken(tokenString);
        OMLog.info(TAG, "Created OAuth Access Token!");
    }

    private void parseForStandardToken(String tokenString) throws JSONException {
        JSONObject tokenJSON = new JSONObject(tokenString);
        String accessTokenValue = tokenJSON.optString(
                OAuthResponseParameters.ACCESS_TOKEN.getValue(), EMPTY_STRING);
        if (TextUtils.isEmpty(accessTokenValue)) {
            // String to token , store to runtime usecase
            this.value = tokenJSON.optString(OMSecurityConstants.TOKEN_VALUE,
                    EMPTY_STRING);
        } else {
            this.value = accessTokenValue;
        }
        String tokenName = tokenJSON.optString(OMSecurityConstants.TOKEN_NAME,
                EMPTY_STRING);
        name = tokenName;
        String refreshTokenValue = tokenJSON.optString(
                OAuthResponseParameters.REFRESH_TOKEN.getValue(), EMPTY_STRING);
        this.mRefreshTokenValue = refreshTokenValue;
        String expTime = tokenJSON.optString(
                OAuthResponseParameters.EXPIRES_IN.getValue(), EMPTY_STRING);
        if (!TextUtils.isEmpty(expTime)) {
            int expiryInSecs = Integer.parseInt(expTime);
            Calendar futureTime = Calendar.getInstance();
            futureTime.add(Calendar.SECOND, expiryInSecs);
            Date expiryDate = futureTime.getTime();
            this.expiryTime = expiryDate;
            this.expiryInSecs = expiryInSecs;
        } else {
            // if it is store to memory use case.
            long expFromStore = tokenJSON.optLong(OMSecurityConstants.EXPIRES,
                    -1);
            if (expFromStore != -1) {
                this.expiryTime = new Date(expFromStore);

            }

        }
        String tokenType = tokenJSON.optString(
                OAuthResponseParameters.TOKEN_TYPE.getValue(), EMPTY_STRING);
        this.mTokenType = tokenType;

        String tokenID = tokenJSON.optString(
                OAuthResponseParameters.TOKEN_ID.getValue(), EMPTY_STRING);
        this.mTokenID = tokenID;
        String idToken = tokenJSON.optString(
                OAuthResponseParameters.ID_TOKEN.getValue(), EMPTY_STRING);
        this.mIdToken = idToken;
        if (TextUtils.isEmpty(name)) {
            name = OMSecurityConstants.OAUTH_ACCESS_TOKEN;
        }
    }

    public String getTokenType() {
        return mTokenType;
    }

    void setTokenType(String tokenType) {
        this.mTokenType = tokenType;
    }

    public String getTokenID() {
        return mTokenID;
    }

    void setTokenID(String tokenID) {
        this.mTokenID = tokenID;
    }

    protected OAuthToken(String name, String tokenValue) {
        super(name, tokenValue);
    }

    OAuthToken(String name, String tokenValue, Date expiry) {
        super(name, tokenValue, expiry);
    }

    public Set<String> getScopes() {
        return mScopes;
    }

    void setScopes(Set<String> scopes) {
        this.mScopes = scopes;
    }

    String getRefreshTokenValue() {
        return mRefreshTokenValue;
    }

    void setRefreshTokenValue(String refreshTokenValue) {
        this.mRefreshTokenValue = refreshTokenValue;
    }

    void setIdToken(String idToken) {
        this.mIdToken = idToken;
    }

    String getIdToken() {
        return mIdToken;
    }

    boolean hasRefreshToken() {
        return !TextUtils.isEmpty(mRefreshTokenValue);
    }

    public String toString() {
        JSONObject tokenJSON = new JSONObject();
        String tokenString = "";
        try {
            tokenJSON.put(OMSecurityConstants.TOKEN_NAME, name);
            tokenJSON.put(OMSecurityConstants.TOKEN_VALUE, value);
            tokenJSON.put(OMSecurityConstants.EXPIRES, expiryTime.toString());
            tokenJSON.put(OMSecurityConstants.EXPIRY_SECS, expiryInSecs);
            tokenJSON.put(OMSecurityConstants.OAUTH_TOKEN_REFRESH_VALUE,
                    mRefreshTokenValue);
            if (mScopes != null)
                tokenJSON.put(OMSecurityConstants.OAUTH_TOKEN_SCOPE,
                        new JSONArray(mScopes));
            tokenString = tokenJSON.toString();
        } catch (JSONException e) {
            Log.e(TAG + "_toString()", e.getLocalizedMessage(), e);
        }
        return tokenString;
    }

}
