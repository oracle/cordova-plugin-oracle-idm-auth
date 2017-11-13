/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;

import org.json.JSONException;
import org.json.JSONObject;

import static oracle.idm.mobile.OMSecurityConstants.EMPTY_STRING;

/**
 * This class is representation of OAuth2.0 token from a Mobile & Social OAuth
 * server.
 *
 */
public class OAuthMSToken extends OAuthToken {
    private static final long serialVersionUID = -5456053768922106402L;
    private static final String TAG = OAuthMSToken.class.getName();
    private static final String ORACLE_CLIENT_ASSERTION_TYPE = "oracle_client_assertion_type";
    private static final String ORACLE_AUX_TOKENS = "oracle_aux_tokens";
    private static final String ORACLE_USER_ASSERTION = "user_assertion";
    private static final String ORACLE_GRANT_TYPE = "oracle_grant_type";
    private static final String ORACLE_TOKEN_CONTEXT = "oracle_tk_context";
    private static final String ORACLE_TOKEN_IN_SERVER_DEVICE_STORE = "oracle_token_in_server_device_store";
    private static final String ORACLE_OAM_MT = "oam_mt";

    private String mTokenContext;
    private String mClientAssertionType;
    private OAuthMSToken mUserToken;
    private String mGrantType;
    private OAuthMSToken mOAMMTToken;
    private boolean mTokenInServerDeviceStore = false;

    public OAuthMSToken(String tokenString) throws JSONException {
        super(tokenString);
        parseMSOAuthToken(tokenString);

    }

    private void parseMSOAuthToken(String tokenString) throws JSONException {
        JSONObject tokenJson = new JSONObject(tokenString);
        String tokenContext = tokenJson.optString(ORACLE_TOKEN_CONTEXT,
                EMPTY_STRING);
        mTokenContext = tokenContext;
        name = mTokenContext;
        String assertionType = tokenJson.optString(
                ORACLE_CLIENT_ASSERTION_TYPE, EMPTY_STRING);
        mTokenType = assertionType;
        JSONObject auxTokens = tokenJson.optJSONObject(ORACLE_AUX_TOKENS);
        if (auxTokens != null) {
            // for now we are only interested in oam_mt and user_assertion.
            String userTokenString = auxTokens.optString(ORACLE_USER_ASSERTION);
            if (!TextUtils.isEmpty(userTokenString)) {
                mUserToken = new OAuthMSToken(userTokenString);
            } else {
                String oamMTString = auxTokens.optString(ORACLE_OAM_MT);
                if (!TextUtils.isEmpty(oamMTString)) {
                    mOAMMTToken = new OAuthMSToken(oamMTString);
                }
            }
        }
        mTokenInServerDeviceStore = tokenJson.optBoolean(
                ORACLE_TOKEN_IN_SERVER_DEVICE_STORE, false);
        mGrantType = tokenJson.optString(ORACLE_GRANT_TYPE, EMPTY_STRING);

    }

    public OAuthMSToken(String name, String tokenValue) {
        super(name, tokenValue);
    }

    public String getClientAssertionType() {
        return mTokenType;
    }

    public void setClientAssertionType(String type) {
        mClientAssertionType = type;
    }

    public OAuthMSToken getUserAssertionToken() {
        return mUserToken;
    }

}
