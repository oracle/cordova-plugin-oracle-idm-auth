/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.openID;

import android.text.TextUtils;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.json.JSONException;
import org.json.JSONObject;

import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import oracle.idm.mobile.auth.OAuthToken;
import oracle.idm.mobile.logging.OMLog;

/**
 * Representation of an Open ID Token.
 */
public class OpenIDToken extends OAuthToken {

    public enum TokenClaims {
        TYPE("typ"),
        ISSUER("iss"),
        JWT_ID("jti"),
        SUBJECT("sub"),
        NONCE("nonce"),
        AUDIENCE("aud"),
        ISSUED_AT("iat"),
        SESSION_ID("sid"),
        NOT_BEFORE("nbf"),
        EXPIRY_TIME("exp"),
        USER_ID("user_id"),
        TOKEN_TYPE("tok_type"),
        AUTH_TIME("auth_time"),
        USER_LANG("user_lang"),
        USER_TIMEZONE("user_tz"),
        USER_LOCAL("user_locale"),
        AUTHORIZATION_PARTY("azp"),
        SESSION_EXPIRY("session_exp"),
        AUTH_STRENGTH("auth_strength"),
        USER_TENANT_NAME("user_tenantname"),
        USER_DISPLAY_NAME("user_displayname"),
        SUBJECT_MAPPING_ATTR("sub_mappingattr");


        private String mValue;

        TokenClaims(String value) {
            mValue = value;
        }

        public String getName() {
            return mValue;
        }
    }

    private static final String TAG = OpenIDToken.class.getSimpleName();

    public static final String OPENID_CONNECT_TOKEN = "openid_connect_token";
    public static final String OPENID_CONNECT_SCOPE = "openid";

    private SignedJWT mSignedJWT;
    private JWTClaimsSet mClaims;
    private JWSHeader mJOSEHeaders;
    private boolean isVerified = false;

    /**
     * Constructs the object based on the output given by
     * {@link #toJSONObject()}.
     *
     * @param signedJWT this should be similar to the output of
     *                  {@link #toJSONObject()}.
     * @throws ParseException
     * @hide
     */
    public OpenIDToken(JSONObject signedJWT) throws ParseException, JSONException {
        this(SignedJWT.parse(signedJWT.getString(OPENID_CONNECT_TOKEN)));
        /* ID Token would have been stored in Secure Storage only if Signature was verified.
        * Hence, isVerified is set to true here.*/
        this.isVerified = true;
    }

    OpenIDToken(SignedJWT jwt) throws ParseException {
        super(OPENID_CONNECT_TOKEN, jwt.getParsedString());
        mSignedJWT = jwt;
        mJOSEHeaders = mSignedJWT.getHeader();
        mClaims = mSignedJWT.getJWTClaimsSet();
        expiryTime = mClaims.getExpirationTime();
        mScopes = new HashSet<>();
        mScopes.add(OpenIDToken.OPENID_CONNECT_SCOPE);
    }


    /**
     * Get Issuer from the claims ({@code TokenClaims.ISSUER}
     *
     * @return
     */
    public String getIssuer() {
        return mClaims.getIssuer();
    }


    /**
     * Gets subject from claims({@code TokenClaims.SUBJECT})
     */
    public String getSubject() {
        return mClaims.getSubject();
    }


    /**
     * Gets {@code List} of audience ({@code TokenClaims.AUDIENCE}) from claims
     */
    public List<String> getAudience() {
        return mClaims.getAudience();
    }


    /**
     * Gets the expiration time ({@code TokenClaims.EXPIRY_TIME}) from claims.
     */
    public Date getExpirationTime() {
        return expiryTime;
    }


    /**
     * Gets the not-before time  ({@code TokenClaims.NOT_BEFORE}) from the claims.
     */
    public Date getNotBeforeTime() {
        return mClaims.getNotBeforeTime();
    }


    /**
     * Gets the issued-at time ({@code TokenClaims.ISSUED_AT}) from the claims.
     */
    public Date getIssueTime() {
        return mClaims.getIssueTime();
    }


    /**
     * Gets the JWT ID from ({@code TokenClaims.JWT_ID}) claims.
     */
    public String getJWTID() {
        return mClaims.getJWTID();
    }


    /**
     * Gets the type ({@code TokenClaims.TYPE}) from claims.
     */
    public String getTokenType() {
        return (String) mClaims.getClaims().get(TokenClaims.TOKEN_TYPE.getName());
    }

    Map<String, Object> getAllClaims() {
        return mClaims.getClaims();
    }


    public boolean isVerified() {
        return isVerified;
    }

    void setVerified(boolean verified) {
        isVerified = verified;
    }

    public boolean matchStringClaim(TokenClaims claim, String expectedValue) {
        Object actualValue = mClaims.getClaims().get(claim.name());
        return actualValue instanceof String && !TextUtils.isEmpty(expectedValue) && expectedValue.equalsIgnoreCase((String) actualValue);
    }

    SignedJWT getSignedJWT() {
        return mSignedJWT;
    }

    @Override
    public String toString() {
        return toJSONObject().toString();
    }

    @Override
    public JSONObject toJSONObject() {
        JSONObject jsonObject = new JSONObject();
        try {
            jsonObject.put(OPENID_CONNECT_TOKEN, mSignedJWT.getParsedString());
        } catch (JSONException e) {
            OMLog.error(TAG, e.getMessage(), e);
        }
        return jsonObject;
    }
}
