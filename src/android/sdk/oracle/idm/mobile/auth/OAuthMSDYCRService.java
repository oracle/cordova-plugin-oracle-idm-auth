/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import org.json.JSONException;

import java.io.UnsupportedEncodingException;
import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.*;
import static oracle.idm.mobile.auth.OAuthConnectionsUtil.*;

/**
 * DYCR -> Dynamic Client Registration. This class is responsible for performing
 * dynamic client registration of a OAuth mobile client against the M&S OAuth
 * server. This class strictly follows the M&S OAuth server standards.
 *
 */
abstract class OAuthMSDYCRService extends OAuthAuthenticationService {
    private static final String TAG = OAuthMSDYCRService.class.getName();
    private static final String AMPERSAND = "&";

    protected OAuthMSDYCRService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
    }

    protected String getPayloadForClientAssertionTwoLegged(
            Map<String, Object> paramMap) throws UnsupportedEncodingException,
            JSONException {
        StringBuilder payload = new StringBuilder();
        payload.append(OAuthConnectionsUtil.OAUTH_GRANT_TYPE_REQ);
        payload.append(OAUTH_GRANT_TYPE_PASSWORD);
        payload.append(AMPERSAND);
        payload.append(OAuthConnectionsUtil.OAUTH_USERNAME_REQ);
        payload.append((String) paramMap.get(USERNAME_KEY));
        payload.append(AMPERSAND);
        payload.append(OAuthConnectionsUtil.OAUTH_PASSWORD_REQ);
        payload.append((String) paramMap.get(PASSWORD_KEY));
        payload.append(AMPERSAND);
        updatePayloadWithClientID(payload);
        payload.append(OAUTH_MS_PRE_AUTHZ_CODE_REQ);
        payload.append((String) paramMap.get(OAUTH_MS_PRE_AUTHZ_CODE_PARAM));
        payload.append(AMPERSAND);
        updatePayloadWithDeviceProfile(payload);
        payload.append(OAUTH_MS_REQUESTED_ASSERTIONS_REQ);
        payload.append(OAUTH_TOKEN_TYPE_JWT_CLIENT_ASSERTION);
        if (enableReqResVerbose) {
            Log.d(TAG, "--> Request for CLIENT ASSERTION TWO-LEGGED :"
                    + payload.toString());
        }
        return payload.toString();
    }

    private void updatePayloadWithClientID(StringBuilder payload) {
        payload.append(OAuthConnectionsUtil.OAUTH_CLIENT_ID_REQ);
        payload.append(getClientID());
        payload.append(AMPERSAND);
    }

    private void updatePayloadWithDeviceProfile(StringBuilder payload)
            throws UnsupportedEncodingException, JSONException {
        payload.append(OAUTH_MS_DEVICE_PROFILE_REQ);
        payload.append(Base64.encodeToString(getIdentityClaims().getBytes("UTF-8"), Base64.NO_WRAP));
        payload.append(AMPERSAND);
    }

    private String getClientID() {
        return ((OMOAuthMobileSecurityConfiguration) mASM.getMSS()
                .getMobileSecurityConfig()).getOAuthClientID();
    }


    @Override
    public boolean isValid(OMAuthenticationContext authContext,
                           boolean validateOnline) {

        // extra checks for the scenario where client assertion is
        // revoked/expired even before completion of OAuth authentication.
        // in this case the provider will be null, so alone this condition here
        // will not help.
        if (authContext.getAuthenticationProvider() != OMAuthenticationContext.AuthenticationProvider.OAUTH20
                && (mASM.getOAuthConnectionsUtil() == null || mASM.getOAuthConnectionsUtil()
                .getOAuthType() != OAuthConnectionsUtil.OAuthType.MSOAUTH)) {
            return true;
        }
        boolean isTokenExpired = false;
        OAuthMSToken token = mASM.retrieveClientAssertion();
        if (token != null) {
            isTokenExpired = token.isTokenExpired();
        }
        Log.d(TAG, "isValid = " + !isTokenExpired);
        return !isTokenExpired;
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd,
                       boolean isDeleteHandles, boolean isDeleteTokens,
                       boolean isLogoutCall) {

        if (authContext.getAuthenticationProvider() != OMAuthenticationContext.AuthenticationProvider.OAUTH20) {
            return;
        }
        if (mASM.getOAuthConnectionsUtil() != null
                && mASM.getOAuthConnectionsUtil().getOAuthType() != OAuthConnectionsUtil.OAuthType.MSOAUTH) {
            return;
        }
        if (isDeleteHandles && isLogoutCall) {
            mASM.removeClientAssertion();
            Log.d(TAG, "Client Assertion Removed from Store.");
        }
    }

    protected boolean isClientAssertionValid(OMAuthenticationContext authContext)
            throws OMMobileSecurityException {
        if (mASM.retrieveClientAssertion() != null) {
            return isValid(authContext, false);
        }
        return false;
    }

    protected void onClientAssertion(String clientAssertionResponse,
                                     OMAuthenticationContext authContext) throws JSONException {
        OAuthMSToken clientAssertionToken = new OAuthMSToken(
                clientAssertionResponse);
        if (clientAssertionToken != null) {
            Log.d(TAG, "Client Assertion acquired!");
            mASM.setClientAssertion(clientAssertionToken);
            OAuthMSToken userAssertion = clientAssertionToken
                    .getUserAssertionToken();
            // add user assertion only when we have a non null value, as SERVER
            // SIDE SSO mode gives us an empty assertion.
            if (userAssertion != null
                    && !TextUtils.isEmpty(userAssertion.getValue())) {
                Log.d(TAG, "User Assertion acquired!");
                authContext.getTokens().put(
                        OMSecurityConstants.OM_OAUTH_USER_ASSERTION_TOKEN,
                        userAssertion);
            } else {
                Log.d(TAG, "User Assertion not acquired!");
            }
            authContext.setStatus(OMAuthenticationContext.Status.OAUTH_DYCR_DONE);
        }
    }
}
