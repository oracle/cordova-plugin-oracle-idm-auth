/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.util.Base64;
import android.util.Log;

import org.json.JSONException;

import java.io.UnsupportedEncodingException;
import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OMAuthenticationContext.Status;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.auth.OAuthConnectionsUtil.*;

/**
 * This class is a subclass of {@link OAuthMSDYCRService}. This class will be
 * responsible for fetching the pre-authz code from the Mobile and social. This
 * is the first step for doing any type dynamic client registration for Mobile
 * and Social.
 *
 */
class OAuthMSPreAuthZCodeService extends OAuthMSDYCRService implements ChallengeBasedService {
    private static final String TAG = OAuthMSPreAuthZCodeService.class
            .getName();
    private static final String AMPERSAND = "&";

    protected OAuthMSPreAuthZCodeService(AuthenticationServiceManager asm,
                                         OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
    }

    protected String getPayloadForPreAuthZCode()
            throws UnsupportedEncodingException, JSONException {
        StringBuilder payload = new StringBuilder();
        payload.append(OAUTH_GRANT_TYPE_REQ);
        payload.append(OAUTH_GRANT_TYPE_CLIENT_CREDENTIALS);
        payload.append(AMPERSAND);
        payload.append(OAUTH_MS_DEVICE_PROFILE_REQ);
        payload.append(Base64.encodeToString(
                getIdentityClaims().getBytes("UTF-8"), Base64.NO_WRAP));
        payload.append(AMPERSAND);
        payload.append(OAUTH_CLIENT_ID_REQ);
        payload.append((((OMOAuthMobileSecurityConfiguration) mASM
                .getMSS().getMobileSecurityConfig())
                .getOAuthClientID()));
        // utils.
        payload.append(AMPERSAND);
        payload.append(OAUTH_MS_REQUESTED_ASSERTIONS_REQ);
        payload.append(OAUTH_MS_GRANT_TYPE_PRE_AUTHZ_CODE);
        if (enableReqResVerbose) {
            Log.d(TAG, "--> Request for PRE-AUTHZ CODE :" + payload.toString());
        }
        return payload.toString();
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, final ASMInputController inputController) {
        OMLog.info(OMSecurityConstants.TAG, "collectChallengeInput");
        if (!isChallengeInputRequired(inputParams)) {
            //have all the required inputs lets proceed for authentication
            inputController.onInputAvailable(inputParams);
        } else {
            mAuthCompletionHandler.createChallengeRequest(mASM.getMSS(), createLoginChallenge(), new AuthServiceInputCallback() {
                @Override
                public void onInput(final Map<String, Object> inputs) {
                    inputController.onInputAvailable(inputs);
                }

                @Override
                public void onError(final OMErrorCode error) {
                    inputController.onInputError(error);
                }

                @Override
                public void onCancel() {
                    inputController.onCancel();
                }
            });
        }
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest,
                                               OMAuthenticationContext authContext)
            throws OMMobileSecurityException {
        Log.d(TAG, "handle authentication!");
        if (isClientAssertionValid(authContext)) {
            Log.d(TAG, "client Assertion valid!");
            authContext.setStatus(Status.OAUTH_PRE_AUTHZ_DONE);
            return null;
        }
        if (authContext.getInputParams() != null
                && !authContext.getInputParams().isEmpty()) {
            OAuthMSToken preAuthZCode = (OAuthMSToken) authContext
                    .getInputParams().get(OAUTH_MS_PRE_AUTHZ_CODE_PARAM);
            if (preAuthZCode != null && !preAuthZCode.isTokenExpired()) {
                Log.d(TAG, "pre AuthZ code already available!");
                authContext.setStatus(Status.OAUTH_PRE_AUTHZ_DONE);
                return null;
            }
        }
        OAuthMSToken token;
        try {
            String identityDomain = (String) authContext.getInputParams().get(
                    OMSecurityConstants.IDENTITY_DOMAIN);
            String preAuthZResponse = getToken(getPayloadForPreAuthZCode(),
                    ((OMOAuthMobileSecurityConfiguration) mASM
                            .getMSS()
                            .getMobileSecurityConfig()), identityDomain);
            if (enableReqResVerbose) {
                Log.d(TAG, "<-- Response for PRE-AUTHZ code :"
                        + preAuthZResponse);
            }
            token = new OAuthMSToken(preAuthZResponse);
            if (token != null) {
                authContext.getInputParams().put(OAUTH_MS_PRE_AUTHZ_CODE_PARAM,
                        token);
                authContext.setStatus(Status.OAUTH_PRE_AUTHZ_DONE);
                Log.d(TAG, "Pre AuthZ code acquired!");
            }
        } catch (Exception e) {
            Log.e(TAG, e.getLocalizedMessage(), e);
            throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
        }
        return null;
    }

    @Override
    public Type getType() {
        return Type.OAUTH_MS_PREAUTHZ;
    }

    @Override
    public OMAuthenticationChallenge createLoginChallenge() {
        return createUsernamePasswordChallenge();
    }

    @Override
    public OMAuthenticationChallenge createLogoutChallenge() {
        return null;
    }

    @Override
    public boolean isChallengeInputRequired(Map<String, Object> inputParams) {
        boolean result = true;
        try {
            mAuthCompletionHandler.validateResponseFields(inputParams);
            result = false;
        } catch (OMMobileSecurityException e) {
            OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
        }
        OMLog.info(OMSecurityConstants.TAG, "isChallengeInputRequired");
        return result;
    }

    @Override
    public OMAuthenticationCompletionHandler getCompletionHandlerImpl() {
        return mAuthCompletionHandler;
    }
}
