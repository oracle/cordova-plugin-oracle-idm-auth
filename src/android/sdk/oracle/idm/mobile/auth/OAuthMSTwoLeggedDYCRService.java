/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.util.Log;

import org.json.JSONException;

import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.WeakHashMap;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPResponse;

import static oracle.idm.mobile.auth.OAuthConnectionsUtil.OAUTH_MS_PRE_AUTHZ_CODE_PARAM;

/**
 * This class is a subclass of {@link OAuthMSDYCRService}. This class will be
 * responsible for handling the Two legged client registration for Mobile and
 * Social OAuth flows.
 *
 */
class OAuthMSTwoLeggedDYCRService extends OAuthMSDYCRService implements ChallengeBasedService {
    private static final String TAG = OAuthMSTwoLeggedDYCRService.class
            .getName();

    protected OAuthMSTwoLeggedDYCRService(AuthenticationServiceManager asm,
                                          OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
    }


    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, ASMInputController inputController) {
        inputController.onInputAvailable(inputParams);
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest,
                                               OMAuthenticationContext authContext)
            throws OMMobileSecurityException {
        Log.v(TAG, "handleAuthentication");
        boolean isValid = isClientAssertionValid(authContext);
        if (!isValid) {
            OMOAuthMobileSecurityConfiguration oAuthConfig = (OMOAuthMobileSecurityConfiguration) mASM
                    .getMSS().getMobileSecurityConfig();
            authContext
                    .setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.OAUTH20);
            WeakHashMap<String, Object> paramMap = getEmptyParamHashMap();
            paramMap.putAll(authContext.getInputParams());
            try {
                OAuthMSToken token = (OAuthMSToken) paramMap
                        .get(OAUTH_MS_PRE_AUTHZ_CODE_PARAM);
                if (token != null && !token.isTokenExpired()) {
                    paramMap.put(OAUTH_MS_PRE_AUTHZ_CODE_PARAM,
                            token.getValue());
                    String identityDomain = (String) authContext
                            .getInputParams().get(
                                    OMSecurityConstants.IDENTITY_DOMAIN);
                    String clientAssertionResponse = getToken(
                            getPayloadForClientAssertionTwoLegged(paramMap),
                            oAuthConfig, identityDomain);
                    if (enableReqResVerbose) {
                        Log.d(TAG,
                                " <-- Response for : CLIENT ASSERTION (2-legged) "
                                        + clientAssertionResponse);
                    }
                    if (clientAssertionResponse != null) {
                        onClientAssertion(clientAssertionResponse,
                                authContext);
                        return null;
                    }
                } else {
                    throw new OMMobileSecurityException(OMErrorCode.OAUH_MS_PRE_AUHZ_CODE_INVALID);
                }

            } catch (JSONException jse) {
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
            } catch (UnsupportedEncodingException e) {
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
            }

        } else {
            authContext.setStatus(OMAuthenticationContext.Status.OAUTH_DYCR_DONE);
        }
        return null;
    }

    @Override
    public Type getType() {
        return null;
    }

    @Override
    public OMAuthenticationChallenge createLoginChallenge() throws OMMobileSecurityException {
        return null;
    }

    @Override
    public OMAuthenticationChallenge createLogoutChallenge() {
        return null;
    }

    @Override
    public boolean isChallengeInputRequired(Map<String, Object> inputParams) {
        return false;
    }

    @Override
    public OMAuthenticationCompletionHandler getCompletionHandlerImpl() {
        return null;
    }
}
