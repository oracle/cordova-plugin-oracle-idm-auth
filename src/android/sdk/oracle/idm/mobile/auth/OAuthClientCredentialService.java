/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;

import java.util.Map;
import java.util.WeakHashMap;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY;

/**
 * Authentication service for OAuth2.0 client credential grant type.
 *
 * @since 11.1.2.3.1
 */
class OAuthClientCredentialService extends OAuthAuthenticationService {
    private static final String TAG = OAuthClientCredentialService.class.getSimpleName();
    private AuthenticationServiceManager mAsm;

    protected OAuthClientCredentialService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
        mAsm = asm;
        OMLog.trace(TAG, "initialized");
    }


    @Override
    public void collectLoginChallengeInput(final Map<String, Object> inputParams, final ASMInputController inputController) {
        OMLog.trace(TAG, "collectChallengeInput");
        inputController.onInputAvailable(inputParams);
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.debug(TAG, "handleAuthentication");
        OMOAuthMobileSecurityConfiguration config = (OMOAuthMobileSecurityConfiguration) mASM
                .getMSS().getMobileSecurityConfig();
        String clientSecret = config
                .getOAuthClientSecret();
        WeakHashMap<String, Object> paramMap = getEmptyParamHashMap();
        paramMap.putAll(authContext.getInputParams());

        if (TextUtils.isEmpty(clientSecret)) {
            throw new OMMobileSecurityException(OMErrorCode.OAUTH_CLIENT_SECRET_INVALID);
        }
        try {
            String payload = mASM.getOAuthConnectionsUtil()
                    .getBackChannelRequestForAccessToken(
                            OAuthAuthorizationGrantType.CLIENT_CREDENTIALS,
                            paramMap);
            String identityDomain = (String) authContext.getInputParams().get(
                    IDENTITY_DOMAIN_KEY);
            String tokenResponse = getToken(payload,
                    config, identityDomain);
            if (tokenResponse != null) {
                OAuthToken accessToken = onAccessToken(tokenResponse);
                if (accessToken != null) {
                    onAuthSuccess(authContext, accessToken, OMAuthenticationContext.AuthenticationProvider.OAUTH20);
                    return null;
                }
            }
            // Any other error in the request will be reported by the
            // connection handler.
        } catch (OMMobileSecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR, e);
        }
        return null;
    }

    @Override
    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {
        return authContext.getAuthenticationProvider() != OMAuthenticationContext.AuthenticationProvider.OAUTH20 || isValidInternalAccessToken(authContext, validateOnline);
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
        OMLog.info(TAG, "logout");
        if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.OAUTH20) {
            clearOAuthTokens(authContext, isLogoutCall);
            reportLogoutCompleted(mAsm.getMSS(), isLogoutCall, null);
        } else {
            OMLog.info(TAG, "Not this config");
        }
    }

    @Override
    public Type getType() {
        return Type.OAUTH20_CC_SERVICE;
    }

}
