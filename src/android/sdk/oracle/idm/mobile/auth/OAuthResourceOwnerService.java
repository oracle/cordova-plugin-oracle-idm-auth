/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.util.Log;

import org.json.JSONException;

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
import static oracle.idm.mobile.OMSecurityConstants.Challenge.USERNAME_KEY;

/**
 * Authentication service for OAuth2.0 resource_owner grant type.
 *
 * @since 11.1.2.3.1
 */
class OAuthResourceOwnerService extends OAuthAuthenticationService implements ChallengeBasedService {
    private static final String TAG = OAuthResourceOwnerService.class.getSimpleName();
    private AuthenticationServiceManager mAsm;

    protected OAuthResourceOwnerService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
        mAsm = asm;
        OMLog.trace(TAG, "initialized");
    }

    @Override
    public void collectLoginChallengeInput(final Map<String, Object> inputParams, final ASMInputController inputController) {
        OMLog.trace(TAG, "collectLoginChallengeInput");
        if (!isChallengeInputRequired(inputParams)) {
            inputController.onInputAvailable(inputParams);
        } else {
            mAuthCompletionHandler.createChallengeRequest(mASM.getMSS(), createLoginChallenge(), new AuthServiceInputCallback() {
                @Override
                public void onInput(Map<String, Object> inputs) {
                    if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
                        //lets update the RC UI preferences.

                        OMLog.info(TAG, "Remember Cred feature is enabled, Storing UI prefs");
                        //no need to check for *'s being returned from the UI layer, as we are not dealing with auto login or remember creds.
                        storeRCUIPreferences(inputs);
                    }
                    inputController.onInputAvailable(inputs);
                }

                @Override
                public void onError(OMErrorCode error) {
                    inputController.onInputError(error);
                }

                @Override
                public void onCancel() {
                    inputController.onCancel();
                }
            });
            //as application for the credentials
        }


    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.debug(TAG, "handleAuthentication");
        String userName = (String) authContext.getInputParams().get(USERNAME_KEY);
        OMLog.debug(TAG, "username: " + userName);
        authContext.setUserName(userName);
        final WeakHashMap<String, Object> params = getEmptyParamHashMap();
        params.putAll(authContext.getInputParams());
        String payload = null;
        OMOAuthMobileSecurityConfiguration oAuthConfig = (OMOAuthMobileSecurityConfiguration) mAsm
                .getMSS().getMobileSecurityConfig();
        boolean addClientAssertion = updateParamsForClientAssertionForTokenRequest(
                authContext, params);
        try {
            if (addClientAssertion) {
                // get the payload for access token using client assertion
                payload = mAsm.getOAuthConnectionsUtil()
                        .getBackChannelRequestForAccessTokenUsingClientAssertion(
                                OAuthAuthorizationGrantType.RESOURCE_OWNER, params, determineClientAssertionType());
            } else {
                payload = mAsm.getOAuthConnectionsUtil().getBackChannelRequestForAccessToken(OAuthAuthorizationGrantType.RESOURCE_OWNER, params);
            }
        } catch (Exception e) {
            Log.e(TAG, e.getLocalizedMessage(), e);
            throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR); //TODO check error code
        }
        authContext.setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.OAUTH20);
        String identityDomain = (String) authContext.getInputParams().get(IDENTITY_DOMAIN_KEY);
        OAuthToken accessToken = null;
        try {
            String tokenResponse = getToken(payload, oAuthConfig, identityDomain);
            if (enableReqResVerbose) {
                OMLog.debug(TAG, "<-- Response for ACCESS TOKEN : " + tokenResponse);
            }
            accessToken = onAccessToken(tokenResponse);
        } catch (JSONException e) {
            throw new OMMobileSecurityException(OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
        } catch (OMMobileSecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
        }
        if (accessToken != null) {
            onAuthSuccess(authContext, accessToken, OMAuthenticationContext.AuthenticationProvider.OAUTH20);
            return null;
        }
        // if any other exception/error during this process will be reported by
        // the
        // connection handler.
        return null;
    }

    @Override
    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {
        if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.OAUTH20) {
            return isValidInternalAccessToken(authContext, validateOnline);
        }
        OMLog.info(TAG, "isValid - Not an OAuth Use case");
        return true;
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
        OMLog.info(TAG, "logout");
        if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.OAUTH20) {
            if (isDeleteTokens) {
                clearOAuthTokens(authContext, isLogoutCall);
                reportLogoutCompleted(mASM.getMSS(), isLogoutCall, (OMMobileSecurityException) null);
            }
        } else {
            OMLog.info(TAG, "Not an OAuth (resource_owner) logout use case!");
        }
    }

    @Override
    public Type getType() {
        return Type.OAUTH20_RO_SERVICE;
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
        OMLog.info(TAG, "isChallengeInputRequired");
        return result;
    }

    @Override
    public OMAuthenticationCompletionHandler getCompletionHandlerImpl() {
        OMLog.trace(TAG, "getCompletionHandlerImpl");
        return mAuthCompletionHandler;
    }

}
