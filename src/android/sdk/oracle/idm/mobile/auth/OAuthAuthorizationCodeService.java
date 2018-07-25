/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.os.Handler;
import android.os.Looper;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONException;

import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OAuthConnectionsUtil.OAuthResponseParameters;
import oracle.idm.mobile.auth.logout.OAuthAuthorizationCodeLogoutHandler;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.auth.webview.LogoutWebViewClient;
import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY;

/**
 * OAuth authentication service to handle authorization code grant type.
 *
 * @hide
 * @since 11.1.2.3.1
 */
class OAuthAuthorizationCodeService extends OAuthAuthenticationService implements ChallengeBasedService {

    private static final String TAG = OAuthAuthorizationCodeService.class.getSimpleName();

    protected boolean isClientRegistration = false;

    protected OAuthAuthorizationCodeService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler loginHandler, OMLogoutCompletionHandler logoutHandler) {
        super(asm, loginHandler, logoutHandler);
        OMLog.trace(TAG, "initialized");
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, final ASMInputController inputController) {

        OMLog.trace(TAG, "collectChallengeInput");
        if (!isChallengeInputRequired(inputParams)) {
            inputController.onInputAvailable(inputParams);
        } else {

            try {
                //FIXME Use oracle.idm.mobile.auth.webview.WebViewAuthServiceInputCallbackImpl instead of a new anonymous AuthServiceInputCallback
                mAuthCompletionHandler.createChallengeRequest(mASM.getMSS(), createLoginChallenge(), new AuthServiceInputCallback() {
                    @Override
                    public void onInput(Map<String, Object> inputs) {
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
            } catch (OMMobileSecurityException e) {
                inputController.onInputError(OMErrorCode.INTERNAL_ERROR);
            }
        }
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.info(TAG, "handleAuthentication");
        final HashMap<String, Object> inputParams = (HashMap<String, Object>) authContext
                .getInputParams();
        validateAndUpdateInputParams(inputParams);
        authContext.setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.OAUTH20);
        OAuthToken accessToken = null;
        if (inputParams.containsKey(OAuthConnectionsUtil.OAuthResponseParameters.CODE.getValue())) {
            // adding client id/client secret to params
            WeakHashMap<String, Object> paramMap = getEmptyParamHashMap();
            paramMap.put(OAuthResponseParameters.CODE.getValue(),
                    inputParams.get(OAuthResponseParameters.CODE
                            .getValue()));
            String identityDomain = (String) authContext.getInputParams().get(
                    OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY);
            String tokenResponse = onAuthZCode(authContext, paramMap, identityDomain);
            try {
                accessToken = onAccessToken(tokenResponse);
                if (accessToken != null) {
                    if (isClientRegistration) {
                        OMLog.debug(TAG, "Obtained AT for the client registration service (updating params)");
                        //do not mark authentication complete.
                        authContext.getInputParams().put(OMSecurityConstants.Param.IDCS_CLIENT_REGISTRATION_ACCESS_TOKEN, accessToken);
                    } else {
                        onAuthSuccess(authContext, accessToken, OMAuthenticationContext.AuthenticationProvider.OAUTH20);
                    }
                    return null;
                }
            } catch (JSONException e) {
                if (isClientRegistration) {
                    OMLog.error(TAG, "Unable to parse AT for the client registration service!", e);
                    throw new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_UNABLE_TO_OBTAIN_AT, e);
                } else {
                    OMLog.error(TAG, "Access Token Parsing failed!", e);
                    throw new OMMobileSecurityException(OMErrorCode.OAUTH_AUTHENTICATION_FAILED, e);
                }
            }
        } else if (inputParams.containsKey(OAuthResponseParameters.ERROR
                .getValue())) {
            // this may be because of some error either in front channel or back
            // channel
            // check in the input params for the same.
            OMMobileSecurityException mobileException = onError(inputParams);
            if (isClientRegistration) {
                OMLog.error(TAG, "Error obtaining the AT for the client registration service");
            }
            if (mobileException == null) {
                mobileException = new OMMobileSecurityException(
                        isClientRegistration ? OMErrorCode.IDCS_CLIENT_REGISTRATION_UNABLE_TO_OBTAIN_AT : OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
                return null;
            }

            authContext.setException(mobileException);
            authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
        }
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

    protected void handle3LeggedLogout(final OMAuthenticationContext authContext, final boolean report) {
        OMLog.info(TAG, "Since user agent was involved during authentication, the provided logout url needs to be loaded in the same.");
        collectLogoutChallengeInput(authContext.getInputParams(), new AuthServiceInputCallback() {
            @Override
            public void onInput(Map<String, Object> inputs) {
                if (inputs != null) {

                    if (mConfig.getOAuthBrowserMode() == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
                        boolean loaded = true;
                        //embedded
                        final WebView webview = (WebView) inputs.get(OMSecurityConstants.Challenge.WEBVIEW_KEY);
                        final WebViewClient webViewClient = (WebViewClient) inputs.get(OMSecurityConstants.Challenge.WEBVIEW_CLIENT_KEY);
                        final String logoutURL = mASM.getOAuthConnectionsUtil().getLogoutUrl(mASM.getAuthenticationContext());
                        if (webview != null && logoutURL != null) {
                            final Handler handler = new Handler(Looper.getMainLooper());
                            handler.post(new Runnable() {
                                @Override
                                public void run() {
                                    loadLogoutURL(webview, new LogoutWebViewClient(webview, webViewClient,
                                            mASM.getMSS(), handler, mConfig, authContext.getLogoutTimeout(),
                                            report), logoutURL);
                                }
                            });
                        } else {
                            loaded = false;
                            OMLog.error(TAG, "logout_onInput()- WebView is null or logoutURL is null");
                        }
                        if (!loaded) {
                            OMLog.info(TAG, "Unable to load logout URL, so removing all session cookies");
                            removeSessionCookies();
                            clearOAuthTokens(authContext, true);
                            if (report) {
                                reportLogoutCompleted(mASM.getMSS(), true, OMErrorCode.LOGOUT_URL_NOT_LOADED);
                            }
                            return;
                        }
                    } else if (mConfig.getOAuthBrowserMode() == OMMobileSecurityConfiguration.BrowserMode.EXTERNAL) {
                        /**
                         * OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY is already matched in
                         * {@link OAuthAuthorizationCodeLogoutHandler#validateResponseFields(Map)}
                         */
                        clearOAuthTokens(authContext, true);
                        if (report) {
                            reportLogoutCompleted(mASM.getMSS(), true, (OMMobileSecurityException) null);
                        }
                    }
                }
            }

            @Override
            public void onError(OMErrorCode error) {
                if (mConfig.getOAuthBrowserMode() == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
                    removeSessionCookies();
                }
                clearOAuthTokens(authContext, true);
                reportLogoutCompleted(mASM.getMSS(), true, error);
            }

            @Override
            public void onCancel() {
                removeSessionCookies();
                clearOAuthTokens(authContext, true);
                reportLogoutCompleted(mASM.getMSS(), true, OMErrorCode.LOGOUT_URL_NOT_LOADED);
            }
        });
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
        if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.OAUTH20) {
            OMLog.debug(TAG, "~logout~");
            boolean needLogoutHandler = false;
            if (isLogoutCall) {
                final URL logoutURL = mConfig.getLogoutUrl();
                if (logoutURL != null) {
                    needLogoutHandler = true;
                    handle3LeggedLogout(authContext, true);
                }
            }
            if (isDeleteTokens && !needLogoutHandler) {
                //1. either isValid false use case
                //2. logout - with no logout URL
                //3. logout - non 3-legged flows
                clearOAuthTokens(authContext, isLogoutCall);
                reportLogoutCompleted(mASM.getMSS(), isLogoutCall, (OMMobileSecurityException) null);
            }
        }
    }

    /**
     * This method returns an access token given an authorization code.
     *
     * @param paramMap
     * @param identityDomain
     * @return
     * @throws OMMobileSecurityException
     */
    protected String onAuthZCode(OMAuthenticationContext context, WeakHashMap<String, Object> paramMap, String identityDomain)
            throws OMMobileSecurityException {
        OMLog.debug(TAG, "onAuthZCode");
        String payload = null;

        boolean addClientAssertion = false;
        if (!isClientRegistration) {
            //we do not send assertion for the client registration flow
            addClientAssertion = updateParamsForClientAssertionForTokenRequest(context, paramMap);
        }
        try {
            if (addClientAssertion) {
                payload = mASM.getOAuthConnectionsUtil().getBackChannelRequestForAccessTokenUsingClientAssertion(OAuthAuthorizationGrantType.AUTHORIZATION_CODE, paramMap, determineClientAssertionType());
            } else {
                payload = mASM.getOAuthConnectionsUtil()
                        .getBackChannelRequestForAccessToken(
                                OAuthAuthorizationGrantType.AUTHORIZATION_CODE,
                                paramMap);
            }
        } catch (Exception e) {
            OMLog.error(TAG, "Error while parsing authorization code", e);
            throw new OMMobileSecurityException(OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
        }
        if (payload != null) {
            try {
                String tokenResponse = getToken(payload, mConfig,
                        identityDomain);
                if (enableReqResVerbose) {
                    OMLog.debug(TAG, "<--- Response while getting ACCESS token : " + tokenResponse);
                }
                return tokenResponse;
            } catch (OMMobileSecurityException e) {
                throw e;
            } catch (Exception e) {
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
            }
        }
        return null;
    }

    @Override
    public Type getType() {
        return Type.OAUTH20_AC_SERVICE;
    }

    @Override
    public OMAuthenticationChallenge createLoginChallenge() throws OMMobileSecurityException {
        //based on the configuration create the challenge.

        OMAuthenticationChallenge challenge;

        OMMobileSecurityConfiguration.BrowserMode mode = mConfig.getOAuthBrowserMode();
        OMLog.info(TAG, "Creating Challenge for browser mode: " + mode.name());
        if (mode == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
            challenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.EMBEDDED_WEBVIEW_REQUIRED);
        } else {
            challenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.EXTERNAL_BROWSER_INVOCATION_REQUIRED);
            OAuthConnectionsUtil oauthConnUtil = mASM.getOAuthConnectionsUtil();
            try {
                challenge.addChallengeField(OMSecurityConstants.Challenge.EXTERNAL_BROWSER_LOAD_URL, isClientRegistration ?
                        oauthConnUtil.getFrontChannelRequestForClientRegistration() :
                        oauthConnUtil.getFrontChannelRequestForAccessToken(true));
                challenge.addChallengeField(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY, "");//indicates that we want this
            } catch (UnsupportedEncodingException e) {
                OMLog.error(TAG, "error while getting the front channel request", e);
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR, e);
            } catch (NoSuchAlgorithmException e) {
                OMLog.error(TAG, "error while getting the front channel request", e);
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR, e);
            }
            //put login URL to be invoked?
        }
        updateChallengeWithException(challenge);
        OMLog.info(TAG, "Challenge : " + challenge.toString());
        return challenge;
    }

    @Override
    public OMAuthenticationChallenge createLogoutChallenge() {
        //TODO handle logout ajulka
        return null;
    }

    @Override
    public boolean isChallengeInputRequired(Map<String, Object> inputParams) {
        //we still require input, if we do not have redirect response key.
        return !inputParams.containsKey(REDIRECT_RESPONSE_KEY) || inputParams.containsKey(MOBILE_SECURITY_EXCEPTION);
    }

    @Override
    public OMAuthenticationCompletionHandler getCompletionHandlerImpl() {
        return null;
    }
}
