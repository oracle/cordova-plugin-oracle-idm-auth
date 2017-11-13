/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.os.Handler;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONException;

import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OMAuthenticationContext.AuthenticationProvider;
import oracle.idm.mobile.auth.logout.FedAuthLogoutCompletionHandler;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.auth.webview.LogoutWebViewClient;
import oracle.idm.mobile.auth.webview.WebViewAuthServiceInputCallbackImpl;
import oracle.idm.mobile.configuration.OMFederatedMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.GenericsUtils;

/**
 * @hide
 */
public class FederatedAuthenticationService extends AuthenticationService implements ChallengeBasedService {
    private static final String TAG = FederatedAuthenticationService.class.getSimpleName();
    private OMFederatedMobileSecurityConfiguration mConfig;

    protected FederatedAuthenticationService(
            AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler, OMLogoutCompletionHandler logoutHandler) {
        super(asm, handler, logoutHandler);
        OMLog.info(TAG, "initialized");
        if (asm.getMSS().getMobileSecurityConfig() instanceof OMFederatedMobileSecurityConfiguration) {
            mConfig = ((OMFederatedMobileSecurityConfiguration) asm.getMSS().getMobileSecurityConfig());
        }
    }

    @Override
    public OMAuthenticationChallenge createLoginChallenge() {
        OMAuthenticationChallenge challenge = createCommonChallenge();
        OMLog.info(TAG, "Create Login Challenge : " + challenge.toString());
        return challenge;
    }

    @Override
    public OMAuthenticationChallenge createLogoutChallenge() {
        OMAuthenticationChallenge challenge = createCommonChallenge();
        OMLog.info(TAG, "Create Logout Challenge : " + challenge.toString());
        return challenge;
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
        OMLog.info(OMSecurityConstants.TAG, "isChallengeInputRequired " + result);
        return result;
    }

    @Override
    public OMAuthenticationCompletionHandler getCompletionHandlerImpl() {
        return null;
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        Set<String> requiredCookies = mASM.getMSS().getMobileSecurityConfig().getRequiredTokens();
        Map<String, Object> inputParams = authContext.getInputParams();
        Set<String> visitedUrls = (Set<String>) inputParams
                .get(OMSecurityConstants.Param.VISITED_URLS);
        try {
            if (OMCookieManager.getInstance().hasRequiredCookies(requiredCookies, GenericsUtils.convert(visitedUrls))) {
                boolean parseTokenRelayResponse = mConfig.parseTokenRelayResponse();
                if (parseTokenRelayResponse) {
                    parseTokenRelayResponse(authContext);
                }

                authContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
                OMAuthenticationContext.AuthenticationMechanism authenticationMechanism = (OMAuthenticationContext.AuthenticationMechanism) inputParams
                        .get(OMSecurityConstants.Param.AUTHENTICATION_MECHANISM);
                if (authenticationMechanism != null) {
                    authContext.setAuthenticationMechanism(authenticationMechanism);
                } else {
                    authContext
                            .setAuthenticationMechanism(OMAuthenticationContext.AuthenticationMechanism.FEDERATED);
                }
            } else {
                // fail only if the apps has specified required tokens.
                // this can happen due to the tokens requested not matching
                // Setting AuthenticationProvider so that logout url is invoked
                // properly in this use case, clearing the same in
                // OMAuthenticationContext#clearAllFields()
//                authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
//                OMLog.error(TAG, "Tokens that are requested are not available from the server.");
//                throw new OMMobileSecurityException(OMErrorCode.AUTHENTICATION_FAILED, new InvalidCredentialEvent());
                onAuthenticationFailed(
                        authContext,
                        "Tokens that are requested are not available from the server.",
                        null);
            }
        } catch (URISyntaxException e) {
            OMLog.error(TAG, "Really unexpected, URL loaded in webview is not a proper URL", e);
            authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
            throw new OMMobileSecurityException(OMErrorCode.RFC_NON_COMPLIANT_URI);
        } finally {
            // AuthentcationProvider is being set here to delete the cookies
            // from CookieManger properly, in case of exceptions
            authContext
                    .setAuthenticationProvider(AuthenticationProvider.FEDERATED);
        }
        return null;
    }

    @Override
    public void cancel() {
        OMLog.trace(TAG, "cancel");
        if (mAuthCompletionHandler != null) {
            mAuthCompletionHandler.cancel();
        } else {
            OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
        }
    }

    @Override
    public Type getType() {
        return Type.FED_AUTH_SERVICE;
    }

    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {
        OMLog.info(TAG, "isValid");
        // validateOnline is not needed here as of now.
        if (authContext.getAuthenticationProvider() != AuthenticationProvider.FEDERATED) {
            return true;
        }

        Date sessionExpiry = authContext.getSessionExpiry();
        Date idleTimeExpiry = authContext.getIdleTimeExpiry();
        Date currentTime = Calendar.getInstance().getTime();

        // Non-zero checks for getSessionExpInSecs() and getIdleTimeExpInSecs()
        // added to ignore session/idle time
        // expiry if session/idle timeout value is 0.
        if ((sessionExpiry != null && authContext.getSessionExpInSecs() != 0 && (currentTime
                .after(sessionExpiry) || currentTime.equals(sessionExpiry)))
                || (idleTimeExpiry != null
                && authContext.getIdleTimeExpInSecs() != 0 && (currentTime
                .after(idleTimeExpiry) || currentTime
                .equals(idleTimeExpiry)))) {
            Log.d(TAG + "_isValid", "Idle time or Session time is expired.");
            return false;
        }

        if (authContext.getIdleTimeExpInSecs() > 0) {
            authContext.resetIdleTime();
            Log.d(TAG + "_isValid",
                    "Idle time is reset to : "
                            + authContext.getIdleTimeExpiry());
        }

        if (mConfig.parseTokenRelayResponse()) {
            List<OMToken> tokens = authContext.getTokens(null);
            if (tokens == null || tokens.isEmpty()) {
                return false;
            }
            OAuthToken oAuthToken = (OAuthToken) tokens.get(0);
            if (oAuthToken.isTokenExpired()) {
                return false;
            } else {
                Log.d(TAG, "OAuth token is valid");
            }
        }


        return true;
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, final ASMInputController controller) {
        OMLog.info(TAG, "collectLoginChallengeInput");
        if (!isChallengeInputRequired(inputParams)) {
            //have all the required inputs lets proceed for authentication
            controller.onInputAvailable(inputParams);
        } else {
            mAuthCompletionHandler.createChallengeRequest(mASM.getMSS(), createLoginChallenge(),
                    new WebViewAuthServiceInputCallbackImpl(mASM, controller));
        }
    }


    @Override
    public void logout(final OMAuthenticationContext authContext, final boolean isDeleteUnPwd, final boolean isDeleteCookies, final boolean isDeleteTokens, final boolean isLogoutCall) {
        if (authContext.getAuthenticationProvider() != AuthenticationProvider.FEDERATED) {
            return;
        }

        collectLogoutChallengeInput(authContext.getInputParams(), new AuthServiceInputCallback() {
            @Override
            public void onInput(Map<String, Object> inputs) {
                //Input validation is done in proceed(). Invalid input results in onError being called.
                OMLog.trace(TAG, "Inside AuthServiceInputCallback#onInput");
                authContext.getInputParams().putAll(inputs);
                handleLogout(authContext, isDeleteUnPwd, isDeleteCookies, isDeleteTokens, isLogoutCall);
            }

            @Override
            public void onError(OMErrorCode error) {
                if (error == OMErrorCode.WEB_VIEW_REQUIRED) {
                    OMLog.info(TAG, "Since Login Webview not supplied, simply clear session cookies and report this back to app");
                    removeSessionCookies();
                    reportLogoutCompleted(mASM.getMSS(), isLogoutCall, OMErrorCode.LOGOUT_URL_NOT_LOADED);
                }
            }

            @Override
            public void onCancel() {
                /*Cancel of logout DOES NOT happen as we expect the SDK consumer to always return a webview in which logout url can be loaded.
                  But, to cover the negative scenario of logout cancel, we clear all session cookies. This is because logout can be initiated on
                  idle/session timeout. This should make authContext invalid. If we do not clear cookies just because the webview is not returned by SDK consumer,
                  the next authentication MAY NOT show the login screen as the cookies might still be valid. */

                removeSessionCookies();
                reportLogoutCompleted(mASM.getMSS(), true, OMErrorCode.LOGOUT_URL_NOT_LOADED);
            }
        });
    }

    @Override
    public void collectLogoutChallengeInput(Map<String, Object> inputParams, final AuthServiceInputCallback callback) {
        mLogoutCompletionHandler.createLogoutChallengeRequest(mASM.getMSS(), createLogoutChallenge(), callback);
    }


    @Override
    public void handleLogout(final OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteToken, final boolean isLogoutCall) {
        OMLog.trace(TAG, "Inside handleLogout");
        final URL logoutUrl = mASM.getMSS().getMobileSecurityConfig().getLogoutUrl();
        final Handler handler = ((FedAuthLogoutCompletionHandler) mLogoutCompletionHandler).getAppCallback().getHandler();
        if (handler != null) {
            handler.post(new Runnable() {
                @Override
                public void run() {
                    WebView webView = (WebView) authContext.getInputParams().get(OMSecurityConstants.Challenge.WEBVIEW_KEY);
                    WebViewClient appWebViewClient = (WebViewClient) authContext.getInputParams().get(OMSecurityConstants.Challenge.WEBVIEW_CLIENT_KEY);
                    loadLogoutURL(webView, new LogoutWebViewClient(webView, appWebViewClient, mASM.getMSS(), handler,
                            mConfig, authContext.getLogoutTimeout(), isLogoutCall), logoutUrl.toString());
                   /* webView.getSettings().setJavaScriptEnabled(true);
                    webView.setWebViewClient(new LogoutWebViewClient(webView, appWebViewClient, handler, authContext.getLogoutTimeout(), isLogoutCall));
                    OMLog.trace(TAG, "Loading logout url");
                    webView.loadUrl(logoutUrl.toString());*/
                }
            });
        } else {
            removeSessionCookies();
            reportLogoutCompleted(mASM.getMSS(), isLogoutCall, OMErrorCode.LOGOUT_URL_NOT_LOADED);
           /* OMCookieManager.getInstance().removeSessionCookies(mASM.getApplicationContext());
            OMMobileSecurityService mss = mASM.getMSS();
            OMMobileSecurityServiceCallback callback = mss.getCallback();
            mss.onLogoutCompleted();
            if (isLogoutCall && callback != null) {
                callback.onLogoutCompleted(
                        mss,
                        new OMMobileSecurityException(OMErrorCode.LOGOUT_URL_NOT_LOADED));
            }*/
        }
    }

    private OMAuthenticationChallenge createCommonChallenge() {
        OMAuthenticationChallenge challenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.EMBEDDED_WEBVIEW_REQUIRED);
        updateChallengeWithException(challenge);
        return challenge;
    }

    private void parseTokenRelayResponse(OMAuthenticationContext authContext) throws OMMobileSecurityException {
        Map<String, Object> inputParams = authContext.getInputParams();
        String tokenRelayResponse = (String) inputParams
                .get(OMSecurityConstants.Param.TOKEN_RELAY_RESPONSE);
        if (TextUtils.isEmpty(tokenRelayResponse)) {
            onAuthenticationFailed(authContext,
                    "Token Relay Response is empty", null);
        }
        try {
            OAuthToken oAuthToken = new OAuthToken(tokenRelayResponse);
            List<OAuthToken> oauthTokenList = new ArrayList<>();
            oauthTokenList.add(oAuthToken);
            authContext.setOAuthTokenList(oauthTokenList);
            Log.d(TAG,
                    "Token Relay Response has a valid access token. It is parsed & set in authContext.");
        } catch (JSONException e) {
            onAuthenticationFailed(
                    authContext,
                    "Token Relay Response does not have valid access token",
                    e);
        }
    }

    private void onAuthenticationFailed(OMAuthenticationContext authContext,
                                        String errorMessage, Throwable tr) throws OMMobileSecurityException {
        // AuthentcationProvider is being set here to delete the cookies
        // from CookieManger properly
        authContext.setAuthenticationProvider(AuthenticationProvider.FEDERATED);
        authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
        OMLog.error(TAG, errorMessage, tr);
        throw new OMMobileSecurityException(OMErrorCode.AUTHENTICATION_FAILED);
    }

}
