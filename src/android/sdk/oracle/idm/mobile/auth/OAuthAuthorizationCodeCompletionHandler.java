/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.net.Uri;
import android.webkit.WebView;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.webview.OAuthWebViewConfigurationHandler;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;

/**
 * Completion handler for OAuth Authorization code grant type
 *
 * @since 11.1.2.3.1
 */
class OAuthAuthorizationCodeCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = OAuthAuthorizationCodeCompletionHandler.class.getSimpleName();

    protected AuthServiceInputCallback mAuthServiceCallback;
    protected AuthenticationServiceManager mASM;
    private OMOAuthMobileSecurityConfiguration mOAuthConfig;
    private OAuthWebViewConfigurationHandler mWebviewConfigurator;
    protected boolean isClientRegistration;

    protected OAuthAuthorizationCodeCompletionHandler(AuthenticationServiceManager asm, OMMobileSecurityConfiguration config, boolean isClientRegistration, OMMobileSecurityServiceCallback appCallback) {
        super(config, appCallback);
        mASM = asm;
        mOAuthConfig = (OMOAuthMobileSecurityConfiguration) mConfig;
        mWebviewConfigurator = new OAuthWebViewConfigurationHandler(mASM, isClientRegistration);
    }

    @Override
    protected void createChallengeRequest(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        mAuthServiceCallback = authServiceCallback;
        mAppCallback.onAuthenticationChallenge(mss, challenge, this);
    }

    @Override
    public void proceed(Map<String, Object> responseFields) {
        OMLog.info(TAG, "proceed");
        try {
            validateResponseFields(responseFields);
            if (mOAuthConfig.getOAuthBrowserMode() == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
                mWebviewConfigurator.configureView(responseFields, mAuthServiceCallback);
            } else {
                mAuthServiceCallback.onInput(responseFields);
            }
        } catch (OMMobileSecurityException e) {
            OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
            mAuthServiceCallback.onError(e.getError());
        }
    }

    @Override
    public void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {
        if (mOAuthConfig.getOAuthBrowserMode() == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
            if (responseFields.containsKey(OMSecurityConstants.Challenge.WEBVIEW_KEY)) {
                Object webViewObj = responseFields.get(OMSecurityConstants.Challenge.WEBVIEW_KEY);
                if (webViewObj instanceof WebView) {
                    return;
                }
            }
        } else {
            //in case of external browser we expect redirect response URL.
            Object redirectResponse = responseFields.get(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY);
            if (redirectResponse instanceof String) {
                return;
            } else if (redirectResponse instanceof Uri) {
                return;
            }
        }
        throw new OMMobileSecurityException(OMErrorCode.INVALID_CHALLENGE_INPUT_RESPONSE);
    }

    @Override
    public void cancel() {
        OMLog.debug(TAG, "cancel");
        if (mWebviewConfigurator != null) {
            mWebviewConfigurator.onCancel();
        }
        if (mAuthServiceCallback != null) {
            mAuthServiceCallback.onCancel();
        } else {
            OMLog.error(TAG, "Something went wrong can not report the cancel operation to app");
        }
    }
}
