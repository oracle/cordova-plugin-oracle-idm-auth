/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.webview;

import android.graphics.Bitmap;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.AuthenticationServiceManager;
import oracle.idm.mobile.auth.OAuthConnectionsUtil;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;

/**
 * OAuth WebviewConfiguration handler
 */
public class OAuthWebViewConfigurationHandler extends LoginWebViewHandler {

    private static final String TAG = OAuthWebViewConfigurationHandler.class.getName();
    private OMOAuthMobileSecurityConfiguration mConfig;
    protected boolean isClientRegistration;

    @SuppressWarnings("unused")
    private OAuthWebViewConfigurationHandler() {
        super();
        // only for testing.
    }

    public OAuthWebViewConfigurationHandler(AuthenticationServiceManager asm, boolean isClientRegistration) {
        super(asm);
        mConfig = (OMOAuthMobileSecurityConfiguration) asm
                .getMSS().getMobileSecurityConfig();
        this.isClientRegistration = isClientRegistration;
    }

    @Override
    public void configureView(Map<String, Object> inputParams,
                              final AuthServiceInputCallback callback) {
        OMLog.info(TAG, "configureView");
        super.configureView(inputParams, callback);
        if (mConfig.getOAuthBrowserMode() == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
            WebView appWebView = (WebView) inputParams.get(OMSecurityConstants.Challenge.WEBVIEW_KEY);
            WebViewClient appWebViewClient = (WebViewClient) inputParams.get(OMSecurityConstants.Challenge.WEBVIEW_CLIENT_KEY);
            appWebView.getSettings().setJavaScriptEnabled(true);
            String redirectEP = mConfig.getOAuthRedirectEndpoint();
            if (redirectEP != null) {
                OMLog.info(TAG, "Redirect EP: " + redirectEP);
                appWebView.setWebViewClient(new OAuthWebViewClient(callback, inputParams, redirectEP, appWebViewClient));
                String loginLoadURL;
                OAuthConnectionsUtil oauthConnUtil = asm.getOAuthConnectionsUtil();
                try {
                    loginLoadURL = isClientRegistration ?
                            oauthConnUtil.getFrontChannelRequestForClientRegistration() :
                            oauthConnUtil.getFrontChannelRequestForAccessToken(true);
                    OMLog.info(TAG, "Loading login load  URL in the webview " + loginLoadURL);
                    appWebView.loadUrl(loginLoadURL);
                } catch (UnsupportedEncodingException e) {
                    OMLog.error(TAG, "Login Load URL not populated properly in the input params", e);
                    callback.onError(OMErrorCode.INTERNAL_ERROR);
                } catch (NoSuchAlgorithmException e) {
                    OMLog.error(TAG, "Login Load URL not populated properly in the input params", e);
                    callback.onError(OMErrorCode.INTERNAL_ERROR);
                }
            } else {
                OMLog.error(TAG, "Mis-configuration, Redirect EP is required!!");
                callback.onError(OMErrorCode.INTERNAL_ERROR);
            }
        }
    }

    /**
     * Webview client impl for OAuth 3-legged flows.
     */
    private class OAuthWebViewClient extends LoginWebViewClient {
        private AuthServiceInputCallback callback;
        private Map<String, Object> inputParams;
        private String redirectEndpoint;
        private boolean redirectReported = false;

        OAuthWebViewClient(AuthServiceInputCallback callback,
                           Map<String, Object> inputParams, String redirectEndpoint,
                           WebViewClient webviewClient) {
            super(webviewClient);
            this.callback = callback;
            this.inputParams = inputParams;
            this.redirectEndpoint = redirectEndpoint;
        }

        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            OMLog.info(TAG, "onPageStarted: " + url);

            /*
             * In case of Android 2.3.3 and less, shouldOverrideUrlLoading may
             * not be called sometimes. So, have this check here to detect the
             * loading of loginSuccessUrl
             */

            if (url.startsWith(redirectEndpoint) && !isRedirectReported()) {
                OMLog.debug(TAG, "Response from OAuth Server to redirect URL: " +
                        url);
                view.stopLoading();
                inputParams.put(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY,
                        url);
                redirectReported = true;
                callback.onInput(inputParams);
            }
            super.onPageStarted(view, url, favicon);
        }

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            OMLog.info(TAG, "shouldOverrideUrlLoading: " + url);
            if (url.startsWith(redirectEndpoint) && !isRedirectReported()) {
                OMLog.debug(TAG, "Response from OAuth Server to redirect URL: " + url);
                inputParams.put(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY,
                        url);
                redirectReported = true;
                callback.onInput(inputParams);
                /*The below line makes sure that app's WebViewClient
                * gets this callback. But, SDK always returns true
                * irrespective of the return value given by the
               * app's WebViewClient.Returning true makes sure that
               * webview does not proceed with loading this url.*/
                super.shouldOverrideUrlLoading(view, url);
                return true;
            } else {
                return super.shouldOverrideUrlLoading(view, url);
            }
        }

        boolean isRedirectReported() {
            return redirectReported;
        }
    }
}
