/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.webview;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Message;
import android.text.TextUtils;
import android.util.Log;
import android.view.KeyEvent;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import oracle.idm.mobile.logging.OMLog;

/**
 * This class just contains methods which MUST simply delegate the control to app's webviewclient.
 * <p>
 */
public class BaseWebViewClient extends WebViewClient {
    private final String TAG = BaseWebViewClient.class.getSimpleName();
    private Context context;
    private WebViewClient origAppWebViewClient;

    private enum OMAUrlScheme {
        ORACLE_MOBILE_AUTHENTICATOR("oraclemobileauthenticator"),
        ORACLE_AUTHENTICATOR("oracleauthenticator"),
        OTP_AUTH("otpauth"),
        OMA("oma");

        private String value;

        OMAUrlScheme(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    // for testing.
    BaseWebViewClient() {

    }

    public BaseWebViewClient(Context context, WebViewClient origAppWebViewClient) {
        this.context = context;
        this.origAppWebViewClient = origAppWebViewClient;
    }

    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        OMLog.trace(TAG, "shouldOverrideUrlLoading: url = " + url);
        if (isUrlOfOMAApp(url)) {
            /* This use-case is Mobile App enrollment in case
             * of IDCS. WebView does not have support to launch
             * the app by its own. Hence, below code launches
             * the OMA app.*/
            Intent omaIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            if (context == null) {
                Log.e(TAG, "context is null. Cannot launch OMA app");
                return false;
            }
            if (omaIntent.resolveActivity(context.getPackageManager()) == null) {
                Log.e(TAG, "No apps are found with the url scheme to be loaded.");
                return false;
            }
            context.startActivity(omaIntent);
            if (origAppWebViewClient != null) {
                /* SDK anyways overrides URL loading by returning true.
                 * But, SDK lets the app know through origAppWebViewClient
                 * as done below.*/
                origAppWebViewClient.shouldOverrideUrlLoading(view, url);
            }
            return true;
        } else {
            if (origAppWebViewClient != null) {
                return origAppWebViewClient.shouldOverrideUrlLoading(view, url);
            } else {
                return super.shouldOverrideUrlLoading(view, url);
            }
        }
    }

    private boolean isUrlOfOMAApp(String url) {
        if (TextUtils.isEmpty(url)) {
            return false;
        }
        if (url.startsWith(OMAUrlScheme.OMA.getValue())
                || url.startsWith(OMAUrlScheme.ORACLE_AUTHENTICATOR.getValue())
                || url.startsWith(OMAUrlScheme.ORACLE_MOBILE_AUTHENTICATOR.getValue())
                || url.startsWith(OMAUrlScheme.OTP_AUTH.getValue())) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        OMLog.trace(TAG, "onPageStarted: url = " + url);
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onPageStarted(view, url, favicon);
        } else {
            super.onPageStarted(view, url, favicon);
        }
    }

    @Override
    public void onPageFinished(WebView view, String url) {
        OMLog.trace(TAG, "onPageFinished: url = " + url);
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onPageFinished(view, url);
        } else {
            super.onPageFinished(view, url);
        }
    }

    @Override
    public void onLoadResource(WebView view, String url) {
        OMLog.trace(TAG, "onLoadResource: url = " + url);
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onLoadResource(view, url);
        } else {
            super.onLoadResource(view, url);
        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public void onPageCommitVisible(WebView view, String url) {
        OMLog.trace(TAG, "onPageCommitVisible: url = " + url);
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onPageCommitVisible(view, url);
        } else {
            super.onPageCommitVisible(view, url);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public WebResourceResponse shouldInterceptRequest(WebView view, String url) {
        OMLog.trace(TAG, "shouldInterceptRequest: url = " + url);
        if (origAppWebViewClient != null) {
            return origAppWebViewClient.shouldInterceptRequest(view, url);
        } else {
            return super.shouldInterceptRequest(view, url);
        }
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
        OMLog.trace(TAG, "shouldInterceptRequest");
        if (origAppWebViewClient != null) {
            return origAppWebViewClient.shouldInterceptRequest(view, request);
        } else {
            return super.shouldInterceptRequest(view, request);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onTooManyRedirects(WebView view, Message cancelMsg, Message continueMsg) {
        OMLog.trace(TAG, "onTooManyRedirects");
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onTooManyRedirects(view, cancelMsg, continueMsg);
        } else {
            super.onTooManyRedirects(view, cancelMsg, continueMsg);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onReceivedError(WebView view, int errorCode, String description, String failingUrl) {
        OMLog.trace(TAG, "onReceivedError deprecated: "
                + " errorCode = " + errorCode
                + " description = " + description
                + " failingUrl = " + failingUrl);
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onReceivedError(view, errorCode, description, failingUrl);
        } else {
            super.onReceivedError(view, errorCode, description, failingUrl);
        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
        OMLog.trace(TAG, "onReceivedError: "
                + " code: " + error.getErrorCode()
                + " description: " + error.getDescription()
                + " failingUrl = " + request.getUrl());
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onReceivedError(view, request, error);
        } else {
            super.onReceivedError(view, request, error);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
        OMLog.trace(TAG, "onReceivedHttpError: "
                + " Status Code: " + errorResponse.getStatusCode()
                + " url: " + request.getUrl());
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onReceivedHttpError(view, request, errorResponse);
        } else {
            super.onReceivedHttpError(view, request, errorResponse);
        }
    }

    @Override
    public void onFormResubmission(WebView view, Message dontResend, Message resend) {
        OMLog.trace(TAG, "onFormResubmission");
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onFormResubmission(view, dontResend, resend);
        } else {
            super.onFormResubmission(view, dontResend, resend);
        }
    }

    @Override
    public void doUpdateVisitedHistory(WebView view, String url, boolean isReload) {
        OMLog.trace(TAG, "doUpdateVisitedHistory: url = " + url);
        if (origAppWebViewClient != null) {
            origAppWebViewClient.doUpdateVisitedHistory(view, url, isReload);
        } else {
            super.doUpdateVisitedHistory(view, url, isReload);
        }
    }

    @Override
    public boolean shouldOverrideKeyEvent(WebView view, KeyEvent event) {
        OMLog.trace(TAG, "shouldOverrideKeyEvent");
        if (origAppWebViewClient != null) {
            return origAppWebViewClient.shouldOverrideKeyEvent(view, event);
        } else {
            return super.shouldOverrideKeyEvent(view, event);
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onUnhandledKeyEvent(WebView view, KeyEvent event) {
        OMLog.trace(TAG, "onUnhandledKeyEvent");
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onUnhandledKeyEvent(view, event);
        } else {
            super.onUnhandledKeyEvent(view, event);
        }
    }

    @Override
    public void onScaleChanged(WebView view, float oldScale, float newScale) {
        OMLog.trace(TAG, "onScaleChanged");
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onScaleChanged(view, oldScale, newScale);
        } else {
            super.onScaleChanged(view, oldScale, newScale);
        }
    }

    @Override
    public void onReceivedLoginRequest(WebView view, String realm, String account, String args) {
        OMLog.trace(TAG, "onReceivedLoginRequest");
        if (origAppWebViewClient != null) {
            origAppWebViewClient.onReceivedLoginRequest(view, realm, account, args);
        } else {
            super.onReceivedLoginRequest(view, realm, account, args);
        }
    }
}
