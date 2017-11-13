/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.webview;

import android.annotation.TargetApi;
import android.graphics.Bitmap;
import android.net.Uri;
import android.net.http.SslError;
import android.os.Build;
import android.os.Handler;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Set;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.StringUtils;

import static oracle.idm.mobile.util.URLUtils.areUrisEqual;
import static oracle.idm.mobile.util.URLUtils.areUrlsEqual;

/**
 * As there is no callback in WebViewClient to explicitly find if a page has
 * finished loading, the following logic is applied: If onPageStarted
 * callback is not called within TIME_BETWEEN_PAGE_START_AND_FINISH after
 * onPageFinished is called, then it is assumed that logout url is
 * completely loaded. Also, a maximum time of MAX_TIME_FOR_LOGOUT is allowed
 * for the logout call to be finished.
 *
 * If logout success/failure urls are given, they are used instead of the above
 * logic.
 *
 */
public class LogoutWebViewClient extends BaseWebViewClient {
    private final String TAG = LogoutWebViewClient.class.getSimpleName();
    private static final String DEFAULT_CONFIRM_LOGOUT_ID = "Confirm";
    /*
     * The following Javascript code is minified using Google Closure Compiler.
     * The original javascript code (which is not minified) is present in
     * idmmobile\Headless\Android\IDMMobileSDKNotShippedResources\
     */
    private static final String CONFIRM_LOGOUT_AUTOMATICALLY = "function oracle_access_confirmLogout(a){if(a){a=a.split(',');for(var b=0;b<a.length;b++){var c=document.getElementById(a[b]);if(c){c.click();break}}}};";
    private static final int TIME_BETWEEN_PAGE_START_AND_FINISH = 3000; // milli
    // seconds
    private static final int DEFAULT_LOGOUT_TIMEOUT = 30; // seconds
    private WebView webView;
    private OMMobileSecurityService mss;
    private Handler handler;
    private CheckLogoutDoneRunnable checkLogoutDoneRunnable;
    private CheckLogoutMaxTimeRunnable checkLogoutMaxTimeRunnable;
    private int logoutTimeout = DEFAULT_LOGOUT_TIMEOUT;
    /* This is the timeout for each page redirect. */
    private boolean logoutDone;
    private boolean isLogoutCall;

    private boolean receivedErrorLoadingUrl;
    private URL logoutSuccessUrl;
    private URI logoutSuccessUri;
    private boolean logoutSuccessUriAbsent;
    private URL logoutFailureUrl;
    private boolean confirmLogoutAutomatically;
    private String confirmLogoutButtonIds;

    public LogoutWebViewClient(WebView webView, WebViewClient appWebViewClient, OMMobileSecurityService mss,
                               Handler handler, OMMobileSecurityConfiguration config, int logoutTimeout,
                               boolean isLogoutCall) {
        super(appWebViewClient);
        this.webView = webView;
        this.mss = mss;
        this.handler = handler;
        this.logoutSuccessUrl = config.getLogoutSuccessUrl();
        if (logoutSuccessUrl == null) {
            this.logoutSuccessUri = config.getLogoutSuccessUri();
        }
        this.logoutSuccessUriAbsent = (logoutSuccessUrl == null && logoutSuccessUri == null);
        this.logoutFailureUrl = config.getLogoutFailureUrl();
        this.confirmLogoutAutomatically = config.isConfirmLogoutAutomatically();
        Set<String> confirmLogoutButtonIdSet = config.getConfirmLogoutButtonId();
        confirmLogoutButtonIdSet.add(DEFAULT_CONFIRM_LOGOUT_ID);
        this.confirmLogoutButtonIds = StringUtils.convertToString(confirmLogoutButtonIdSet);
        if (logoutTimeout > 0) {
            this.logoutTimeout = logoutTimeout;
        }
        this.isLogoutCall = isLogoutCall;
    }

    @SuppressWarnings("deprecation")
    @Override
    public void onReceivedError(WebView view, int errorCode,
                                String description, String failingUrl) {
        receivedErrorLoadingUrl = true;
        super.onReceivedError(view, errorCode, description, failingUrl);
        /* In case of IDCS logout, since we give redirect uri as the OAuth redirect endpoint,
        * server redirects to the same. This may result in ERROR_UNSUPPORTED_SCHEME.
        * So, have the following.*/
        if (errorCode == WebViewClient.ERROR_UNSUPPORTED_SCHEME &&
                logoutSuccessUri != null &&
                failingUrl != null &&
                Uri.parse(failingUrl).getScheme().equals(logoutSuccessUri.getScheme())) {
            onLogoutSuccessful();
        } else {
            onLogoutFailed(OMErrorCode.LOGOUT_FAILED, description);
        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    @Override
    public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
        receivedErrorLoadingUrl = true;
        super.onReceivedError(view, request, error);
        /* In case of IDCS logout, since we give redirect uri as the OAuth redirect endpoint,
        * server redirects to the same. This may result in ERROR_UNSUPPORTED_SCHEME.
        * So, have the following.*/
        if (error.getErrorCode() == WebViewClient.ERROR_UNSUPPORTED_SCHEME &&
                logoutSuccessUri != null &&
                request.getUrl().getScheme().equals(logoutSuccessUri.getScheme())) {
            onLogoutSuccessful();
        } else {
            onLogoutFailed(OMErrorCode.LOGOUT_FAILED, (String) error.getDescription());
        }

    }

    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        OMLog.error(TAG, "onReceivedSslError: " + error.toString());
        receivedErrorLoadingUrl = true;
        handler.cancel();
        onLogoutFailed(OMErrorCode.LOGOUT_FAILED, "Unexpected: Received SSL error while loading logout url");
    }

    @Override
    public void onPageStarted(WebView view, String url, Bitmap favicon) {
        if (logoutSuccessUriAbsent) {
            if (checkLogoutDoneRunnable != null) {
                handler.removeCallbacks(checkLogoutDoneRunnable, null);
            }
            if (checkLogoutMaxTimeRunnable == null) {
                checkLogoutMaxTimeRunnable = new CheckLogoutMaxTimeRunnable();
                handler.postDelayed(checkLogoutMaxTimeRunnable,
                        logoutTimeout * 1000);
            }
        } else {
            if (logoutDone) {
                Log.d(TAG,
                        "Success or Failure url already hit. Hence, not loading the page.");
                view.stopLoading();
                super.onPageStarted(view, url, favicon);
                return;
            }
            if (receivedErrorLoadingUrl) {
                receivedErrorLoadingUrl = false;
            }
        }
        super.onPageStarted(view, url, favicon);

    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    @Override
    public void onPageFinished(WebView view, String url) {
        OMCookieManager.getInstance().flush(webView.getContext());
        if (logoutSuccessUriAbsent) {
            handler.removeCallbacks(checkLogoutMaxTimeRunnable, null);
            if (checkLogoutDoneRunnable == null) {
                checkLogoutDoneRunnable = new CheckLogoutDoneRunnable();
            }

            boolean runnablePlaced = handler
                    .postDelayed(checkLogoutDoneRunnable,
                            TIME_BETWEEN_PAGE_START_AND_FINISH);
            if (!runnablePlaced) {
                Log.e(TAG,
                        "CheckLogoutDoneRunnable is not placed in MessageQueue!");
                onLogoutFailed(OMErrorCode.INTERNAL_ERROR, null);
            } else if (confirmLogoutAutomatically) {
                confirmLogout(view);
            }
        } else {
            Log.d(TAG + "_onPageFinished", "ReceivedErrorLoadingUrl = "
                    + receivedErrorLoadingUrl);
            if (receivedErrorLoadingUrl) {
            /*
             * In these scenarios, the current url can be logoutSuccessUrl.
             * But, this should not result in successful logout.
             * Hence, returning from here.
             */
                return;
            }
            if (logoutDone) {
                Log.d(TAG,
                        "Success or Failure url already hit. Hence, not loading the page.");
                view.stopLoading();
                return;
            }
            URL currentURL = null;
            URI currentURI = null;
            try {
                currentURL = new URL(url);
            } catch (MalformedURLException e) {
                try {
                    currentURI = new URI(url);
                } catch (URISyntaxException e1) {
                    Log.e(TAG, e1.getMessage(), e1);
                }

            }

            if ((currentURL!=null && logoutSuccessUrl != null && areUrlsEqual(currentURL, logoutSuccessUrl)) ||
                    (currentURI != null && logoutSuccessUri!= null && areUrisEqual(currentURI, logoutSuccessUri, false)) ) {
                onLogoutSuccessful();
            } else if (currentURL!=null && logoutFailureUrl != null && areUrlsEqual(currentURL, logoutFailureUrl)) {
                    /*Even though user has cancelled logout, we do clear all session cookies.
                    * This is done to avoid making additional changes for this specific use-case.
                    * Also, SIM has not enabled cancel button in logout consent screen.*/
                onLogoutFailed(OMErrorCode.LOGOUT_FAILED, "Logout Failure url is hit");
            } else if (confirmLogoutAutomatically) {
                confirmLogout(view);
            }
        }
        super.onPageFinished(view, url);
    }

    private void confirmLogout(WebView view) {
        String script = "javascript: " + CONFIRM_LOGOUT_AUTOMATICALLY + "javascript: oracle_access_confirmLogout('" + confirmLogoutButtonIds + "');";
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            view.evaluateJavascript(script, null);
        } else {
            view.loadUrl(script);
        }
    }

    private class CheckLogoutDoneRunnable implements Runnable {

        @Override
        public void run() {
            onLogoutSuccessful();
        }

    }

    private class CheckLogoutMaxTimeRunnable implements Runnable {

        @Override
        public void run() {
            Log.e(TAG, "Logout failed as connection timed out.");
            onLogoutFailed(OMErrorCode.LOGOUT_TIMED_OUT, null);
        }

    }

    private void onLogoutSuccessful() {
        if (logoutDone) {
            return;
        }
        performCleanup();
        mss.onLogoutCompleted();
        logoutDone = true;
        if (isLogoutCall) {
            OMMobileSecurityServiceCallback callback = mss.getCallback();
            if (callback != null) {
                callback.onLogoutCompleted(mss, null);
            } else {
                OMLog.error(TAG, "FATAL: Cannot invoke onLogoutCompleted as app callback is not available with SDK");
            }
        }

    }

    private void onLogoutFailed(OMErrorCode errorCode, String msgParam) {
        if (logoutDone) {
            return;
        }
        performCleanup();
        if (logoutSuccessUriAbsent) {
            handler.removeCallbacks(checkLogoutDoneRunnable, null);
        }

        OMCookieManager.getInstance().removeSessionCookies(mss.getApplicationContext());
        mss.onLogoutCompleted();
        logoutDone = true;
        if (isLogoutCall) {
            OMMobileSecurityServiceCallback callback = mss.getCallback();
            if (callback != null) {
                callback.onLogoutCompleted(
                        mss,
                        new OMMobileSecurityException(errorCode, msgParam));
            }
        }
    }

    private void performCleanup() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            WebView.clearClientCertPreferences(null);
        }

        OMLog.debug(TAG, "Clearing SSL preferences");
        webView.clearSslPreferences();

        webView.clearHistory();
        if (logoutSuccessUriAbsent) {
            handler.removeCallbacks(checkLogoutMaxTimeRunnable, null);
        }
    }
}
