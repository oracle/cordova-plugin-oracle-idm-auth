/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.webview;

import android.annotation.TargetApi;
import android.graphics.Bitmap;
import android.os.Build;
import android.os.Handler;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.AuthenticationServiceManager;
import oracle.idm.mobile.configuration.OMFederatedMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.CustomLinkedHashSet;
import oracle.idm.mobile.util.StringUtils;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.WEBVIEW_CLIENT_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Param.TOKEN_RELAY_RESPONSE;
import static oracle.idm.mobile.util.URLUtils.areUrlsEqual;


/**
 * @hide
 */
public class FederatedWebViewHandler extends LoginWebViewHandler
{
    private static final String TAG = FederatedWebViewHandler.class.getSimpleName();
    /*
     * The following Javascript code is minified using Google Closure Compiler.
     * The original javascript code (which is not minified) is present in
     * idmmobile\Headless\Android\IDMMobileSDKNotShippedResources\
     */
    private static final String USERNAME_EXTRACTION_JAVASCRIPT = "\"oracle_access_interceptUsernameOnSubmit\"!==HTMLFormElement.prototype.submit.name&&(HTMLFormElement.prototype.originalSubmit=HTMLFormElement.prototype.submit);HTMLFormElement.prototype.submit=oracle_access_interceptUsernameOnSubmit;\"oracle_access_interceptUsernameOnXHROpen\"!==XMLHttpRequest.prototype.open.name&&(XMLHttpRequest.prototype.originalOpen=XMLHttpRequest.prototype.open);XMLHttpRequest.prototype.open=oracle_access_interceptUsernameOnXHROpen;" +
            "\"oracle_access_interceptUsernameOnXHRSend\"!==XMLHttpRequest.prototype.send.name&&(XMLHttpRequest.prototype.originalSend=XMLHttpRequest.prototype.send);XMLHttpRequest.prototype.send=oracle_access_interceptUsernameOnXHRSend;window.addEventListener(\"submit\",function(a){oracle_access_interceptUsername.call(this,a,!1)},!0);var oracle_access_usernameParams;function oracle_acess_setUsernameParams(a){\"undefined\"!=typeof a&&(oracle_access_usernameParams=a.split(\",\"))}" +
            "function oracle_access_interceptUsernameOnSubmit(a){oracle_access_interceptUsername.call(this,a,!0)}function oracle_access_interceptUsername(a,b){var c;c=a instanceof Event&&\"undefined\"!=typeof a?a.target:this;oracle_access_interceptUsernameFromForm(c);b&&c.originalSubmit()}" +
            "function oracle_access_interceptUsernameFromForm(a){if(a instanceof HTMLFormElement)for(i=0;i<a.elements.length;i++){var b=a.elements[i].name,c=a.elements[i].type,b=b.toLocaleLowerCase();if((\"text\"==c||\"email\"==c)&&oracle_access_containsUsername(b)&&\"undefined\"!=typeof a.elements[i].value&&null!==a.elements[i].value){window.FederatedJSI.setUsername(a.elements[i].value);break}}}" +
            "function oracle_access_interceptUsernameOnXHROpen(a,b,c,d,e){\"undefined\"!=typeof d&&null!==d&&window.FederatedJSI.setUsername(d);this.originalOpen(a,b,c,d,e)}function oracle_access_interceptUsernameOnXHRSend(a){if(oracle_access_containsUsername(a)){var b=oracle_access_parseUsername(a);\"undefined\"!=typeof b&&null!==b&&window.FederatedJSI.setUsername(b)}this.originalSend(a)}" +
            "function oracle_access_containsUsername(a){if(\"undefined\"!=typeof oracle_access_usernameParams&&null!==oracle_access_usernameParams&&\"undefined\"!=typeof a&&null!==a&&(\"string\"===typeof a||a instanceof String))for(var b=0;b<oracle_access_usernameParams.length;b++)if(-1!=a.indexOf(oracle_access_usernameParams[b].toLocaleLowerCase()))return!0;return!1}" +
            "function oracle_access_parseUsername(a){if(\"undefined\"!=typeof a&&null!==a&&(\"string\"===typeof a||a instanceof String)){a=a.split(\"&\");for(var b=0;b<a.length;b++){var c=a[b].split(\"=\");if(oracle_access_containsUsername(c[0]))return c[1]}}};";
    private static final String PARSE_JSON_RESPONSE_JAVASCRIPT = "function parseJSONResponse(){var a=document.getElementsByTagName('pre');return 0<a.length?a[0].innerHTML:document.getElementsByTagName('body')[0].innerHTML};";
    private static final String SET_TOKEN_RELAY_RESPONSE_JAVASCRIPT = "javascript:window.FederatedJSI.setTokenRelayResponse(parseJSONResponse());";
    private final String usernameParamNamesStr;

    private OMFederatedMobileSecurityConfiguration mConfig;
    private boolean javascriptInterfaceBroken;
    private Set<String> defaultUsernameParamNamesSet;

    @SuppressWarnings("unused")
    private FederatedWebViewHandler()
    {
        super();
        // only for testing.
        usernameParamNamesStr = null;
    }

    public FederatedWebViewHandler(AuthenticationServiceManager asm)
    {
        super(asm);

        OMMobileSecurityConfiguration mobileSecurityConfiguration = asm
                .getMSS().getMobileSecurityConfig();
        if (mobileSecurityConfiguration instanceof OMFederatedMobileSecurityConfiguration) {
            mConfig = (OMFederatedMobileSecurityConfiguration) mobileSecurityConfiguration;
        }
        /*
         * Javascript interface is broken in Gingerbread. Hence, SDK does not
         * add Javascript interface in Gingerbread to extract username.
         */
        if (Build.VERSION.SDK_INT != Build.VERSION_CODES.GINGERBREAD
                && Build.VERSION.SDK_INT != Build.VERSION_CODES.GINGERBREAD_MR1
                && mConfig != null)
        {
            javascriptInterfaceBroken = false;

            Set<String> usernameParamNamesSet;
            Set<String> moreUsernameParamNames = mConfig.getUsernameParamNames();
            if (moreUsernameParamNames != null)
            {
                usernameParamNamesSet = new HashSet<>(getDefaultUsernameParamNamesSet());
                usernameParamNamesSet.addAll(moreUsernameParamNames);
            }
            else
            {
                usernameParamNamesSet = getDefaultUsernameParamNamesSet();
            }

            this.usernameParamNamesStr = StringUtils.convertToString(usernameParamNamesSet);
        }
        else
        {
            javascriptInterfaceBroken = true;
            usernameParamNamesStr = null;
        }

    }

    @Override
    public void configureView(Map<String, Object> inputParams,
                              final AuthServiceInputCallback callback)
    {
        super.configureView(inputParams, callback);

        WebView webView = (WebView) inputParams.get(OMSecurityConstants.Challenge.WEBVIEW_KEY);

        String userAgentHeader = mConfig.getUserAgentHeaderString();
        if (!TextUtils.isEmpty(userAgentHeader))
        {
            Log.d(TAG, "Setting user agent as : " + userAgentHeader);
            webView.getSettings().setUserAgentString(userAgentHeader);
        }


        Object webViewClientObj = inputParams.get(WEBVIEW_CLIENT_KEY);
        WebViewClient origAppWebViewClient = null;
        if(webViewClientObj instanceof WebViewClient) {
            origAppWebViewClient = (WebViewClient) webViewClientObj;
        }

        FederatedWebViewClient federatedWebViewClient = new FederatedWebViewClient(
                callback, inputParams, mConfig.getLoginSuccessUrl(),
                mConfig.getLoginFailureUrl(), origAppWebViewClient);
        webView.setWebViewClient(federatedWebViewClient);
        if (!javascriptInterfaceBroken)
        {
            /*
             * Not adding Javascript Interface in Android 2.3 as the
             * Javascript-Java bridge is broken in Android 2.3.
             */
            webView.addJavascriptInterface(
                    new FederatedJavascriptInterface(asm.getMSS().getCallback().getHandler(), federatedWebViewClient),
                    "FederatedJSI");
        }
        webView.loadUrl(mConfig.getAuthenticationURL().toString());
    }

    @Override
    public void onCancel() {
        OMLog.trace(TAG, "onCancel");
        super.onCancel();
    }

    class FederatedWebViewClient extends LoginWebViewClient
    {
        private AuthServiceInputCallback callback;
        private URL loginSuccessUrl;
        private URL loginFailureUrl;
        private boolean loginSuccessFailureUrlHit = false;
        private Set<String> visitedUrls;
        private boolean parseTokenRelayResponse;
        private boolean receivedErrorLoadingUrl;
        boolean isKitKatOrAbove = false;

        @SuppressWarnings("unused")
        FederatedWebViewClient()
        {
            // for testing.
            super();
        }

        /**
         * It is MANDATORY that we perform authentication related logic here and then call the corresponding methods in the webview client created by the app [@param origAppWebViewClient].
         *
         * @param callback
         * @param inputParams
         * @param loginSuccessUrl
         * @param loginFailureUrl
         * @param origAppWebViewClient
         */
        FederatedWebViewClient(AuthServiceInputCallback callback,
                Map<String, Object> inputParams, URL loginSuccessUrl, URL loginFailureUrl, WebViewClient origAppWebViewClient)
        {
            super(origAppWebViewClient);
            this.callback = callback;
            this.inputParams = inputParams;
            this.loginSuccessUrl = loginSuccessUrl;
            this.loginFailureUrl = loginFailureUrl;
            visitedUrls = new CustomLinkedHashSet<>();
            this.parseTokenRelayResponse = mConfig.parseTokenRelayResponse();

            isKitKatOrAbove = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT);
        }

        @Override
        public void onPageStarted(WebView view, String url, Bitmap favicon)
        {
            Log.d(TAG, "onPageStarted: " + url);
            if (loginSuccessFailureUrlHit)
            {
                Log.d(TAG,
                        "Success or Failure url already hit. Hence, not loading the page.");
                view.stopLoading();
                super.onPageStarted(view, url, favicon);
                return;
            }
            if (receivedErrorLoadingUrl)
            {
                receivedErrorLoadingUrl = false;
            }

            visitedUrls.add(url);
            super.onPageStarted(view, url, favicon);
        }

        @Override
        public void onPageFinished(WebView view, String url)
        {
            super.onPageFinished(view, url);
            Log.d(TAG + "_onPageFinished", "ReceivedErrorLoadingUrl = "
                    + receivedErrorLoadingUrl + " AuthenticationCancelled = "
                    + authenticationCancelled);
            if (receivedErrorLoadingUrl || authenticationCancelled)
            {
                /*
                 * In these scenarios, the current url can be loginSuccessUrl.
                 * But, this should not result in successful authentication.
                 * Hence, returning from here.
                 */
                return;
            }
            if (loginSuccessFailureUrlHit)
            {
                Log.d(TAG,
                        "Success or Failure url already hit. Hence, not loading the page.");
                view.stopLoading();
                return;
            }
            if (!javascriptInterfaceBroken)
            {
                String javaScriptToBeLoaded = "javascript: "
                        + USERNAME_EXTRACTION_JAVASCRIPT
                        + "javascript: oracle_acess_setUsernameParams('"
                        + usernameParamNamesStr + "')";
                loadJavascript(view, javaScriptToBeLoaded, false);
            }

            try
            {
                URL currentURL = new URL(url);
                if (areUrlsEqual(currentURL, loginSuccessUrl))
                {
                    if (parseTokenRelayResponse) {
                        loadJavascript(view, PARSE_JSON_RESPONSE_JAVASCRIPT
                                + SET_TOKEN_RELAY_RESPONSE_JAVASCRIPT, true);
                        OMLog.trace(TAG,
                                "ParseTokenRelayResponse = true; Javascript to capture OAuth access token is loaded");
                    } else {
                        OMLog.trace(TAG,
                                "ParseTokenRelayResponse = false; Javascript to capture OAuth access token is NOT loaded");
                        returnControl(view, true);
                    }
                    return;
                }
                else if (areUrlsEqual(currentURL, loginFailureUrl))
                {
                    returnControl(view, false);
                    return;
                }

            }
            catch (MalformedURLException e)
            {
                /*
                 * This will not happen as the current url will always be a
                 * valid one.
                 */
                Log.e(TAG, e.getMessage(), e);
            }
        }

        @Override
        public void onReceivedError(WebView view, int errorCode,
                String description, String failingUrl)
        {
            OMLog.error(TAG, "onReceivedError deprecated: errorCode " + errorCode
                    + " description = " + description + " failingUrl = " + failingUrl);
            super.onReceivedError(view, errorCode, description, failingUrl);
            receivedErrorLoadingUrl = true;
        }

        @TargetApi(Build.VERSION_CODES.M)
        @Override
        public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
            OMLog.error(TAG, "onReceivedError code: " + error.getErrorCode()
                    + " description: " + error.getDescription() + " failingUrl = " + request.getUrl());
            super.onReceivedError(view, request, error);
            String lastUrl = (String) ((CustomLinkedHashSet) visitedUrls).getLastElement();
            /* Refer onReceivedHttpError below where the same thing is done
            for explanation of the following:*/
            if (lastUrl != null && lastUrl.equals(request.getUrl().toString())) {
                receivedErrorLoadingUrl = true;
            }
        }

        /*App will get to know of Http errors like 502 only from LOLLIPOP onwards.
        * If 502 error happens on loading login url in versions below LOLLIPOP,
        * authentication will not succeed anyways, as cookies check will not pass.*/
        @TargetApi(Build.VERSION_CODES.LOLLIPOP)
        @Override
        public void onReceivedHttpError(WebView view, WebResourceRequest request, WebResourceResponse errorResponse) {
            OMLog.trace(TAG, "onReceivedHttpError: Status Code: " + errorResponse.getStatusCode());
            super.onReceivedHttpError(view, request, errorResponse);
            String lastUrl = (String) ((CustomLinkedHashSet) visitedUrls).getLastElement();
            /*
             1. This callback will be called for any resource (iframe, image, etc.),
             not just for the main page. receivedErrorLoadingUrl needs to be set
             only for main page so that we don't indicate a false positive for
             authentication. Error for any resource need not hold back authentication
             as there may be some small images which can result in 404 sometimes.

             2. isTokenRelayError: Since token relay service returns 401 in webview
             and SDK has to access anti-CSRF endpoint, treat this as not an error scenario.*/
            if (lastUrl != null && lastUrl.equals(request.getUrl().toString())
                    && !isTokenRelayError(errorResponse.getStatusCode())) {
                receivedErrorLoadingUrl = true;
            }
        }

        @TargetApi(Build.VERSION_CODES.KITKAT)
        private void loadJavascript(final WebView view, String script,
                                    final boolean successUrlHit) {

            if (isKitKatOrAbove) {
                view.evaluateJavascript(script, new ValueCallback<String>() {

                    @Override
                    public void onReceiveValue(String value) {
                        OMLog.trace(TAG, "Javascript is loaded successfully");
                        if (successUrlHit) {
                            returnControl(view, true);
                        }

                    }
                });
            } else {
                view.loadUrl(script);
                OMLog.trace(TAG, "Javascript is loaded successfully");
                if (successUrlHit) {
                    returnControl(view, true);
                }
            }
        }

        /**
         * Returns the control to Federated Authentication service with the set
         * of visited urls and login status
         *
         * @param view
         *            the instance of WebView being used
         * @param successUrlHit
         *            true means that successUrl is hit, otherwise failureUrl is
         *            hit
         */
        private void returnControl(WebView view, boolean successUrlHit)
        {
            view.stopLoading();
            loginSuccessFailureUrlHit = true;

            if (successUrlHit)
            {
                Log.d(TAG, "loginSuccessUrl is hit");
                inputParams.put(OMSecurityConstants.Param.VISITED_URLS, visitedUrls);
                if (username != null)
                {
                    inputParams.put(OMSecurityConstants.Challenge.USERNAME_KEY, username);
                }
                if (authenticationMechanism != null)
                {
                    inputParams.put(OMSecurityConstants.Param.AUTHENTICATION_MECHANISM,
                            authenticationMechanism);
                }
            }
            else
            {
                Log.d(TAG, "loginFailureUrl is hit");
                inputParams.put(OMSecurityConstants.Param.LOGIN_FAILURE_URL_HIT, "");
            }
            callback.onInput(inputParams);
        }

        void setTokenRelayResponse(String tokenRelayResponse) {
            inputParams.put(TOKEN_RELAY_RESPONSE, tokenRelayResponse);
        }

        private boolean isTokenRelayError(int errorCode) {
            return parseTokenRelayResponse && errorCode == HttpURLConnection.HTTP_UNAUTHORIZED;
        }
    }

    /**
     * JavascriptInterface to obtain username using javascript from the login
     * page and pass it on to SDK Java code.
     *
     * @author arunpras
     *
     */
    static class FederatedJavascriptInterface
    {
        private static final String TAG = FederatedJavascriptInterface.class
                .getName();
        private FederatedWebViewClient federatedWebViewClient;
        private Handler handler;

        /**
         * Quoting Javadoc of addJavascriptInterface (Object object, String name):
         * "JavaScript interacts with Java object on a private, background thread of this WebView. Care is therefore required to maintain thread safety."
         *
         * Hence, we use Handler to set the username using UI thread to be on safe side. Modifying it in background thread does not cause
         * a problem normally as only one authentication happens at a time with one MSS instance.
         *
         * @param handler
         * @param federatedWebViewClient
         */
        public FederatedJavascriptInterface(Handler handler,
                FederatedWebViewClient federatedWebViewClient)
        {
            this.handler = handler;
            this.federatedWebViewClient = federatedWebViewClient;
        }

        @JavascriptInterface
        public void setTokenRelayResponse(String jsonBody) {
            OMLog.trace(TAG, "Inside setTokenRelayResponse");
            federatedWebViewClient.setTokenRelayResponse(jsonBody);

        }

        @JavascriptInterface
        public void setUsername(final String username)
        {
            OMLog.trace(TAG, "Inside setUsername");
            boolean postStatus = handler.post(new Runnable() {
                @Override
                public void run() {
                    federatedWebViewClient.setUsername(username);
                }
            });
            if(!postStatus) {
                OMLog.warn(TAG, "The handler supplied by OMMobileSecurityServiceCallback#getHandler() could NOT be used for posting a runnable. Probable reason: looper processing the message queue is exiting.");
                /*Will go ahead setting username using background thread as it does not cause a problem normally.
                * Please refer the javadoc of UsernameExtractionJavascriptInterface for more details.*/
                federatedWebViewClient.setUsername(username);
            }
            else {
                OMLog.debug(TAG, "The handler supplied by OMMobileSecurityServiceCallback#getHandler() WAS used for posting a runnable.");
            }
        }

    }

    private Set<String> getDefaultUsernameParamNamesSet()
    {
        if (defaultUsernameParamNamesSet == null)
        {
            defaultUsernameParamNamesSet = new HashSet<>();
            defaultUsernameParamNamesSet.add("username");
            defaultUsernameParamNamesSet.add("uname");
            defaultUsernameParamNamesSet.add("email");
            defaultUsernameParamNamesSet.add("uid");
            defaultUsernameParamNamesSet.add("userid");
        }
        return defaultUsernameParamNamesSet;
    }
}
