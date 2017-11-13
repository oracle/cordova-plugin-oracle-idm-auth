/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.webview;

import android.annotation.TargetApi;
import android.net.http.SslError;
import android.os.Build;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.webkit.ClientCertRequest;
import android.webkit.HttpAuthHandler;
import android.webkit.SslErrorHandler;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Map;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.AuthenticationService;
import oracle.idm.mobile.auth.AuthenticationServiceManager;
import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.logging.OMLog;

/**
 * @hide
 */
public abstract class LoginWebViewHandler implements WebViewConfigurationHandler
{
    private static final String TAG = LoginWebViewHandler.class.getSimpleName();
    private static Method enablePlatformNotifications;

    protected AuthenticationServiceManager asm;
    protected boolean authenticationCancelled;
    protected AuthServiceInputCallback callback;

    static
    {
        // check at run time whether the device api supports this method. As api
        // > 4.2 has made the method obsolete.
        try
        {
            enablePlatformNotifications = WebView.class.getMethod(
                    "enablePlatformNotifications", null);
        }
        catch (NoSuchMethodException e)
        {
            Log.e(TAG,
                    "enablePlatformNotifications isn't available in this device's api",
                    e);
        }
    }

    protected LoginWebViewHandler()
    {
        // for testing.
    }

    public LoginWebViewHandler(AuthenticationServiceManager asm)
    {
        this.asm = asm;
    }

    @Override
    public void configureView(Map<String, Object> inputParams,
                       final AuthServiceInputCallback callback)
    {
        // Resetting this variable for every new authentication attempt
        authenticationCancelled = false;

        this.callback = callback;
        WebView webView = (WebView) inputParams.get(OMSecurityConstants.Challenge.WEBVIEW_KEY);

        if (enablePlatformNotifications != null)
        {
            try
            {
                enablePlatformNotifications.invoke(null);
            }
            catch (IllegalArgumentException e)
            {
                Log.e(TAG, " IllegalArgumentException", e);
            }
            catch (IllegalAccessException e)
            {
                Log.e(TAG, " IllegalAccessException", e);
            }
            catch (InvocationTargetException e)
            {
                Log.e(TAG, " InvocationTargetException", e);
            }
        }

        // The following has been added to solve the Bug 16374827
        webView.requestFocus(View.FOCUS_DOWN);
        webView.setOnTouchListener(new View.OnTouchListener()
        {
            @Override
            public boolean onTouch(View v, MotionEvent event)
            {
                switch (event.getAction())
                {
                    case MotionEvent.ACTION_DOWN:
                    case MotionEvent.ACTION_UP:
                        if (!v.hasFocus())
                        {
                            v.requestFocus();
                        }
                        break;
                }
                return false;
            }
        });

        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setBuiltInZoomControls(true);
        webSettings.setDomStorageEnabled(true);
    }

    public void onCancel() {
        OMLog.trace(TAG, "onCancel");
        authenticationCancelled = true;
    }

    /**
     * This class takes care of handling the scenario where the server
     * certificate is untrusted. All the authentication flows which use WebView
     * should extend this class to define the custom web view clients.
     * <p>
     * @since 11.1.2.2.0
     *
     */
    protected class LoginWebViewClient extends BaseWebViewClient
    {
        protected WebViewClient origAppWebViewClient;
        /**
         * username is captured from the HTML form using Javascript. If basic auth/NTLM/Kerberos challenge comes from sever,
         * then username capture becomes much easier as SDK consumer passes it to SDK.
         * Refer {@link oracle.idm.mobile.auth.BasicAuthCompletionHandler#proceed(Map)}
         */
        protected String username;
        protected Map<String, Object> inputParams;
        protected OMAuthenticationContext.AuthenticationMechanism authenticationMechanism;

        // for testing.
        LoginWebViewClient() {

        }

        LoginWebViewClient(WebViewClient origAppWebViewClient) {
            this.origAppWebViewClient = origAppWebViewClient;
        }

        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler,
                                       SslError error)
        {
            OMLog.error(TAG, "onReceivedSslError: " + error.toString());

            AuthenticationService.onUntrustedServerCertificate(asm, handler, error);
        }

        @TargetApi(Build.VERSION_CODES.LOLLIPOP)
        @Override
        public void onReceivedClientCertRequest(WebView view,
                                                final ClientCertRequest request) {
            OMLog.error(TAG, "onReceivedClientCertRequest: Host: " + request.getHost() +
                    " Port: " + request.getPort() + " \nKeyTypes: " + Arrays.toString(request.getKeyTypes()) +
                    " \nAcceptable certificate issuers for the certificate matching the private key:" + Arrays.toString(request.getPrincipals()));

            AuthenticationService.onClientCertificateRequired(asm, request);
        }

        @Override
        public void onReceivedHttpAuthRequest(WebView view,
                                              HttpAuthHandler handler, String host, String realm) {
            OMLog.debug(TAG + "_onReceivedHttpAuthRequest", "host = " + host
                    + " realm = " + realm);

            AuthenticationService.onReceivedHttpAuthRequest(asm, handler, host, realm, inputParams, asm.getMSS().getCallback());
            // This is the only place where we can set the authentication mechanism. Please refer to doc for more details.
            authenticationMechanism = OMAuthenticationContext.AuthenticationMechanism.FEDERATED_HTTP_AUTH;
        }


        public void setUsername(String username)
        {
            OMLog.trace(TAG, "Username is captured");
            this.username = username;
        }
    }

}
