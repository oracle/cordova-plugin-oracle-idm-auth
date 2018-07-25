/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.net.http.SslCertificate;
import android.net.http.SslError;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.ClientCertRequest;
import android.webkit.HttpAuthHandler;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.auth.webview.WebViewAuthServiceInputCallbackImpl;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.connection.CBAExceptionEvent;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.connection.OMSSLSocketFactory;
import oracle.idm.mobile.credentialstore.OMCredential;
import oracle.idm.mobile.crypto.Base64;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.HTTP_AUTH_HOST;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.HTTP_AUTH_REALM;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.IS_FORCE_AUTHENTICATION;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.PASSWORD_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.UNTRUSTED_SERVER_CERTIFICATE_AUTH_TYPE_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.UNTRUSTED_SERVER_CERTIFICATE_CHAIN_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.USERNAME_KEY;
import static oracle.idm.mobile.OMSecurityConstants.ConnectionConstants;
import static oracle.idm.mobile.OMSecurityConstants.DOMAIN;
import static oracle.idm.mobile.OMSecurityConstants.EXPIRES;
import static oracle.idm.mobile.OMSecurityConstants.HTTP_ONLY;
import static oracle.idm.mobile.OMSecurityConstants.PATH;
import static oracle.idm.mobile.OMSecurityConstants.SECURE;


/**
 * Parent class for all the authentication services.
 * <p/>
 * Communication is as follows:
 * <p/>
 * [ASM]                                   --- collectLoginChallengeInput -------> [AuthenticationService]
 * <p/>
 * [AuthenticationService]                 --- createChallengeRequest ------> [OMAuthenticationCompletionHandler]
 * <p/>
 * [OMAuthenticationCompletionHandler]     --- onInput ---------------------> [AuthenticationService]
 * <p/>
 * [AuthenticationService]                 --- onInputAvailable ------------> [ASM]
 * <p/>
 * [ASM]                                   --- handleAuthentication --------> [AuthenticationService]
 * <p/>
 * [AuthenticationService]                 --- onAuthDone ------------------> [ASM]
 * <p/>
 * The major functions of this class are:
 * <p/>
 * - invoke registered input handlers to collect inputs from the app.
 * - perform core authentication
 * - create challenge object as required.
 * - logout
 * - validation of the authentication context.
 *
 * @hide
 */
public abstract class AuthenticationService {

    /**
     * ENUM to store Authentication service type supported by SDK
     * Internal to SDK
     */
    enum Type {
        /**
         * Client Certificate based Authentication Service
         */
        CBA_SERVICE,
        /**
         * Basic Authentication service
         */
        BASIC_SERVICE,
        /**
         * Offline Authentication service
         */
        OFFLINE_SERVICE,
        /**
         * Federated Authentication Service
         */
        FED_AUTH_SERVICE,
        /**
         * grant type resource_owner Authentication service
         */
        OAUTH20_RO_SERVICE,
        /**
         * grant type authorization_code Authentication service
         */
        OAUTH20_AC_SERVICE,
        /**
         * grant type client_credential Authentication service
         */
        OAUTH20_CC_SERVICE,

        /**
         * openID connect/OAuth IDCS Dynamic Client Registration service.
         */
        CLIENT_REGISTRATION_SERVICE,

        /**
         * openID Connect Authentication Service
         */
        OPENIDCONNECT10,
        /**
         * Authentication service to handle dynamic client registration for Mobile and Social
         */
        OAUTH_MS_PREAUTHZ,
        /**
         * Authentication service to handle dynamic client registration for Mobile and Social
         */
        OAUTH_MS_DYCR,
        /**
         * Authentication service to obtain new access tokens using refresh token.
         */
        REFRESH_TOKEN_SERVICE
    }

    public static void onUntrustedServerCertificate(AuthenticationServiceManager asm, SslErrorHandler handler, SslError sslError) {
        final SslCertificate sslCertificate = sslError.getCertificate();

        /*Check if this certificate is already imported in App level trust store as this error would come
        ONLY if it is not trusted as per system level trust store.
        */
        Bundle bundle = SslCertificate.saveState(sslCertificate);
        X509Certificate rootX509Certificate = OMCertificateService.convertToX509Certificate(bundle);
        OMLog.trace(TAG, "Root certificate: " + rootX509Certificate.toString());
        X509Certificate[] chain = new X509Certificate[]{rootX509Certificate};
        String authType = rootX509Certificate.getPublicKey().getAlgorithm();
        OMLog.trace(TAG, "Public Key Algo Name: " + authType);
        boolean certificateUnTrusted = true;
        try {
            OMCertificateService certificateService = new OMCertificateService(asm.getApplicationContext());
            OMSSLSocketFactory.OMTrustManager trustManager = new OMSSLSocketFactory.OMTrustManager(certificateService.getTrustStore());
            trustManager.checkServerTrustedLocally(chain, authType, null);
            certificateUnTrusted = false;
        } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if (!certificateUnTrusted) {
            handler.proceed();
            return;
        }

        onUntrustedServerCertificate(asm, chain, authType, handler, null, null, null);
    }

    public static void onUntrustedServerCertificate(AuthenticationServiceManager asm, final X509Certificate[] chain,
                                                    final String authType, OMAuthenticationRequest request,
                                                    AuthenticationService authService, OMAuthenticationContext authContext) {
        onUntrustedServerCertificate(asm, chain, authType, null, request, authService, authContext);
    }

    public static void onClientCertificateRequired(AuthenticationServiceManager asm, final ClientCertRequest clientCertRequest) {
        onClientCertificateRequired(asm, clientCertRequest, null, null, null, null);
    }

    public static void onClientCertificateRequired(AuthenticationServiceManager asm, final CBAExceptionEvent event,
                                                   OMAuthenticationRequest authenticationRequest, AuthenticationService authenticationService,
                                                   OMAuthenticationContext authContext) {
        onClientCertificateRequired(asm, null, event, authenticationRequest, authenticationService, authContext);
    }

    public static void onReceivedHttpAuthRequest(AuthenticationServiceManager asm, HttpAuthHandler handler, String host, String realm,
                                                 Map<String, Object> inputParams, OMMobileSecurityServiceCallback appCallback) {
        OMAuthenticationChallenge challenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.USERNAME_PWD_REQUIRED);
        challenge.addChallengeField(HTTP_AUTH_HOST, host);
        challenge.addChallengeField(HTTP_AUTH_REALM, realm);
        challenge.addChallengeField(USERNAME_KEY, null);
        challenge.addChallengeField(PASSWORD_KEY, null);

        OMLog.info(TAG, "basicAuthChallenge : " + challenge.toString());
        BasicAuthCompletionHandler basicAuthCompletionHandler = new BasicAuthCompletionHandler(asm, appCallback, handler, inputParams);
        basicAuthCompletionHandler.createChallengeRequest(asm.getMSS(), challenge,
                new WebViewAuthServiceInputCallbackImpl(asm, asm.getASMInputController()));
    }

    private static void onUntrustedServerCertificate(AuthenticationServiceManager asm, final X509Certificate[] chain, final String authType, SslErrorHandler handler,
                                                     OMAuthenticationRequest request, AuthenticationService authService, OMAuthenticationContext authContext) {
        //ADD asm level completion handlers for this process, once done start the authentication process here.
        OMAuthenticationChallenge sslChallenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.UNTRUSTED_SERVER_CERTIFICATE);
        sslChallenge.addChallengeField(UNTRUSTED_SERVER_CERTIFICATE_CHAIN_KEY, chain);
        sslChallenge.addChallengeField(UNTRUSTED_SERVER_CERTIFICATE_AUTH_TYPE_KEY, authType);
        OMLog.info(TAG, "sslChallenge : " + sslChallenge.toString());
        OneWaySSLCompletionHandler sslHandler = new OneWaySSLCompletionHandler(asm, handler, request, authService, authContext);
        sslHandler.createChallengeRequest(asm.getMSS(), sslChallenge, null);
    }

    private static void onClientCertificateRequired(AuthenticationServiceManager asm, final ClientCertRequest clientCertRequest,
                                                    final CBAExceptionEvent cbaExceptionEvent, OMAuthenticationRequest authenticationRequest,
                                                    AuthenticationService authenticationService, OMAuthenticationContext authContext) {

        //less likely to happen, but consider the case where client cert preference is already available, then refrain calling the callbak,
        //It has catch that in the first case if the app/user selected wrong certificate, so by calling the callback again app will get a chance to given the correct certificate next time
        //re-visit this with a better plan
        OMAuthenticationChallenge cbaChallenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.CLIENT_IDENTITY_CERTIFICATE_REQUIRED);
        //
        if (clientCertRequest != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_HOST, clientCertRequest.getHost());
                cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_PORT, clientCertRequest.getPort());
                cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_ISSUERS_KEY, clientCertRequest.getPrincipals());
                cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_KEYTYPES_KEY, clientCertRequest.getKeyTypes());
            }
        } else if (cbaExceptionEvent != null) {
            cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_ISSUERS_KEY, cbaExceptionEvent.getIssuers());
            cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_KEYTYPES_KEY, cbaExceptionEvent.getKeys());
            cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_HOST, cbaExceptionEvent.getPeerHost());
            cbaChallenge.addChallengeField(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_PORT, cbaExceptionEvent.getPeerPort());
        }


        OMLog.info(TAG, "cbaChallenge : " + cbaChallenge.toString());
        TwoWaySSLCompletionHandler clientCertHandler = new TwoWaySSLCompletionHandler(asm, clientCertRequest, authenticationRequest, authenticationService, authContext);
        clientCertHandler.createChallengeRequest(asm.getMSS(), cbaChallenge, null);
    }


    protected final AuthenticationServiceManager mASM;
    final OMAuthenticationCompletionHandler mAuthCompletionHandler;
    final OMLogoutCompletionHandler mLogoutCompletionHandler;
    private static final String TAG = AuthenticationService.class.getSimpleName();

    AuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        mASM = asm;
        mAuthCompletionHandler = handler;
        mLogoutCompletionHandler = null;
    }

    AuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler, OMLogoutCompletionHandler logoutCompletionHandler) {
        mASM = asm;
        mAuthCompletionHandler = handler;
        mLogoutCompletionHandler = logoutCompletionHandler;
    }

    /**
     * This method will check whether the input params contains all the required inputs if yes then this method will return to the asm engine to continue the authentication.
     * If the required inputs are not available, this method invokes creates the challenge object and returns to the engine so that application callbacks can be invoked to collect the required inputs.
     *
     * @param inputParams
     * @param inputController
     */
    public abstract void collectLoginChallengeInput(Map<String, Object> inputParams, ASMInputController inputController);

    public abstract OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException;

    public abstract void cancel();

    public abstract boolean isValid(OMAuthenticationContext authContext, boolean validateOnline);

    /**
     * This method performs logout based on below flags
     *
     * @param authContext     authentication context
     * @param isDeleteUnPwd   : should user name and password be deleted
     * @param isDeleteCookies : should cookies be deleted
     * @param isDeleteTokens  : should tokens be deleted
     * @param isLogoutCall    : is it logout call
     */
    public abstract void logout(final OMAuthenticationContext authContext, final boolean isDeleteUnPwd, final boolean isDeleteCookies, final boolean isDeleteTokens, final boolean isLogoutCall);

    public abstract void collectLogoutChallengeInput(Map<String, Object> inputParams, final AuthServiceInputCallback callback);

    public abstract void handleLogout(final OMAuthenticationContext authContext, final boolean isDeleteUnPwd, final boolean isDeleteCookies, final boolean isDeleteTokens, final boolean isLogoutCall);

    public abstract Type getType();


    /**
     * Add the identity domain in the map passed based on SDK configuration.
     */
    protected String addIdentityDomain(String userName, Map<String, String> headers,
                                       String identityDomain) throws OMMobileSecurityException {
        // check for identity domain name preferences.
        OMMobileSecurityConfiguration mobileSecurityConfiguration = mASM.getMSS().getMobileSecurityConfig();
        boolean sendIdentityDomainInHeader = mobileSecurityConfiguration.sendIdentityDomainInHeader();
        if (!TextUtils.isEmpty(identityDomain)) {
            if (sendIdentityDomainInHeader) {
                String headerName = mobileSecurityConfiguration.getIdentityDomainHeaderName();
                headers.put(headerName, identityDomain);
                Log.d(TAG + "_addIdentityDomain", "Identity Domain Header " + headerName + " set!");
            } else {
                userName = identityDomain + "." + userName;
            }
        } else {
            if (sendIdentityDomainInHeader)
                throw new OMMobileSecurityException(OMErrorCode.IDENTITY_DOMAIN_REQUIRED);
        }
        return userName;
    }

    protected Map<String, Object> getRCChallengeFields() {
        return mASM.getRCUtility().getRememberCredentialsChallengeFields();
    }

    protected void storeRCUIPreferences(Map<String, Object> prefs) {
        mASM.getRCUtility().storeRememberCredentialsUIPreferences(prefs);
    }

    protected List<OMCookie> parseVisitedURLCookieMap(Map<String, List<String>> stringListMap) {
        List<OMCookie> cookies = new ArrayList<>();
        for (String url : stringListMap.keySet()) {
            List<String> setCookieHeaderList = stringListMap.get(url);
            List<OMCookie> omCookieList = new ArrayList<>();
            for (String setCookieHeaderValue : setCookieHeaderList) {
                int firstEqualsIndex = setCookieHeaderValue.indexOf('=');
                String cookieName = setCookieHeaderValue.substring(0,
                        firstEqualsIndex);
                int firstSemicolonIndex = setCookieHeaderValue.indexOf(';');
                String cookieValue;
                if (firstSemicolonIndex != -1) {
                    cookieValue = setCookieHeaderValue.substring(
                            firstEqualsIndex + 1, firstSemicolonIndex);
                } else {
                    cookieValue = setCookieHeaderValue
                            .substring(firstEqualsIndex + 1);
                }
                String domain = getAttributeValue(
                        setCookieHeaderValue, DOMAIN);
                if (TextUtils.isEmpty(domain)) {
                    try {
                        URL visitedURL = new URL(url);
                        domain = visitedURL.getHost();
                    } catch (MalformedURLException e) {
                        OMLog.error(TAG, e.getMessage(), e);
                    }
                }

                String path = getAttributeValue(
                        setCookieHeaderValue, PATH);
                String expiryDateStr = getAttributeValue(
                        setCookieHeaderValue, EXPIRES);
                boolean secure = setCookieHeaderValue
                        .contains(SECURE);
                boolean httpOnly = setCookieHeaderValue
                        .contains(HTTP_ONLY);
                OMCookie cookie = new OMCookie(url, cookieName, cookieValue, domain, path, expiryDateStr, httpOnly, secure);
                omCookieList.add(cookie);
            }
            cookies.addAll(omCookieList);
        }
        return cookies;
    }

    private String getAttributeValue(String setCookieHeaderValueAllLowerCase,
                                     String attribute) {
        int beginIndex = setCookieHeaderValueAllLowerCase.indexOf(attribute);
        String attributeValue = null;
        if (beginIndex != -1) {
            beginIndex += attribute.length() + 1;
            int endIndex = setCookieHeaderValueAllLowerCase.indexOf(';',
                    beginIndex);
            if (endIndex != -1) {
                attributeValue = setCookieHeaderValueAllLowerCase.substring(
                        beginIndex, endIndex);
            } else {
                attributeValue = setCookieHeaderValueAllLowerCase
                        .substring(beginIndex);
            }
        }
        return attributeValue;
    }

    /*
    Creates challenge for ChallengeType USERNAME_PWD_REQUIRED
     */
    public OMAuthenticationChallenge createUsernamePasswordChallenge() {
        OMAuthenticationChallenge challenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.USERNAME_PWD_REQUIRED);
        challenge.addChallengeField(USERNAME_KEY, null);
        challenge.addChallengeField(PASSWORD_KEY, null);
        if (mASM.getMSS().getMobileSecurityConfig().isCollectIdentityDomain()) {
            challenge.addChallengeField(IDENTITY_DOMAIN_KEY, null);
        }
        if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
            challenge.addChallengeFields(getRCChallengeFields());
            Log.i(TAG, "Adding RC challenge fields");
        }
        // add input params present in authContext to challenge
        OMAuthenticationContext authContext = mASM.getTemporaryAuthenticationContext();
        if (authContext != null && authContext.getMobileException() != null) {
            challenge.addChallengeField(MOBILE_SECURITY_EXCEPTION, authContext.getMobileException());
            if (authContext.getInputParams() != null) {
                challenge.addChallengeField(USERNAME_KEY, authContext.getInputParams().get(USERNAME_KEY));
                if (mASM.getMSS().getMobileSecurityConfig().isCollectIdentityDomain()) {
                    challenge.addChallengeField(IDENTITY_DOMAIN_KEY, authContext.getInputParams().get(IDENTITY_DOMAIN_KEY));
                }
                //resetting the exception before new challenge is thrown
                authContext.getInputParams().remove(MOBILE_SECURITY_EXCEPTION);
                authContext.setException(null);
            }
        }
        if (authContext != null && authContext.getForceAuthentication()) {
            challenge.addChallengeField(IS_FORCE_AUTHENTICATION, true);
        }
        OMLog.info(TAG, "createChallenge : " + challenge.toString());
        return challenge;
    }

    /*
    Adds exception field present in authcontext input parameters to the challenge
     */
    public void updateChallengeWithException(OMAuthenticationChallenge challenge) {
        if (mASM != null) {
            OMAuthenticationContext authContext = mASM.getTemporaryAuthenticationContext();
            if (authContext != null && authContext.getMobileException() != null) {
                challenge.addChallengeField(MOBILE_SECURITY_EXCEPTION, authContext.getMobileException());
                //resetting the exception before new challenge is thrown
                authContext.setException(null);
            }
        }

    }

    /**
     * Utility method to remove all session cookies from the application webview.
     */
    protected void removeSessionCookies() {
        OMLog.debug(TAG, "removeSessionCookies");
        OMCookieManager.getInstance().removeSessionCookies(mASM.getApplicationContext());
    }

    /**
     * Utility method to report logout on application callback only in case logout operation.
     *
     * @param mss
     * @param code
     */
    protected void reportLogoutCompleted(OMMobileSecurityService mss, boolean isLogoutCall,
                                         OMErrorCode code) {
        reportLogoutCompleted(mss, isLogoutCall,
                ((code != null) ? new OMMobileSecurityException(code) : null));
    }

    protected void reportLogoutCompleted(OMMobileSecurityService mss, boolean isLogoutCall,
                                         OMMobileSecurityException mse) {
        mss.onLogoutCompleted();
        if (isLogoutCall) {
            OMMobileSecurityServiceCallback callback = mss.getCallback();
            if (callback != null) {
                OMLog.info(TAG, "Invoking onLogoutCompleted callback");
                callback.onLogoutCompleted(mss, mse);
            } else {
                OMLog.error(TAG, "Cannot invoke app callback for logout, as the callback is not registered");
            }
        }
    }

    protected void loadLogoutURL(WebView webView, WebViewClient webViewClient, String logoutURL) {
        webView.getSettings().setJavaScriptEnabled(true);
        if (webViewClient != null) {
            webView.setWebViewClient(webViewClient);
        }
        OMLog.trace(TAG, "Loading logout url");
        webView.loadUrl(logoutURL);
    }

    /**
     * Accesses logout url in a separate thread; the tokens passed are sent
     * along with the request so that the server can terminate the session
     * corresponding to the tokens
     *
     */
    protected class AccessLogoutUrlTask extends
            AsyncTask<Void, Void, OMMobileSecurityException> {
        private final String TAG = AccessLogoutUrlTask.class.getSimpleName();
        private OMMobileSecurityConfiguration config;
        private boolean isLogoutCall;
        private OMConnectionHandler connHandler;
        private OMAuthenticationContext authContext;

        AccessLogoutUrlTask(OMMobileSecurityConfiguration config,
                            boolean isLogoutCall,
                            OMAuthenticationContext authContext) {
            super();
            this.config = config;
            this.isLogoutCall = isLogoutCall;
            this.authContext = authContext;
        }

        @Override
        protected OMMobileSecurityException doInBackground(Void... params) {
            OMMobileSecurityException exception = null;
            try {
                OMLog.debug(TAG, "Logout url is being invoked");
                int logoutTimeout = authContext.getLogoutTimeout();
                URL logoutUrl = config.getLogoutUrl();
                Map<String, String> headers = null;
                if (logoutTimeout <= 0) {
                    connHandler = mASM.getMSS().getConnectionHandler();
                } else {
                    connHandler = mASM.getMSS().getConnectionHandler(logoutTimeout);
                }
                if (connHandler != null) {
                    if (config.sendIdentityDomainInHeader()) {
                        String idDomain = authContext.getIdentityDomain();
                        if (!TextUtils.isEmpty(idDomain)) {
                            headers = new HashMap<>();
                            OMLog.debug(TAG, "Added ID Domain header!");
                            headers.put(config.getIdentityDomainHeaderName(),
                                    idDomain);
                        }
                    }
                    if (config.isSendCustomAuthHeadersInLogout()
                            && config.getCustomAuthHeaders() != null
                            && !config.getCustomAuthHeaders().isEmpty()) {
                        if (headers == null) {
                            headers = new HashMap<>();
                        }
                        OMLog.debug(TAG, "Added custom auth headers");
                        headers.putAll(config.getCustomAuthHeaders());
                    }

                    if (config.isSendAuthzHeaderInLogout()) {
                        String userName = null;
                        String pwd = null;
                        if (config.isOfflineAuthenticationAllowed()) {
                            userName = authContext.getUserName();
                            pwd = authContext.getUserPassword();
                        } else if (config.isRememberCredentialsEnabled()) {
                            OMCredential rememberedCred = mASM.getRCUtility().retrieveRememberedCredentials();
                            if (rememberedCred != null) {
                                String rememberedCredUserName = rememberedCred.getUserName();
                                if (!TextUtils.isEmpty(rememberedCredUserName) && rememberedCredUserName.equals(authContext.getUserName())) {
                                    userName = rememberedCredUserName;
                                    pwd = rememberedCred.getRawUserPassword();
                                }
                            }
                        }
                        if (!TextUtils.isEmpty(userName)
                                && !TextUtils.isEmpty(pwd)) {
                            if (headers == null) {
                                headers = new HashMap<>();
                            }

                            StringBuilder headerValue = new StringBuilder(
                                    ConnectionConstants.BASIC.getValue());
                            headerValue.append(" ");
                            StringBuilder unNamePwd = new StringBuilder(
                                    userName);
                            unNamePwd.append(":");
                            unNamePwd.append(pwd);
                            headerValue.append(Base64.stringEncode(unNamePwd
                                    .toString()));

                            headers.put(ConnectionConstants.AUTHORIZATION
                                    .getValue(), headerValue.toString());
                            OMLog.debug(TAG, "Added User authorization header!");
                        }
                    }
                    OMHTTPResponse response = connHandler.httpGet(logoutUrl, headers);
                    if (response == null) {
                        exception = new OMMobileSecurityException(OMErrorCode.LOGOUT_FAILED);
                    } else if (!response.isSuccess()) {
                        exception = new OMMobileSecurityException(OMErrorCode.LOGOUT_FAILED,
                                response.constructErrorMessage());
                    }
                } else {
                    Log.e(TAG, "Connection Handler Null [fatal]");
                    exception = new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
                }
            } catch (OMMobileSecurityException e) {
                OMLog.error(TAG,
                        "Error occurred while invoking logout url: "
                                + e.getMessage());
                exception = e;
            }
            return exception;
        }

        @Override
        protected void onPostExecute(OMMobileSecurityException result) {
            OMLog.debug(TAG, "onPostExecute ");
            authContext.deleteCookies();
            OMLog.debug(TAG, "Deleted cookies locally after invoking logout url");
            /* To clear the cookies on idle timeout if offline authentication is disabled,
            * SDK invokes logout url. mss.onLogoutCompleted() clears entire state including
            * cancelling any pending timer. But, we need the session timer to be running
            * so that we clear the remembered credentials on session timeout. So, it is not
            * called unless this code is executed as part of mss.logout() call i.e.
            * [isLogoutCall = true].
            * */
            if (isLogoutCall) {
                OMMobileSecurityService mss = mASM.getMSS();
                mss.onLogoutCompleted();
                OMMobileSecurityServiceCallback callback = mss.getCallback();
                if (callback != null) {
                    callback.onLogoutCompleted(mss, result);
                }
            }
        }
    }
}
