/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.util.Log;
import android.webkit.SslErrorHandler;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.UNTRUSTED_SERVER_CERTIFICATE_CHAIN_KEY;

/**
 * Completion Handler for untrusted SSL certificate challenge during authentication.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class OneWaySSLCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = OneWaySSLCompletionHandler.class.getSimpleName();

    private boolean mWebViewAuthentication;
    private AuthenticationServiceManager mASM;
    private OMAuthenticationChallenge mSSLChallenge;

    private AuthenticationService mAuthService;
    private OMAuthenticationContext mAuthContext;
    private OMAuthenticationRequest mAuthRequest;

    private SslErrorHandler mSslErrorHandler;
    /**
     * In case of Untrusted Certificate error while using Embedded browser, OneWaySSLCompletionHandler class
     * should delegate the control to FedAuthCompletionHandler for cancel operation. So, mFedAuthCompletionHandler
     * is assigned the same FedAuthCompletionHandler instance which got created in ASM during the authentication attempt.
     */
//    private FedAuthCompletionHandler mFedAuthCompletionHandler;
    private OMAuthenticationCompletionHandler mAuthCompletionHandler;

    OneWaySSLCompletionHandler(AuthenticationServiceManager asm, SslErrorHandler sslErrorHandler, OMAuthenticationRequest request, AuthenticationService authService, OMAuthenticationContext authContext) {
        super(asm.getMSS().getMobileSecurityConfig(), asm.getCallback());
        mWebViewAuthentication = (sslErrorHandler != null);
        mASM = asm;
        mSslErrorHandler = sslErrorHandler;
        mAuthRequest = request;
        mAuthService = authService;
        mAuthContext = authContext;
        if (mWebViewAuthentication) {
            switch (mASM.getMSS().getMobileSecurityConfig().getAuthenticationScheme()) {
                case FEDERATED:
                    mAuthCompletionHandler = (FedAuthCompletionHandler) asm.getAuthenticationCompletionHandler(AuthenticationService.Type.FED_AUTH_SERVICE);
                    break;
                case OAUTH20:
                    mAuthCompletionHandler = (OAuthAuthorizationCodeCompletionHandler) asm.getAuthenticationCompletionHandler(AuthenticationService.Type.OAUTH20_AC_SERVICE);
                    break;
            }
        }
    }

    @Override
    protected void createChallengeRequest(OMMobileSecurityService mas, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        OMLog.info(TAG, "createChallengeRequest");
        mSSLChallenge = challenge;
        mASM.getCallback().onAuthenticationChallenge(mas, challenge, this);
    }

    @Override
    public void proceed(Map<String, Object> responseFields) {
        //we do not want any response fields from the app.
        //as they have called proceed, it means they want to trust the certificate.
        OMLog.info(TAG, "proceed");
        OMLog.info(TAG, "Installing untrusted certificate");
        try {
            OMCertificateService certificateService = new OMCertificateService(mASM.getApplicationContext());
            X509Certificate[] chain = (X509Certificate[]) mSSLChallenge.getChallengeFields().get(UNTRUSTED_SERVER_CERTIFICATE_CHAIN_KEY);
            //Root certificate is imported
            certificateService.importServerCertificate(chain[0]);
            mASM.getMSS().refreshConnectionHandler(OMSecurityConstants.Flags.CONNECTION_ALLOW_UNTRUSTED_SERVER_CERTIFICATE, true);

            if (mWebViewAuthentication) {
                mSslErrorHandler.proceed();
            } else {
                mASM.processAuthRequest(mASM.getCallback(), mAuthRequest, mAuthService, mAuthContext);
            }
        } catch (CertificateException e) {
            Log.e(TAG, e.getMessage(), e);
            mASM.sendFailure(mASM.getCallback(), null, new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR, e));
        }
    }

    @Override
    public void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {
    }

    @Override
    public void cancel() {
        OMLog.trace(TAG, "cancel");
        if (mWebViewAuthentication) {
            // user rejected the untrusted server certificate.
            /*The following order MUST be maintained:
            1. mFedAuthCompletionHandler.cancel()
            2. mSslErrorHandler.cancel()
            This is because mFedAuthCompletionHandler sets a boolean variable which in turn is used in
            onPageFinished(). If mSslErrorHandler.cancel() is called first, then the  boolean variable
             will not be set, leading to false successful authentication in certain scenarios.
            */
            if (mAuthCompletionHandler != null) {
                mAuthCompletionHandler.cancel();
            } else {
                OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
            }
            mSslErrorHandler.cancel();
        } else {
            mASM.sendFailure(mASM.getCallback(), null, new OMMobileSecurityException(OMErrorCode.USER_REJECTED_SERVER_CERTIFICATE));
        }

    }
}
