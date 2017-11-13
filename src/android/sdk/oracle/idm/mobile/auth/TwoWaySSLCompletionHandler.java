/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.annotation.TargetApi;
import android.os.Build;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.ClientCertRequest;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.certificate.ClientCertificatePreference;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.logging.OMLog;

/**
 * Completion Handler for 2-way SSL challenge during authentication.
 *
 * @since 11.1.2.3.1
 */
public class TwoWaySSLCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = TwoWaySSLCompletionHandler.class.getSimpleName();

    private boolean mWebViewAuthentication;
    private AuthenticationServiceManager mASM;
    private ClientCertRequest mClientCertRequest;

    private AuthenticationService mAuthService;
    private OMAuthenticationContext mAuthContext;
    private OMAuthenticationRequest mAuthRequest;

    private OMAuthenticationChallenge mSSLChallenge;
    private String mClientAlias;
    private ClientCertificatePreference.Storage mClientCertStorage;
    /**
     * In case of CBA while using Embedded browser, TwoWaySSLCompletionHandler class
     * should delegate the control to FedAuthCompletionHandler for cancel operation. So, mFedAuthCompletionHandler
     * is assigned the same FedAuthCompletionHandler instance which got created in ASM during the authentication attempt.
     */
//    private FedAuthCompletionHandler mFedAuthCompletionHandler;
    private OMAuthenticationCompletionHandler mAuthCompletionHandler;

    TwoWaySSLCompletionHandler(AuthenticationServiceManager asm, ClientCertRequest clientCertRequest, OMAuthenticationRequest authenticationRequest,
                               AuthenticationService authService, OMAuthenticationContext authContext) {
        super(asm.getMSS().getMobileSecurityConfig(), asm.getCallback());
        mWebViewAuthentication = (clientCertRequest != null);
        mASM = asm;
        mClientCertRequest = clientCertRequest;
        mAuthRequest = authenticationRequest;
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
    protected void createChallengeRequest(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        OMLog.info(TAG, "createChallengeRequest");
        mSSLChallenge = challenge;
        mASM.getCallback().onAuthenticationChallenge(mss, challenge, this);
    }

    @Override
    public void proceed(Map<String, Object> responseFields) {
        //Well in this case we need that the application provides us with the alias name and storage preference.
        OMLog.info(TAG, "proceed");

        try {
            validateResponseFields(responseFields);
        } catch (OMMobileSecurityException e) {
            mASM.sendFailure(mASM.getCallback(), null, new OMMobileSecurityException(OMErrorCode.INVALID_CLIENT_CERTIFICATE));
            return;
        }

        ClientCertificatePreference clientCertificatePreference = new ClientCertificatePreference(mClientAlias, mClientCertStorage);
        OMLog.info(TAG, "Provided Client alias: " + mClientAlias + " from: " + mClientCertStorage);

        if (mWebViewAuthentication) {
            processClientCertChallengeResponse(mClientCertRequest, clientCertificatePreference);
        } else {

            //to reuse this in event of retries.
            mAuthContext.getInputParams().put(OMSecurityConstants.CLIENT_CERTIFICATE_PREFERENCE, clientCertificatePreference);
            mASM.getMSS().setClientCertificatePreference(clientCertificatePreference);

            mASM.processAuthRequest(mASM.getCallback(), mAuthRequest, mAuthService, mAuthContext);
        }

    }

    @Override
    public void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {

        if (responseFields != null) {
            mClientAlias = (String) responseFields.get(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_ALIAS_KEY);
            mClientCertStorage = (ClientCertificatePreference.Storage) responseFields.get(OMSecurityConstants.Challenge.CLIENT_CERTIFICATE_STORAGE_PREFERENCE_KEY);
            if (TextUtils.isEmpty(mClientAlias) || mClientCertStorage == null) {
                OMLog.error(TAG, "Invalid response fields.");
                throw new OMMobileSecurityException(OMErrorCode.INVALID_CLIENT_CERTIFICATE);
            } else if (mClientCertStorage == ClientCertificatePreference.Storage.APP_LEVEL_ANDROID_KEYSTORE
                    && Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
                OMLog.error(TAG, "AndroidKeyStore is available only in Android 4.3 and above.");
                throw new OMMobileSecurityException(OMErrorCode.ANDROID_KEYSTORE_NOT_AVAILABLE);
            }
            OMLog.debug(TAG, "Have the required fields.");
            return;
        } else {
            OMLog.error(TAG, "Response fields are null.");
            throw new OMMobileSecurityException(OMErrorCode.INVALID_CLIENT_CERTIFICATE);
        }
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    public void cancel() {
        OMLog.trace(TAG, "cancel");
        if (mWebViewAuthentication) {
            //user cancelled the operation.
            /*The following order MUST be maintained:
            1. mFedAuthCompletionHandler.cancel()
            2. mClientCertRequest.ignore()
            This is because mFedAuthCompletionHandler sets a boolean variable which in turn is used in
            onPageFinished(). If mClientCertRequest.ignore() is called first, then the  boolean variable
             will not be set, leading to false successful authentication in certain scenarios.
            */
            if (mAuthCompletionHandler != null) {
                mAuthCompletionHandler.cancel();
            } else {
                OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
            }
            mClientCertRequest.ignore();
        } else {
            mASM.sendFailure(mASM.getCallback(), null, new OMMobileSecurityException(OMErrorCode.USER_CANCELED_AUTHENTICATION));
        }
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public void processClientCertChallengeResponse(ClientCertRequest request,
                                                   final ClientCertificatePreference clientCertificatePreference) {
        if (clientCertificatePreference.getAlias() != null) {
            KeyStore.PrivateKeyEntry pke;
            try {
                OMCertificateService certService = new OMCertificateService(
                        mASM.getApplicationContext());
                pke = certService.getPrivateEntry(clientCertificatePreference.getAlias(), clientCertificatePreference.getStorage());
                request.proceed(
                        pke.getPrivateKey(),
                        ((X509Certificate[]) pke
                                .getCertificateChain()));
            } catch (Exception e) {
                Log.e(TAG, e.getLocalizedMessage(),
                        e);
                request.ignore();// do not remember
                // this choice.
            }

        } else {
            Log.d(TAG,
                    "No Client alias selected hence canceling the client certificate request.");
            request.cancel();// remember the choice.
        }
    }
}

