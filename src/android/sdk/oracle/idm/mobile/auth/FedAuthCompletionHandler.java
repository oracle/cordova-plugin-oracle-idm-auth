/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.webkit.WebView;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.webview.FederatedWebViewHandler;
import oracle.idm.mobile.auth.webview.LoginWebViewHandler;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.WEBVIEW_KEY;


class FedAuthCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = FedAuthCompletionHandler.class.getSimpleName();
    private AuthServiceInputCallback mAuthServiceCallback;

    private AuthenticationServiceManager mASM;
    private OMMobileSecurityConfiguration mConfig;
    private LoginWebViewHandler mLoginWebViewHandler;

    FedAuthCompletionHandler(AuthenticationServiceManager asm, OMMobileSecurityConfiguration config, OMMobileSecurityServiceCallback appCallback) {
        super(config, appCallback);
        mASM = asm;
        mConfig = config;
        mLoginWebViewHandler = new FederatedWebViewHandler(mASM);
    }

    @Override
    protected void createChallengeRequest(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        OMLog.info(OMSecurityConstants.TAG, "createChallengeRequest");
        mAuthServiceCallback = authServiceCallback;
        mAppCallback.onAuthenticationChallenge(mss, challenge, this);
    }


    @Override
    public void proceed(final Map<String, Object> responseFields) /*throws OMMobileSecurityException*/ {

        OMLog.info(OMSecurityConstants.TAG, "proceed");
        //all sorts of error checking and input validation handling.
        try {
            validateResponseFields(responseFields);
            mLoginWebViewHandler.configureView(responseFields, mAuthServiceCallback);
        } catch (OMMobileSecurityException e) {
            OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
            mAuthServiceCallback.onError(e.getError());
        }
    }

    @Override
    public void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {

        OMLog.info(TAG, "validateResponseFields");
        if (responseFields != null && !responseFields.isEmpty()) {
            if (responseFields.containsKey(WEBVIEW_KEY)) {
                Object webViewObj = responseFields.get(WEBVIEW_KEY);
                if (webViewObj instanceof WebView) {
                    // WebView is available. Hence proceed.
                    return;
                }
            }
        }
        throw new OMMobileSecurityException(OMErrorCode.WEB_VIEW_REQUIRED);
    }

    @Override
    public void cancel() {
        OMLog.trace(TAG, "cancel");
        if (mLoginWebViewHandler != null) {
            mLoginWebViewHandler.onCancel();
        } else {
            OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
        }
        if (mAuthServiceCallback != null) {
            mAuthServiceCallback.onCancel();
        } else {
            OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
        }

    }

    public AuthServiceInputCallback getAuthServiceCallback() {
        return mAuthServiceCallback;
    }
}
