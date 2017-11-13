/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.logout;

import android.webkit.WebView;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.OMAuthenticationChallenge;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.WEBVIEW_KEY;

/**
 * @since 11.1.2.3.1
 */
public class FedAuthLogoutCompletionHandler extends OMLogoutCompletionHandler {
    private static final String TAG = FedAuthLogoutCompletionHandler.class.getSimpleName();
    protected OMMobileSecurityServiceCallback mAppCallback;
    private AuthServiceInputCallback mAuthServiceCallback;

    public FedAuthLogoutCompletionHandler(OMMobileSecurityServiceCallback appCallback) {
        mAppCallback = appCallback;
    }

    @Override
    public void createLogoutChallengeRequest(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        OMLog.info(TAG, "create Logout ChallengeRequest");
        mAuthServiceCallback = authServiceCallback;
        mAppCallback.onLogoutChallenge(mss, challenge, this);
    }

    @Override
    public void proceed(Map<String, Object> responseFields) {
        OMLog.info(TAG, "proceed");
        try {
            validateResponseFields(responseFields);
            mAuthServiceCallback.onInput(responseFields);
        } catch (OMMobileSecurityException e) {
            OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
            //Session cookies are cleared in mAuthServiceCallback.onError
            mAuthServiceCallback.onError(e.getError());
        }
    }

    @Override
    void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {
        OMLog.info(TAG, "validateResponseFields");
        if (responseFields != null && !responseFields.isEmpty()) {
            if(responseFields.containsKey(WEBVIEW_KEY)) {
                Object webViewObj = responseFields.get(WEBVIEW_KEY);
                if(webViewObj instanceof WebView) {
                    // WebView is available. Hence proceed.
                    return;
                }
            }
        }
        throw new OMMobileSecurityException(OMErrorCode.WEB_VIEW_REQUIRED);
    }

    @Override
    public void cancel() {
        OMLog.info(TAG, "cancel");
        if (mAuthServiceCallback != null) {
            mAuthServiceCallback.onCancel();
        }
    }

    public OMMobileSecurityServiceCallback getAppCallback() {
        return mAppCallback;
    }
}
