/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.webkit.HttpAuthHandler;

import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;


class OAuthMSPreAuthzCodeAuthCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = OAuthMSPreAuthzCodeAuthCompletionHandler.class.getSimpleName();
    private AuthServiceInputCallback mAuthServiceCallback;

    private OMMobileSecurityConfiguration mConfig;
    private Map<String, Object> mInputParams;
    private boolean mWebViewAuthentication;
    private HttpAuthHandler mHttpAuthHandler;
    private AuthenticationServiceManager mAsm;

    OAuthMSPreAuthzCodeAuthCompletionHandler(AuthenticationServiceManager asm, OMMobileSecurityServiceCallback appCallback, HttpAuthHandler httpAuthHandler, Map<String, Object> inputParams) {
        this(asm.getMSS().getMobileSecurityConfig(), appCallback);
        mInputParams = inputParams;
        mWebViewAuthentication = (httpAuthHandler != null);
        mHttpAuthHandler = httpAuthHandler;
    }

    OAuthMSPreAuthzCodeAuthCompletionHandler(OMMobileSecurityConfiguration basicAuthConfig, OMMobileSecurityServiceCallback appCallback) {
        super(basicAuthConfig, appCallback);
        mConfig = basicAuthConfig;
    }

    @Override
    protected void createChallengeRequest(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        OMLog.trace(TAG, " createChallengeRequest");
        mAuthServiceCallback = authServiceCallback;
        mAppCallback.onAuthenticationChallenge(mss, challenge, this);
    }


    @Override
    public void proceed(final Map<String, Object> responseFields) /*throws OMMobileSecurityException*/ {

        OMLog.trace(TAG, " proceed");
            //all sorts of error checking and input validation handling.
            try {
                validateResponseFields(responseFields);
                mAuthServiceCallback.onInput(responseFields);
            } catch (OMMobileSecurityException e) {
                OMLog.debug(TAG, "Response Fields are not valid. Error : " + e.getErrorMessage());
                mAuthServiceCallback.onError(e.getError());
        }
    }

    @Override
    public void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {
        OMLog.trace(TAG, " validateResponseFields");
        validateUsernamePasswordResponse(responseFields);
    }

    @Override
    public void cancel() {
        OMLog.trace(TAG, "cancel");
            if (mAuthServiceCallback != null) {
                mAuthServiceCallback.onCancel();
            }
            else {
                OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
            }
        }
}
