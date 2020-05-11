/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.webkit.HttpAuthHandler;

import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.ArrayUtils;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.*;


class BasicAuthCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = BasicAuthCompletionHandler.class.getSimpleName();
    private AuthServiceInputCallback mAuthServiceCallback;

    //config, or some light weight version of config
    //TODO
    private OMMobileSecurityConfiguration mConfig;
    private Map<String, Object> mInputParams;
    private boolean mWebViewAuthentication;
    private HttpAuthHandler mHttpAuthHandler;
    /**
     * In case of Basic authentication using Embedded browser, BasicAuthCompletionHandler class
     * should delegate the control to FedAuthCompletionHandler for cancel operation. So, mFedAuthCompletionHandler
     * is assigned the same FedAuthCompletionHandler instance which got created in ASM during the authentication attempt.
     */
    private FedAuthCompletionHandler mFedAuthCompletionHandler;

    BasicAuthCompletionHandler(AuthenticationServiceManager asm, OMMobileSecurityServiceCallback appCallback,
                               HttpAuthHandler httpAuthHandler, Map<String, Object> inputParams) {
        this(asm, asm.getMSS().getMobileSecurityConfig(), appCallback);
        mInputParams = inputParams;
        mWebViewAuthentication = (httpAuthHandler != null);
        mHttpAuthHandler = httpAuthHandler;
        if (mWebViewAuthentication) {
            mFedAuthCompletionHandler = (FedAuthCompletionHandler) asm.getAuthenticationCompletionHandler(AuthenticationService.Type.FED_AUTH_SERVICE);
        }
    }

    BasicAuthCompletionHandler(AuthenticationServiceManager asm, OMMobileSecurityConfiguration basicAuthConfig,
                               OMMobileSecurityServiceCallback appCallback) {
        super(asm, basicAuthConfig, appCallback);
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
        if (mWebViewAuthentication) {
            try {
                validateResponseFields(responseFields);
                String username = (String) responseFields.get(USERNAME_KEY);
                mInputParams.put(OMSecurityConstants.Challenge.USERNAME_KEY, username);
                char[] password = (char[]) responseFields.get(PASSWORD_KEY_2);
                if (!ArrayUtils.isEmpty(password)) {
                    /*HttpAuthHandler#proceed(String username, String password) requires password
                    as String. Hence, have to create a String as follows.*/
                    mHttpAuthHandler.proceed(username, new String(password));
                } else {
                    mHttpAuthHandler.proceed(username, (String) responseFields.get(PASSWORD_KEY));
                }
            } catch (OMMobileSecurityException e) {
                OMLog.debug(TAG, "Response Fields are not valid. Error : " + e.getErrorMessage());
                AuthServiceInputCallback authServiceInputCallback = mFedAuthCompletionHandler.getAuthServiceCallback();
                if (authServiceInputCallback != null) {
                    authServiceInputCallback.onError(e.getError());
                }
            }
        } else {
            //all sorts of error checking and input validation handling.
            try {
                validateResponseFields(responseFields);
                mAuthServiceCallback.onInput(responseFields);
            } catch (OMMobileSecurityException e) {
                OMLog.debug(TAG, "Response Fields are not valid. Error : " + e.getErrorMessage());
                storeChallengeInputTemporarily(responseFields);
                mAuthServiceCallback.onError(e.getError());
            }
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
        if (mWebViewAuthentication) {
            /*The following order MUST be maintained:
            1. mFedAuthCompletionHandler.cancel()
            2. mHttpAuthHandler.cancel()
            This is because mFedAuthCompletionHandler sets a boolean variable which in turn is used in
            onPageFinished(). If mHttpAuthHandler.cancel() is called first, then the  boolean variable
             will not be set, leading to false successful authentication in certain scenarios.
            */
            if (mFedAuthCompletionHandler != null) {
                mFedAuthCompletionHandler.cancel();
            } else {
                OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
            }
            mHttpAuthHandler.cancel();
        } else {
            if (mAuthServiceCallback != null) {
                mAuthServiceCallback.onCancel();
            } else {
                OMLog.error(TAG, "Something went wrong. Cannot return control back to app.");
            }
        }
    }
}
