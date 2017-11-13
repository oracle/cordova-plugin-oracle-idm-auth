/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;

class OfflineAuthCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = OfflineAuthCompletionHandler.class.getSimpleName();
    private AuthServiceInputCallback mAuthServiceCallback;

    //config, or some light weight version of config
    //TODO
    private OMMobileSecurityConfiguration mConfig;

    OfflineAuthCompletionHandler(OMMobileSecurityConfiguration config, OMMobileSecurityServiceCallback appCallback) {
        super(config, appCallback);
        mConfig = config;
    }

    @Override
    protected void createChallengeRequest(OMMobileSecurityService mas, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
       OMLog.trace(TAG, "createChallengeRequest");
        mAuthServiceCallback = authServiceCallback;
        mAppCallback.onAuthenticationChallenge(mas, challenge, this);
    }


    @Override
    public void proceed(final Map<String, Object> responseFields) {

        OMLog.trace(TAG, "proceed");
        //all sorts of error checking and input validation handling.
        try {
            validateResponseFields(responseFields);
            mAuthServiceCallback.onInput(responseFields);
        } catch (OMMobileSecurityException e) {
            OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
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
        if(mAuthServiceCallback != null) {
            mAuthServiceCallback.onCancel();
        }
    }
}
