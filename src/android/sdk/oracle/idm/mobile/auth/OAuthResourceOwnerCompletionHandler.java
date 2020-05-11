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

/**
 * OMAuthenticationCompletionHandler implementation for handling OAuth resource_owner grant type.
 *
 * @since 11.1.2.3.1
 */
class OAuthResourceOwnerCompletionHandler extends OMAuthenticationCompletionHandler {

    private static final String TAG = OAuthResourceOwnerCompletionHandler.class.getSimpleName();
    private AuthServiceInputCallback mAuthServiceCallback;

    //TODO config, or some light weight version of config
    private OMMobileSecurityConfiguration mConfig;

    protected OAuthResourceOwnerCompletionHandler(AuthenticationServiceManager asm,
                                                  OMMobileSecurityConfiguration config,
                                                  OMMobileSecurityServiceCallback appCallback) {
        super(asm, config, appCallback);
        mConfig = config;
    }

    @Override
    protected void createChallengeRequest(OMMobileSecurityService mas, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
        OMLog.trace(TAG, " createChallengeRequest");
        mAuthServiceCallback = authServiceCallback;
        mAppCallback.onAuthenticationChallenge(mas, challenge, this);
    }

    @Override
    public void proceed(Map<String, Object> responseFields) {
        OMLog.trace(TAG, " proceed");
        //all sorts of error checking and input validation handling.
        try {
            validateResponseFields(responseFields);
            mAuthServiceCallback.onInput(responseFields);
        } catch (OMMobileSecurityException e) {
            OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
            storeChallengeInputTemporarily(responseFields);
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
        OMLog.trace(TAG, " cancel");
        if (mAuthServiceCallback != null) {
            mAuthServiceCallback.onCancel();
        }
    }
}
