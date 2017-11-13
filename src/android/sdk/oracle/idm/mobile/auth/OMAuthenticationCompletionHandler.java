/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.*;

/**
 * Base class for completion handlers for all authentication services.
 * Communication:
 * [AuthenticationService]                 --- createChallengeRequest ------> [OMAuthenticationCompletionHandler]
 * <p/>
 * [OMAuthenticationCompletionHandler]     --- onAuthenticationChallenge ---> [OMMobileSecurityServiceCallback]
 * <p/>
 * [OMMobileSecurityServiceCallback]       --- proceed ---------------------> [OMAuthenticationCompletionHandler]
 * <p/>
 * [OMAuthenticationCompletionHandler]     --- onInputAvailable ------------> [AuthenticationServiceManager]
 * <p/>
 * ---alt
 * <p/>
 * [OMMobileSecurityServiceCallback] --- cancel ----------------------> [OMAuthenticationCompletionHandler]
 * <p/>
 * [OMAuthenticationCompletionHandler]     --- onCancel --------------------> [AuthenticationServiceManager]
 */
public abstract class OMAuthenticationCompletionHandler {
    private static final String TAG = OMAuthenticationCompletionHandler.class.getSimpleName();
    protected OMMobileSecurityServiceCallback mAppCallback;
    protected ASMInputController mChallengeInputCallback;
    protected OMMobileSecurityConfiguration mConfig;

    protected OMAuthenticationCompletionHandler(OMMobileSecurityConfiguration config, OMMobileSecurityServiceCallback appCallback) {
        mConfig = config;
        mAppCallback = appCallback;
    }

    /**
     * TODO Rename this to much descriptive
     * If the completion handler is registered, the authentication service will invoke this method. The completion handler should invoke application callback to get the inputs required to complete the authentication.
     *
     * @param mas
     * @param challenge
     * @param authServiceCallback
     */
    protected abstract void createChallengeRequest(OMMobileSecurityService mas, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback);

    /**
     * Components registered(OMMobileSecurityServiceCallback) for authentication should call this to provide the challenge input response to proceed with authentication.
     *
     * @param responseFields
     */
    public abstract void proceed(Map<String, Object> responseFields) /*throws OMMobileSecurityException*/;

    /**
     * This method can be used to validate the input response collected after getting onAuthenticationChallenge.
     * <p/>
     * Note: In order to avoid issues and authentication failure, it is recommended that the registered components use this to check whether the response data or data format is in correct format or not?
     *
     * @param responseFields
     * @return
     */

    public abstract void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException;

    /**
     * Method to cancel the authentication
     */
    public abstract void cancel();

    /*
    This method can be used to validate the input response collected after getting onAuthenticationChallenge where challenge type is USERNAME_PWD_REQUIRED
    */
    public void validateUsernamePasswordResponse(Map<String, Object> responseFields) throws OMMobileSecurityException {
        OMLog.trace(TAG, " validateUsernamePasswordResponse");
        //throw the exception present in responseFields
        if (responseFields != null && responseFields.containsKey(MOBILE_SECURITY_EXCEPTION)) {
            OMMobileSecurityException exception = (OMMobileSecurityException) responseFields.get(MOBILE_SECURITY_EXCEPTION);
            if (exception != null) {
                throw exception;
            }
        }
        if (responseFields == null || responseFields.isEmpty()) {
            throw new OMMobileSecurityException(OMErrorCode.USERNAME_REQUIRED);
        }

        String username = (String) responseFields.get(USERNAME_KEY);
        String password = (String) responseFields.get(PASSWORD_KEY);
        String identityDomain = (String) responseFields.get(IDENTITY_DOMAIN_KEY);

        boolean usernameMissing = false;
        if (TextUtils.isEmpty(username)) {
            usernameMissing = true;
        }

        boolean identityDomainMissing = false;
        if (mConfig.isCollectIdentityDomain() && TextUtils.isEmpty(identityDomain)) {
            identityDomainMissing = true;
        }

        if (usernameMissing && identityDomainMissing) {
            throw new OMMobileSecurityException(OMErrorCode.USERNAME_AND_IDENTITY_DOMAIN_REQUIRED);
        } else if (usernameMissing) {
            throw new OMMobileSecurityException(OMErrorCode.USERNAME_REQUIRED);
        } else if (identityDomainMissing) {
            throw new OMMobileSecurityException(OMErrorCode.IDENTITY_DOMAIN_REQUIRED);
        }

        if (TextUtils.isEmpty(password)) {
            throw new OMMobileSecurityException(OMErrorCode.PASSWORD_REQUIRED);
        }
    }
}
