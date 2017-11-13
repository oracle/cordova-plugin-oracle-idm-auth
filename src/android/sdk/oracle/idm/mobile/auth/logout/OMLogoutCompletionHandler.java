/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.logout;

import java.util.Map;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.OMAuthenticationChallenge;

/**
 * Base class for logout completion handlers for all authentication services.
 * Communication:
 * [AuthenticationService]                 --- createLogoutChallengeRequest ------> [OMLogoutCompletionHandler]
 * <p/>
 * [OMLogoutCompletionHandler]     --- onLogoutChallenge ---> [OMMobileSecurityServiceCallback]
 * <p/>
 * [OMMobileSecurityServiceCallback] --- proceed ---------------------> [OMLogoutCompletionHandler]
 * <p/>
 * [OMLogoutCompletionHandler]     --- onInput ------------> [AuthServiceInputCallback]
 * <p/>
 * ---alt
 * <p/>
 * [OMMobileSecurityServiceCallback] --- cancel ----------------------> [OMLogoutCompletionHandler]
 * <p/>
 * [OMLogoutCompletionHandler]     --- onCancel --------------------> [AuthServiceInputCallback]
 *
 * @since 11.1.2.3.1
 */
public abstract class OMLogoutCompletionHandler {
    /**
     *
     * @param mss
     * @param challenge
     * @param authServiceCallback
     * @hide
     */
    public abstract void createLogoutChallengeRequest(OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback);

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

    abstract void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException;

    /**
     * TODO public doc
     */
    public abstract void cancel();

}
