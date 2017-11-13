/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;

/**
 * Callback interface for communication between
 * [AuthCompletionHandlers]     ---> [AuthenticationService]
 * --- or
 * [LogoutOutCompletionHandler] ---> [AuthenticationService]
 * <p/>
 * The authentication handlers can provide the following results:
 * Inputs for the challenge(in Map)
 * Report Error if the inputs sent are not in proper format(types etc) or are invalid
 * If the the app selects to cancel the challenge request when prompted.
 * <p/>
 * Note: This is similar to OMCredentialCollectorCallback in the previous Headed SDK.
 * The main purpose of this interface is to define internal callbacks to obtain credentials
 * from SDK consumer via AuthCompletionHandlers.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public interface AuthServiceInputCallback {

    void onInput(Map<String, Object> inputs);

    void onError(OMErrorCode error);

    void onCancel();
}
