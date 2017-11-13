/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Map;

import oracle.idm.mobile.OMErrorCode;

/**
 * Input controller between ASM and AuthenticationServices
 * <p/>
 * Communication:
 * [AuthenticationService]---->[ASM]
 *
 * Note: This is similar to OMInputParamCallback in the previous Headed SDK.
 * OMInputParamCallback is an interface which is used internally by the
 * {@link AuthenticationServiceManager} to collect the input from UI thread.
 *
 * @hide
 */
public interface ASMInputController {

    void onInputAvailable(Map<String, Object> input);

    void onInputError(OMErrorCode error);

    void onCancel();
}
