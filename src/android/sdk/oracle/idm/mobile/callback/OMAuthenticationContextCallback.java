/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.callback;

import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.auth.OMAuthenticationContext.TimeoutType;

/**
 * {@link OMAuthenticationContextCallback} is an interface which can be
 * implemented by any calling client application to receive the control to them
 * after an timeout occurs
 * {@link OMAuthenticationContext} is done.
 * 
 *
 */
public interface OMAuthenticationContextCallback
{
    /**
     * This method will be called by the SDK after timeout occurs.
     * 
     * @param timeoutType
     *            The {@link TimeoutType} represents type of timeout occured.
     * @param timeLeftToTimeout
     *            Time left to timeout in seconds.
     **/
    public void onTimeout(TimeoutType timeoutType, long timeLeftToTimeout);
}
