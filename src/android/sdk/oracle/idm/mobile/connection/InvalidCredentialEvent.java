/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import oracle.idm.mobile.OMExceptionEvent;

/**
 * Exception event due to invalid credentials.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class InvalidCredentialEvent implements OMExceptionEvent {
    private static final long serialVersionUID = 6827025274292447610L;
    private int mRetryCount;

    @Override
    public OMExceptionEventType getExceptionEventType() {
        return OMExceptionEventType.INVALID_LOGIN_CREDENTIALS;
    }

    public int getRetryCount() {
        return mRetryCount;
    }

    public void setRetryCount(int retryCount) {
        mRetryCount = retryCount;
    }
}
