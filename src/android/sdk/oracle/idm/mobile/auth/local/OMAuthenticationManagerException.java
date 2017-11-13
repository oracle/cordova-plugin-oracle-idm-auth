/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import oracle.idm.mobile.BaseCheckedException;
import oracle.idm.mobile.OMErrorCode;

/**
 * Authentication related exception.
 */
public class OMAuthenticationManagerException extends BaseCheckedException {
    public OMAuthenticationManagerException(OMErrorCode errorCode) {
        super(errorCode);
    }

    public OMAuthenticationManagerException(OMErrorCode errorCode, String detailMessage) {
        super(errorCode, detailMessage);
    }

    public OMAuthenticationManagerException(OMErrorCode errorCode, Throwable throwable) {
        super(errorCode, throwable);
    }

    public OMAuthenticationManagerException(OMErrorCode errorCode, String detailMessage, Throwable throwable) {
        super(errorCode, detailMessage, throwable);
    }
}
