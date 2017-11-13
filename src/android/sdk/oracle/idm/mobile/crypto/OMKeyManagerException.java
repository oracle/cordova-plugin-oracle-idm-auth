/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import oracle.idm.mobile.BaseCheckedException;
import oracle.idm.mobile.OMErrorCode;

/**
 * Key manager related exception.
 */
public class OMKeyManagerException extends BaseCheckedException {

    public OMKeyManagerException(OMErrorCode errorCode) {
        super(errorCode);
    }

    public OMKeyManagerException(OMErrorCode errorCode, String detailMessage) {
        super(errorCode, detailMessage);
    }

    public OMKeyManagerException(OMErrorCode errorCode, String detailMessage, Throwable throwable) {
        super(errorCode, detailMessage, throwable);
    }

    public OMKeyManagerException(OMErrorCode errorCode, Throwable throwable) {
        super(errorCode, throwable);
    }
}
