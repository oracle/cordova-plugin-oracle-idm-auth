/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import oracle.idm.mobile.BaseCheckedException;
import oracle.idm.mobile.OMErrorCode;

/**
 * Secure storage related exception.
 */
public class OMSecureStorageException extends BaseCheckedException {

    public OMSecureStorageException(OMErrorCode errorCode) {
        super(errorCode);
    }

    public OMSecureStorageException(OMErrorCode errorCode, String detailMessage) {
        super(errorCode, detailMessage);
    }

    public OMSecureStorageException(OMErrorCode errorCode, String detailMessage, Throwable throwable) {
        super(errorCode, detailMessage, throwable);
    }

    public OMSecureStorageException(OMErrorCode errorCode, Throwable throwable) {
        super(errorCode, throwable);
    }
}
