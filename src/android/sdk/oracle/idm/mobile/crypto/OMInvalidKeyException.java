/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import oracle.idm.mobile.OMErrorCode;

/**
 * When a user provided key is not the same that used to encypt the data.
 */
public class OMInvalidKeyException extends OMKeyManagerException {
    public OMInvalidKeyException(OMErrorCode errorCode) {
        super(errorCode);
    }

    public OMInvalidKeyException(OMErrorCode errorCode, String detailMessage) {
        super(errorCode, detailMessage);
    }

    public OMInvalidKeyException(OMErrorCode errorCode, String detailMessage, Throwable throwable) {
        super(errorCode, detailMessage, throwable);
    }

    public OMInvalidKeyException(OMErrorCode errorCode, Throwable throwable) {
        super(errorCode, throwable);
    }
}
