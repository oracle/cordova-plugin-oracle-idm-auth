/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile;

import android.text.TextUtils;

/**
 * Base class for all checked exception classes for SDK.
 *
 */
public abstract class BaseCheckedException extends Exception {

    private final OMErrorCode errorCode;

    /**
     * Construct new instance of this class based on <code>OMErrorCode</code>
     * @param errorCode
     */
    public BaseCheckedException(OMErrorCode errorCode) {
        super(errorCode.getErrorString());
        this.errorCode = errorCode;
    }

    /**
     * OMErrorCode along with detail message.
     * @param errorCode
     * @param detailMessage
     */
    public BaseCheckedException(OMErrorCode errorCode, String detailMessage) {
        super(detailMessage);
        this.errorCode = errorCode;
    }

    /**
     * OMErrorCode and cause for this exception.
     * @param errorCode
     * @param throwable
     */
    public BaseCheckedException(OMErrorCode errorCode, Throwable throwable) {
        super(throwable);
        this.errorCode = errorCode;
    }

    /**
     * Includes the cause of exception.
     * @param errorCode
     * @param detailMessage
     * @param throwable
     */
    public BaseCheckedException(OMErrorCode errorCode, String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
        this.errorCode = errorCode;
    }

    @Override
    public String getMessage() {
        String message =  super.getMessage();
        return !TextUtils.isEmpty(message) ? message : errorCode.getErrorString();
    }


    /**
     * A 'numeric' error code that uniquely identifies this error.
     * @return
     */
    public String getErrorCode() {
        return this.errorCode.getErrorCode();
    }

    /**
     * Error description from underlying {@link OMErrorCode} for this exception.
     * @return
     */
    public String getErrorDescription() {
        return errorCode.getErrorDescription();
    }

    /**
     * The underlying source of this exception.
     * @return
     */
    public OMErrorCode getError() {
        return errorCode;
    }
}
