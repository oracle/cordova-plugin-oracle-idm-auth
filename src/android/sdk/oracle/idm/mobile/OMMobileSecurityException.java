/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile;

/**
 * OMMobileSecurityException is the exception class defined for the SDK which
 * will be thrown back to the calling business application on any error
 * conditions.
 *
 * @since 11.1.2.3.1
 */
public class OMMobileSecurityException extends Exception {

    private static final long serialVersionUID = 3748426749199372917L;
    private OMErrorCode mErrorCode;
    private Throwable mCause;
    private OMExceptionEvent mEvent;
    private String additionalInfo;

    public OMMobileSecurityException(OMErrorCode errorCode, Throwable cause) {
        super(errorCode.getErrorString() + " : " + cause.getMessage());
        mCause = cause;
        mErrorCode = errorCode;
    }

    public OMMobileSecurityException(OMErrorCode errorCode) {
        super(errorCode.getErrorString());
        mErrorCode = errorCode;
    }

    public OMMobileSecurityException(OMErrorCode errorCode, OMExceptionEvent event) {
        this(errorCode);
        mEvent = event;
    }

    public OMMobileSecurityException(OMErrorCode errorCode, OMExceptionEvent event, Throwable cause) {
        this(errorCode, event);
        mCause = cause;
    }

    public OMMobileSecurityException(OMErrorCode errorCode, String additionalInfo) {
        super(errorCode.getErrorString() + ": " + additionalInfo);
        mErrorCode = errorCode;
        this.additionalInfo = additionalInfo;
    }

    public String getErrorCode() {
        return mErrorCode.getErrorCode();
    }

    public Throwable getCause() {
        return mCause;
    }

    /*package*///TODO
    public OMExceptionEvent getExceptionEvent() {
        return mEvent;
    }

    public String getErrorMessage() {
        if (additionalInfo == null) {
            return mErrorCode.getErrorString();
        } else {
            /*getMessage() contains error string from OMErrorCode combined with additionalInfo
            * as we use super(errorCode.getErrorString() + ": " + additionalInfo);*/
            return getMessage();
        }
    }

    public String getErrorDescription() {
        return mErrorCode.getErrorDescription();
    }


    public OMErrorCode getError() {
        return mErrorCode;
    }
}

