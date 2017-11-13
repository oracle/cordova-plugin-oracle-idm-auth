/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import oracle.idm.mobile.OMExceptionEvent;

/**
 * Exception Event that represents an invalid redirect.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class InvalidRedirectExceptionEvent implements OMExceptionEvent {

    private static final long serialVersionUID = 8855166278541337108L;
    private Type mType;

    public enum Type {
        HTTPS_TO_HTTP,
        HTTP_TO_HTTPS,
        UNKNOWN;//can be extended handle further redirection scenarios,
    }

    private boolean httpsToHttp;
    private String mCause;

    InvalidRedirectExceptionEvent(Type redirectionType) {
        mType = redirectionType;
    }

    @Override

    public OMExceptionEventType getExceptionEventType() {
        return OMExceptionEventType.INVALID_REDIRECT;
    }


    public Type getRedirectionType() {
        return mType;
    }
}
