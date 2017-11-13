/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.callback;

import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.connection.OMHTTPRequest;
import oracle.idm.mobile.connection.OMHTTPResponse;

/**
 * {@link OMHTTPRequestCallback} is the call back invoked by the SDK after the
 * execution of {@link OMHTTPRequest}. Usage: This is used when the request to
 * be executed is an asynchronous request.
 *
 * @since 11.1.2.3.0
 */
public interface OMHTTPRequestCallback {
    /**
     * This callback will be invoked once the HTTPRequest is completed.
     *
     * @param request
     * @param response
     * @param exception
     */
    public void processHTTPResponse(OMHTTPRequest request,
                                    OMHTTPResponse response, OMMobileSecurityException exception);
}
