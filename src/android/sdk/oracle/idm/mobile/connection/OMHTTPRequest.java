/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.net.URL;


/**
 * This class is used to execute the HTTP Requests . The class provides access
 * to OAuth2.0 specific resources by injecting the appropriate tokens if available .
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class OMHTTPRequest {

    private static final String TAG = OMHTTPRequest.class.getSimpleName();

    public static int REQUIRE_RESPONSE_CODE = 1;
    public static int AUTHENTICATION_REQUEST = REQUIRE_RESPONSE_CODE << 1;
    public static int REQUIRE_RESPONSE_STRING = REQUIRE_RESPONSE_CODE << 2;
    public static int REQUIRE_RESPONSE_HEADERS = REQUIRE_RESPONSE_CODE << 3;


    protected URL mResourceURL;
    protected Method mMethod;
    protected String mRawPayload;
    protected String mPayloadType;

    public enum Method {
        GET,
        POST,
        PUT,
        DELETE,
        PATCH;
    }

    public OMHTTPRequest(URL resourceURL, Method method) {
        mResourceURL = resourceURL;
        mMethod = method;
    }

    public void setRawPayload(String payload) {
        mRawPayload = payload;
    }

    public void setPayloadType(String payloadType) {
        mPayloadType = payloadType;
    }

    public String getRawPayload() {
        return mRawPayload;
    }

    public String getPayloadType() {
        return mPayloadType;
    }


    public URL getResourceURL() {
        return mResourceURL;
    }

    public Method getMethod() {
        return mMethod;
    }

}
