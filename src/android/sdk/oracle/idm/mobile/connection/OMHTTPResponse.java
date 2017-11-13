/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.util.List;
import java.util.Map;

import oracle.idm.mobile.auth.OMCookie;

/**
 * This holds the response from the server. The body of the response is made
 * available as a String.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class OMHTTPResponse {
    private int mResponseCode;
    private String mResponseStringOnFailure;
    private String mResponseStringOnSuccess;
    private Map<String, List<String>> mResponseHeaders;
    private List<OMCookie> mCookies;
    private Map<String, List<String>> mVisitedUrlsCookiesMap;


    OMHTTPResponse() {

    }

    OMHTTPResponse setResponseStringOnSuccess(String response) {
        mResponseStringOnSuccess = response;
        return this;
    }

    OMHTTPResponse setResponseStringOnFailure(String response) {
        mResponseStringOnFailure = response;
        return this;
    }

    OMHTTPResponse setResponseCode(int responseCode) {
        mResponseCode = responseCode;
        return this;
    }

    OMHTTPResponse setResponseHeaders(Map<String, List<String>> headers) {
        mResponseHeaders = headers;
        return this;
    }


    public String getResponseStringOnSuccess() {
        return mResponseStringOnSuccess;
    }

    public String getResponseStringOnFailure() {
        return mResponseStringOnFailure;
    }

    public int getResponseCode() {
        return mResponseCode;
    }

    public Map<String, List<String>> getResponseHeaders() {
        return mResponseHeaders;
    }

    public List<OMCookie> getCookies() {
        return mCookies;
    }

    public void setCookies(List<OMCookie> cookies) {
        mCookies = cookies;
    }

    public Map <String,List<String>> getVisitedUrlsCookiesMap() {
        return mVisitedUrlsCookiesMap;
    }

    void setVisitedUrlsCookiesMap(Map <String,List<String>> visitedUrlsCookiesMap) {
        mVisitedUrlsCookiesMap = visitedUrlsCookiesMap;
    }
}
