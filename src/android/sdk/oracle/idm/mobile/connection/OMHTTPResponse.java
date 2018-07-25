/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.net.HttpURLConnection;
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
    private String mResponseMessage;
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

    OMHTTPResponse setResponseMessage(String responseMessage) {
        mResponseMessage = responseMessage;
        return this;
    }

    OMHTTPResponse setResponseHeaders(Map<String, List<String>> headers) {
        mResponseHeaders = headers;
        return this;
    }


    /**
     * Returns the {@link HttpURLConnection#getInputStream()} in String format.
     */
    public String getResponseStringOnSuccess() {
        return mResponseStringOnSuccess;
    }

    /**
     * Returns the {@link HttpURLConnection#getErrorStream()} in String format.
     */
    public String getResponseStringOnFailure() {
        return mResponseStringOnFailure;
    }

    public int getResponseCode() {
        return mResponseCode;
    }

    /**
     * Returns {@link HttpURLConnection#getResponseMessage()}.
     */
    public String getResponseMessage() {
        return mResponseMessage;
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

    public Map<String, List<String>> getVisitedUrlsCookiesMap() {
        return mVisitedUrlsCookiesMap;
    }

    void setVisitedUrlsCookiesMap(Map<String, List<String>> visitedUrlsCookiesMap) {
        mVisitedUrlsCookiesMap = visitedUrlsCookiesMap;
    }

    /**
     * Creates error message which can be shown to user on failure during
     * authentication, logout, etc.
     * Format of error message:
     * Error Code - Error Response message
     */
    public String constructErrorMessage() {
        int statusCode = getResponseCode();
        return Integer.toString(statusCode) + " - " + getResponseMessage();
    }

    /**
     * Returns true if response code is in 200 series.
     */
    public boolean isSuccess() {
        return mResponseCode / 100 == 2;
    }

    /**
     * Returns true if response code is in 400 series.
     */
    public boolean isClientError() {
        return mResponseCode / 100 == 4;
    }

    /**
     * Returns true if response code is in 500 series.
     */
    public boolean isServerError() {
        return mResponseCode / 100 == 5;
    }
}
