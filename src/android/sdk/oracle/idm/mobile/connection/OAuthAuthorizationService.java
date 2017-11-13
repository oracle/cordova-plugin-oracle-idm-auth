/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import android.os.AsyncTask;

import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.auth.OAuthToken;
import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.auth.OMToken;
import oracle.idm.mobile.callback.OMHTTPRequestCallback;
import oracle.idm.mobile.logging.OMLog;

/**
 * This class handles Authorization request with OAuth servers.
 *
 */
class OAuthAuthorizationService {
    private static final String TAG = OAuthAuthorizationService.class.getSimpleName();
    // For access token
    private static final String BEARER = "Bearer";
    private static final String AUTHORIZATION = "Authorization";
    // for logging
    private static final String className = OAuthAuthorizationService.class
            .getName();
    private OMMobileSecurityService mMSS;
    private OMConnectionHandler mConnectionHandler;

    protected OAuthAuthorizationService(OMConnectionHandler connHandler) {
        OMLog.info(TAG, "initialized");
        mConnectionHandler = connHandler;
    }


    protected OMHTTPResponse handleAuthorization(OAuthHttpRequest httpRequest, OMAuthenticationContext authContext)
            throws OMMobileSecurityException {
        return executeRequest(httpRequest, authContext);
    }

    protected OMHTTPResponse handleAuthorization(OAuthHttpRequest httpRequest,
                                                 OMAuthenticationContext authContext, OMHTTPRequestCallback callback) {
        new ExecuteRequestTask(httpRequest, authContext, callback, this).execute();
        return null;
    }

    private OMHTTPResponse executeRequest(OAuthHttpRequest httpRequest,
                                          OMAuthenticationContext authContext) throws OMMobileSecurityException {
        // this will check validity and refresh if the matching token is
        // expired .
        Set<String> scopes = httpRequest.getScopes();
        if (!authContext.isValid(scopes, true)) {
            throw new OMMobileSecurityException(
                    OMErrorCode.OAUTH_CONTEXT_INVALID);
        }
        ArrayList<OMToken> availableAccessTokens = (ArrayList<OMToken>) authContext
                .getTokens(scopes);
        OAuthToken accessToken = null;
        for (OMToken token : availableAccessTokens) {
            OAuthToken oauthToken = (OAuthToken) token;
            if (oauthToken.getScopes() != null
                    && oauthToken.getScopes().containsAll(scopes)) {
                if (!oauthToken.isTokenExpired()) {
                    accessToken = oauthToken;
                    break;
                }
            }
        }
        // 1. Execute http request to the resource url


        OMHTTPRequest.Method method = httpRequest.getMethod();
        URL resourceURL = httpRequest.getResourceURL();
        if (resourceURL != null) {
            OMLog.info(TAG, "Method: " + method + "requested on URL : " + resourceURL.toString());
            Map<String, String> headers = new HashMap<>();
            headers.put(AUTHORIZATION, BEARER + " " + accessToken.getValue());
            OMHTTPResponse response = null;
            int requestFlags = (OMHTTPRequest.REQUIRE_RESPONSE_CODE |
                    OMHTTPRequest.REQUIRE_RESPONSE_STRING | OMHTTPRequest.REQUIRE_RESPONSE_HEADERS);
            if (OMHTTPRequest.Method.GET == method) {
                response = mConnectionHandler.httpGet(resourceURL, headers);
            } else if (OMHTTPRequest.Method.POST == method) {
                String payload = httpRequest.getRawPayload();
                String payloadType = httpRequest.getPayloadType();
                response = mConnectionHandler.httpPost(resourceURL, headers, payload, payloadType, requestFlags);
            } else if (OMHTTPRequest.Method.PUT == method) {
                String payload = httpRequest.getRawPayload();
                String payloadType = httpRequest.getPayloadType();
                response = mConnectionHandler.httpPut(resourceURL, headers, payload, payloadType, requestFlags);
            } else if (OMHTTPRequest.Method.PATCH == method) {
                String payload = httpRequest.getRawPayload();
                String payloadType = httpRequest.getPayloadType();
                response = mConnectionHandler.httpPatch(resourceURL, headers, payload, payloadType, requestFlags);
            } else {
                throw new OMMobileSecurityException(OMErrorCode.OAUTH_AUTHORIZATION_METHOD_NOT_SUPPORTED);
            }

            if (response != null) {
                if (response.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
                    throw new OMMobileSecurityException(
                            OMErrorCode.OAUTH_CONTEXT_INVALID);
                }
                return response;
            } else {
                OMLog.debug(TAG, "Response null for the request!");
            }
        }
        return null;
    }

    /**
     * static inner class to execute the rest request asynchronously
     *
     */
    private static class ExecuteRequestTask extends
            AsyncTask<Void, Void, OMHTTPResponse> {
        private final String TAG = ExecuteRequestTask.class.getName();
        private OMAuthenticationContext authContext;
        private OAuthHttpRequest omRequest;
        private OMMobileSecurityException exception = null;
        private OMHTTPRequestCallback callback;
        private WeakReference<OAuthAuthorizationService> wReference;
        private OMHTTPRequest.Method method;

        ExecuteRequestTask(OAuthHttpRequest httpRequest,
                           OMAuthenticationContext authContext,
                           OMHTTPRequestCallback callback, OAuthAuthorizationService reference) {
            super();
            this.authContext = authContext;
            this.omRequest = httpRequest;
            this.callback = callback;
            this.wReference = new WeakReference<OAuthAuthorizationService>(
                    reference);

        }

        @Override
        protected OMHTTPResponse doInBackground(Void... params) {

            try {
                OAuthAuthorizationService instance = wReference.get();
                if (instance != null)
                    return instance.executeRequest(omRequest, authContext);
                else {
                    OMLog.debug(TAG, "unable get instance of AuthZ service");
                }
            } catch (OMMobileSecurityException e) {
                exception = e;
            }
            return null;
        }

        @Override
        protected void onPostExecute(OMHTTPResponse result) {
            if (result == null) {
                OMLog.debug(TAG, "execute request failed ");
                if (exception != null) {
                    //handle exception handling
                } else {
                    exception = new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);//TODO ajulka change to to some thing more useful

                }
            }
            callback.processHTTPResponse(omRequest, result, exception);
        }
    }
}
