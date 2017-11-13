/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.util.Set;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.callback.OMHTTPRequestCallback;
import oracle.idm.mobile.logging.OMLog;

/**
 * Top level class to handle all the resource access in the SDK.
 * For now it support OAuth authorization.
 *
 * @since 11.1.2.3.1
 */
public class OMAuthorizationService {

    private static final String TAG = OMAuthorizationService.class.getSimpleName();

    private OMMobileSecurityService mMSS;

    public OMAuthorizationService(OMMobileSecurityService mss) {
        if (mss == null) {
            throw new IllegalArgumentException("OMMobileSecurityService can not be null");
        }
        mMSS = mss;
        OMLog.info(TAG, "initialized");
    }

    public OMHTTPResponse executeRequest(OMHTTPRequest request, Set<String> scopes) {
        return null;
    }

    /**
     * Executes an asynchronous request to access the OAuth protected resource for the given Set of scopes
     *
     * @param request
     * @param callback
     * @param scopes
     * @return
     */
    public void executeRequest(OMHTTPRequest request, OMHTTPRequestCallback callback, Set<String> scopes) {
        if (request == null) {
            throw new IllegalArgumentException("OMHTTPRequest can not be null");
        }
        OMAuthenticationContext authContext = null;
        try {
            authContext = mMSS.retrieveAuthenticationContext();
        } catch (OMMobileSecurityException e) {
            OMLog.error(TAG, e.getMessage(), e);
            callback.processHTTPResponse(request, null, e);
            return;
        }
        if (authContext != null) {

            OAuthHttpRequest oauthRequest = new OAuthHttpRequest(request.getResourceURL(), request.getMethod());
            oauthRequest.setPayloadType(request.getPayloadType());
            oauthRequest.setRawPayload(request.getRawPayload());
            oauthRequest.setScopes(scopes);

            new OAuthAuthorizationService(mMSS.getConnectionHandler()).handleAuthorization(oauthRequest, authContext, callback);
            return;
        } else {
            callback.processHTTPResponse(request, null, new OMMobileSecurityException(OMErrorCode.USER_NOT_AUTHENTICATED));
        }

    }

}
