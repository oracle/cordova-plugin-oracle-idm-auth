/*
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

/**
 * Authentication service to obtain new access tokens using refresh token.
 */

public class RefreshTokenAuthenticationService extends AuthenticationService {

    private static final String TAG = RefreshTokenAuthenticationService.class.getSimpleName();

    RefreshTokenAuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, ASMInputController inputController) {
        OMLog.trace(TAG, "collectChallengeInput");
        inputController.onInputAvailable(inputParams);
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.trace(TAG, "handleAuthentication");
        if (authContext.getStatus() == null || authContext.getStatus() == OMAuthenticationContext.Status.IN_PROGRESS) {
            boolean isValid = authContext.isValid(mASM.getOAuthConnectionsUtil().getOAuthScopes(), true);
            if (isValid) {
                authContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
            } else {
                /*This will make sure that regular authentication flow is
                * taken to proceed with authentication.*/
                authContext.setStatus(OMAuthenticationContext.Status.IN_PROGRESS);
            }
        }
        return null;
    }

    @Override
    public void cancel() {

    }

    @Override
    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {
        return true;
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {

    }

    @Override
    public void collectLogoutChallengeInput(Map<String, Object> inputParams, AuthServiceInputCallback callback) {

    }

    @Override
    public void handleLogout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {

    }

    @Override
    public Type getType() {
        return null;
    }
}
