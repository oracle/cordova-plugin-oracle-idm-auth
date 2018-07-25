/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

/**
 * Created by ajulka on 3/1/2016.
 */
class CBAAuthenticationService extends AuthenticationService {

    private static final String TAG = CBAAuthenticationService.class.getSimpleName();

    CBAAuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
        OMLog.info(TAG, "Initialized");
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, ASMInputController inputController) {
        //for this its assumed that the URL need not require any input from the user.
        inputController.onInputAvailable(null);
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMConnectionHandler connectionHandler = mASM.getMSS().getConnectionHandler();
        OMMobileSecurityConfiguration config = mASM.getMSS().getMobileSecurityConfig();
        OMCookieManager omCookieManager = OMCookieManager.getInstance();
        omCookieManager.startURLTracking();
        OMHTTPResponse response = connectionHandler.httpGet(config.getAuthenticationURL(), config.getCustomAuthHeaders());
        omCookieManager.stopURLTracking();
        // any failure will be reported using the exception.
        // for now if we get 200 we are marking authentication success, however
        // we can add other use cases based on the requirements.
        if (response != null && response.isSuccess()) {
            int responseCode = response.getResponseCode();
            OMLog.debug(TAG, "handleAuthentication responseCode: " + responseCode);
            authContext.setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.CBA);
            authContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
            authContext.setVisitedUrls(omCookieManager.getVisitedURLs());
            authContext.setCookies(parseVisitedURLCookieMap(omCookieManager.getVisitedUrlsCookiesMap()));
        } else {
            authContext.setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.CBA);
            authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
            //authentication error, report it back to the app
            //See if we need a new OMSE to record server error
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
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteToken, boolean isLogoutCall) {
        if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.CBA) {
            //TODO ajulka see if some extra clean up.
            reportLogoutCompleted(mASM.getMSS(), isLogoutCall, (OMMobileSecurityException) null);
        }
    }

    @Override
    public void collectLogoutChallengeInput(Map<String, Object> inputParams, AuthServiceInputCallback callback) {

    }

    @Override
    public void handleLogout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {

    }

    @Override
    public Type getType() {
        return Type.CBA_SERVICE;
    }
}
