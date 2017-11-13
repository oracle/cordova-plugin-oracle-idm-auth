/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;


import android.text.TextUtils;
import android.util.Log;

import java.net.URL;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OMAuthenticationContext.AuthenticationProvider;
import oracle.idm.mobile.auth.OMAuthenticationContext.Status;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.connection.InvalidCredentialEvent;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.connection.OMHTTPRequest;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.credentialstore.OMCredential;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.*;

/**
 * Created by ajulka on 1/7/2016.
 */
class BasicAuthenticationService extends AuthenticationService implements ChallengeBasedService {

    private static final String TAG = BasicAuthenticationService.class.getSimpleName();
    private boolean idleTimeOut = false;
    private boolean sessionTimedOut = false;

    BasicAuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
        OMLog.info(OMSecurityConstants.TAG, "initialized");
    }

    @Override
    public OMAuthenticationChallenge createLoginChallenge() {
        return createUsernamePasswordChallenge();
    }

    @Override
    public OMAuthenticationChallenge createLogoutChallenge() {
        return null;
    }

    @Override
    public boolean isChallengeInputRequired(Map<String, Object> inputParams) {
        boolean result = true;
        try {
            mAuthCompletionHandler.validateResponseFields(inputParams);
            result = false;
        } catch (OMMobileSecurityException e) {
            OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
        }
        OMLog.info(OMSecurityConstants.TAG, "isChallengeInputRequired");
        return result;
    }

    @Override
    public OMAuthenticationCompletionHandler getCompletionHandlerImpl() {
        Log.i(OMSecurityConstants.TAG, "[BasicAuthenticationService] getCompletionHandlerImpl");
        return mAuthCompletionHandler;
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, final ASMInputController controller) {
        OMLog.info(OMSecurityConstants.TAG, "collectChallengeInput");
        if (!isChallengeInputRequired(inputParams)) {
            //have all the required inputs lets proceed for authentication
            controller.onInputAvailable(inputParams);
        } else {
            mAuthCompletionHandler.createChallengeRequest(mASM.getMSS(), createLoginChallenge(), new AuthServiceInputCallback() {
                @Override
                public void onInput(final Map<String, Object> inputs) {
                    if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
                        //lets update the RC UI preferences.

                        OMLog.info(TAG, "Remember Cred feature is enabled, Storing UI prefs");
                        //check for the password.
                        //we already have the password.
                        //usually in case of remember creds and auto login we check for this.
                        OMMobileSecurityConfiguration config = mASM.getMSS().getMobileSecurityConfig();
                        if (config.isAutoLoginEnabled() || config.isRememberCredentialsEnabled()) {
                            String inputPWD = (String) inputs.get(OMSecurityConstants.Challenge.PASSWORD_KEY);
                            RCUtility rcUtility = mASM.getRCUtility();
                            OMCredential remCred = rcUtility.retrieveRememberedCredentials();
                            if (remCred != null && !(TextUtils.isEmpty(remCred.getUserPassword())) && inputPWD.equalsIgnoreCase(RCUtility.OBFUSCATED_PWD)) {
                                //this means the creds are already persisted and the user did not change the password which was pre-filled in the login screen.
                                //TODO if possible we should change this impl.
                                OMLog.info(TAG, "Updating the obfuscated PWD with the one we have in the store.");
                                inputs.put(OMSecurityConstants.Challenge.PASSWORD_KEY, remCred.getUserPassword());
                            }
                        }
                        storeRCUIPreferences(inputs);
                    }
                    controller.onInputAvailable(inputs);
                }

                @Override
                public void onError(final OMErrorCode error) {
                    controller.onInputError(error);
                }

                @Override
                public void onCancel() {
                    //FIXME Clear cookies which were set during this basic authentication attempt
                    controller.onCancel();
                }
            });
        }
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.trace(TAG, "handleAuthentication");
        OMLog.trace(TAG, "username: " + authContext.getInputParams().get(USERNAME_KEY));
        int flag;
        Map<String, Object> inputParams = authContext.getInputParams();
        OMConnectionHandler connectionHandler = mASM.getMSS().getConnectionHandler();
        OMCookieManager omCookieManager = OMCookieManager.getInstance();
        inputParams = authContext.getInputParams();
        String username = (String) inputParams.get(USERNAME_KEY);
        String password = (String) inputParams.get(PASSWORD_KEY);
        String identityDomain = (String) inputParams.get(IDENTITY_DOMAIN_KEY);
        authContext.setUserName(username);

        Map<String, String> headers = new HashMap<>(mASM.getMSS().getMobileSecurityConfig().getCustomAuthHeaders());
        username = addIdentityDomain(username, headers, identityDomain);
        OMAuthenticationContext existingAuthContext = mASM.retrieveAuthenticationContext();
        //Username is being set in authContext only after successful authentication, hence it will be null in case of retries.
        if (existingAuthContext != null && (existingAuthContext.getUserName() != null && !existingAuthContext.getUserName().equals(username))) {
            /*
             * if user is different, delete session cookies of previous authContext before trying
             * online authentication against server
             */
            existingAuthContext.deleteCookies();
        }
        omCookieManager.startURLTracking();
        if (existingAuthContext != null
                && (existingAuthContext.getUserName() != null && existingAuthContext.getUserName().equals(username))
                && authContext.isIdleTimeout()) {
            flag = (OMHTTPRequest.REQUIRE_RESPONSE_HEADERS | OMHTTPRequest.REQUIRE_RESPONSE_CODE | OMHTTPRequest.REQUIRE_RESPONSE_STRING);
        } else {
            flag = (OMHTTPRequest.AUTHENTICATION_REQUEST | OMHTTPRequest.REQUIRE_RESPONSE_HEADERS | OMHTTPRequest.REQUIRE_RESPONSE_CODE | OMHTTPRequest.REQUIRE_RESPONSE_STRING) | OMHTTPRequest.AUTHENTICATION_REQUEST;
        }

        OMHTTPResponse httpResponse = connectionHandler.httpGet(authRequest.getAuthenticationURL(), username, password, headers, false, flag);
        omCookieManager.stopURLTracking();
        Set<String> requiredCookies = mASM.getMSS().getMobileSecurityConfig().getRequiredTokens();
        authContext.setAuthenticationProvider(AuthenticationProvider.BASIC);
        if (omCookieManager.hasRequiredCookies(requiredCookies, omCookieManager.getVisitedURLs())) {
            authContext.setStatus(Status.SUCCESS);
            authContext.setVisitedUrls(omCookieManager.getVisitedURLs());
            authContext.setCookies(parseVisitedURLCookieMap(httpResponse.getVisitedUrlsCookiesMap()));
        } else {
            // fail only if the apps has specified required tokens.
            // this can happen due to the tokens requested not matching
            // Setting AuthenticationProvider so that logout url is invoked
            // properly in this use case, clearing the same in
            // OMAuthenticationContext#clearAllFields()
            authContext.setStatus(Status.FAILURE);
            OMLog.error(TAG, "Tokens that are requested are not available from the server.");
            throw new OMMobileSecurityException(OMErrorCode.AUTHENTICATION_FAILED, new InvalidCredentialEvent());
        }
        return httpResponse;
    }

    @Override
    public void cancel() {
        OMLog.trace(TAG, "cancel");
        if (mAuthCompletionHandler != null) {
            mAuthCompletionHandler.cancel();
        }
        OMAuthenticationContext authContext = mASM.getAuthenticationContext();
        if (authContext != null) {
            authContext.clearFields();
        }
    }

    @Override
    public Type getType() {
        return Type.BASIC_SERVICE;
    }

    /*
     * return if idle time out is hit or not?
     */
    boolean isIdleTimeOut() {
        return idleTimeOut;
    }

    public void setIdleTimeOut(boolean idleTimeOut) {
        this.idleTimeOut = idleTimeOut;
    }

    boolean isSessionTimedOut() {
        return sessionTimedOut;
    }

    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {
        OMLog.info(TAG, "isValid");
        if (authContext.getAuthenticationProvider() != AuthenticationProvider.BASIC) {
            return true;
        }
        Date sessionExpiry = authContext.getSessionExpiry();
        Date idleTimeExpiry = authContext.getIdleTimeExpiry();
        Date currentTime = Calendar.getInstance().getTime();

        setIdleTimeOut(false);// reseting the value .

        // Non-zero check for getSessionExpInSecs() added to ignore session
        // expiry if session timeout value is 0.
        if (sessionExpiry != null
                && authContext.getSessionExpInSecs() != 0
                && (currentTime.after(sessionExpiry) || currentTime
                .equals(sessionExpiry))) {
            OMLog.debug(TAG + "_isValid", "Session is expired.");


             /*
             * on session time out invalidate the remembered credentials ,
             * keeping only the username.
             */
            if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
                mASM.getRCUtility()
                        .inValidateRememberedCredentials();
            }
            this.sessionTimedOut = true;
            mASM.resetFailureCount(authContext);
            return false;
        }

        // Non-zero check for getIdleTimeExpInSecs() added to ignore idle
        // time expiry if idle timeout value is 0.
        if (idleTimeExpiry != null
                && authContext.getIdleTimeExpInSecs() != 0
                && (currentTime.after(idleTimeExpiry) || currentTime
                .equals(idleTimeExpiry))) {

            OMLog.debug(TAG + "_isValid", "Idle time is expired.");
            setIdleTimeOut(true);
            return false;
        }

        if (authContext.getAuthenticatedMode() == OMAuthenticationContext.AuthenticationMode.ONLINE) {
            authContext.resetIdleTime();
            if (authContext.getIdleTimeExpiry() != null) {
                OMLog.debug(TAG + "_isValid", "Idle time is reset to : "
                        + authContext.getIdleTimeExpiry().getTime());
            }
            authContext.setStatus(Status.SUCCESS);
        }
        return true;
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
        if (authContext.getAuthenticationProvider() != AuthenticationProvider.BASIC &&
                authContext.getAuthenticationProvider() != AuthenticationProvider.OFFLINE) {
            return;
        }

        OMLog.info(TAG, "logout");
        OMLog.debug(TAG, "isDeleteUnPwd : " + isDeleteUnPwd + " isDeleteCookies : " + isDeleteCookies + "isLogoutCall : " + isLogoutCall);
        if (isDeleteCookies) {
            URL logoutUrl = mASM.getMSS().getMobileSecurityConfig().getLogoutUrl();
            if (logoutUrl != null) {
                /*
                 * Already setting the logout in progress to true in the
                 * beginning.
                 */
                if (isLogoutCall) {
                    mASM.getMSS().setLogoutInProgress(true);
                }
                new AccessLogoutUrlTask(mASM.getMSS().getMobileSecurityConfig(),
                        isLogoutCall, authContext).execute();
            }
        }
    }

    @Override
    public void collectLogoutChallengeInput(Map<String, Object> inputParams, AuthServiceInputCallback callback) {

    }

    @Override
    public void handleLogout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {

    }
}
