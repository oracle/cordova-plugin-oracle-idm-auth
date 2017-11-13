/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;
import android.util.Log;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.OMAuthenticationContext.AuthenticationMode;
import oracle.idm.mobile.configuration.OMAuthenticationScheme;
import oracle.idm.mobile.configuration.OMConnectivityMode;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.credentialstore.OMCredential;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.crypto.CryptoException;
import oracle.idm.mobile.crypto.CryptoScheme;
import oracle.idm.mobile.crypto.OMCryptoService;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.PASSWORD_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.USERNAME_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Param.COLLECT_OFFLINE_CREDENTIAL;

/**
 * Created by ajulka on 1/7/2016.
 */
final class OfflineAuthenticationService extends AuthenticationService implements ChallengeBasedService {

    private static final String TAG = OfflineAuthenticationService.class.getSimpleName();
    private static final String OFFLINE_CREDENTIAL_COUNT = "offlineCredentialCount";
    private boolean idleTimeOut = false;

    OfflineAuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
        OMLog.info(TAG, "initialized!");
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, final ASMInputController controller) {
        OMLog.trace(TAG, "collectLoginChallengeInput");
        if (!isChallengeInputRequired(inputParams)) {
            //have all the required inputs lets proceed for authentication
            controller.onInputAvailable(inputParams);
        } else {
            Boolean collectCredential = (Boolean) inputParams.get(COLLECT_OFFLINE_CREDENTIAL);
            if (collectCredential != null && collectCredential) {
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
                        controller.onCancel();
                    }
                });
            } else {
                controller.onInputAvailable(inputParams);
            }
        }
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
        OMLog.info(TAG, "isChallengeInputRequired");
        return result;
    }

    @Override
    public OMAuthenticationCompletionHandler getCompletionHandlerImpl() {
        OMLog.info(TAG, "getCompletionHandlerImpl");
        return mAuthCompletionHandler;
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.debug(TAG, "handleAuthentication");

        authContext.setStatus(OMAuthenticationContext.Status.IN_PROGRESS);
        if (mASM.getFailureCount(authContext) >= mASM.getMSS().getMobileSecurityConfig()
                .getMaxFailureAttempts()) {
            OMLog.debug(TAG,
                    " - Maximum Failure attempts has reached.");
            authContext.deleteAuthContext(true, true, true, false, false);
            mASM.resetFailureCount(authContext);
            return null;
        }

        String credentialKey = authContext.getStorageKey() != null ? authContext
                .getStorageKey() : mASM.getAppCredentialKey();

        // avoid checking the value of credential stored , as we are now storing
        // the off-line credentials with different keys based on logged in user
        // . Instead we maintain the
        // count of off-line credentials stored on the device . If the count is
        // 0
        // this means no off-line credentials stored hence the SDK can not
        // perform off-line authentication.
        OMCredentialStore credService = mASM.getMSS()
                .getCredentialStoreService();

        int offlineCredCount = credService.getInt(OFFLINE_CREDENTIAL_COUNT);
        if (offlineCredCount == 0) {
            return null;
        }
        // Retrieve the auth context and see if the time is not expired.
        OMAuthenticationContext authContextFromStore = mASM
                .retrieveAuthenticationContext(credentialKey);
        OMLog.debug(TAG, "authContextFromStore " + authContextFromStore);
        if (authContextFromStore != null)
            OMLog.debug(TAG, "authContextFromStore.isValid()" + authContextFromStore.isValid());
        if (!authRequest.isForceAuthentication()
                && (authContextFromStore != null && authContextFromStore
                .isValid())) {
            authContext.setAuthenticatedMode(authContextFromStore.getAuthenticatedMode());
            authContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
            return null;
        } else {
            Map<String, Object> inputParams = authContext.getInputParams();
            if (inputParams == null || inputParams.isEmpty()
                    || !inputParams.containsKey(USERNAME_KEY)
                    || !inputParams.containsKey(PASSWORD_KEY)
                    || inputParams.containsKey(MOBILE_SECURITY_EXCEPTION)) {
                    /*
                     * Check for username and pwd as the user need to be
                     * authenticated.
                     */
                authContext.setStatus(OMAuthenticationContext.Status.COLLECT_OFFLINE_CREDENTIALS);
                return null;
            }
        }

        OMConnectivityMode mode = authContext.getAuthRequest().getConnectivityMode();
        if (mode == null) {
            mode = mASM.getMSS().getMobileSecurityConfig().getConnectivityMode();
        }
        OMLog.debug(TAG + "_handleAuthentication", "OMConnectivityMode =" + " " + mode.name());
        if (mode == OMConnectivityMode.ONLINE) {
            return null;
        } else if (mode == OMConnectivityMode.OFFLINE) {
            return performOfflineAuthentication(authContext);
        } else {
            /*
             * For authentication types other than basic, the behavior of AUTO
             * is the same as the initial one. For basic auth, it is changed as
             * part of OMSS-15577.
             */
            boolean isNetworkAvail = mASM.getMSS().getConnectionHandler()
                    .isNetworkAvailable(
                            authRequest.getAuthenticationURL().toString());
            if (authRequest.getAuthScheme() == OMAuthenticationScheme.BASIC) {
                OMAuthenticationContext prevContext = mASM
                        .retrieveAuthenticationContext();
                String userName = (String) authContext.getInputParams().get(USERNAME_KEY);
                if (prevContext != null && !TextUtils.isEmpty(userName) && !userName.equals(prevContext.getUserName())) {
                    OMLog.debug(TAG + "_handleAuthentication", "Session for user: " + prevContext.getUserName() + " already available!");
                    // if previous username and the current username mismatch
                    // then do not perform the check for cookie validation, as
                    // previous user's cookies are going to get validated.

                    // to avoid that simply return and do fresh online
                    // Authentication for the new user.
                    if (isNetworkAvail) {
                        return null;
                    } else {
                        return performOfflineAuthentication(authContext);
                    }
                }
                try {
                    Map<String, String> headers = new HashMap<>(
                            mASM.getMSS()
                                    .getMobileSecurityConfig()
                                    .getCustomAuthHeaders());
                    String identityDomain = (String) authContext
                            .getInputParams().get(IDENTITY_DOMAIN_KEY);
                    addIdentityDomain(userName, headers, identityDomain);

                    mASM.getMSS().getConnectionHandler().httpGet(authRequest.getAuthenticationURL(), headers);
                    /*If cookies are invalid, then server will return 401 since this is basic auth.
                     The above method throws OMErrorCode.UN_PWD_INVALID when 401 is obtained,
                     which is handled in catch block.*/
                    OMLog.debug(TAG + "_handleAuthentication",
                            "Cookies are valid. Hence, doing offline authentication.");
                    return performOfflineAuthentication(authContext);
                } catch (OMMobileSecurityException e) {
                    if (e.getErrorCode().equals(OMErrorCode.UN_PWD_INVALID.getErrorCode())) {
                        OMLog.debug(TAG + "_handleAuthentication",
                                "Cookies are NOT valid. Hence, doing online authentication.");
                        return null;
                    }
                    OMLog.debug(TAG + "_handleAuthentication",
                            "Could not connect to server to check cookie validity. Falling back to offline authentication.");
                    return performOfflineAuthentication(authContext);
                }
            } else {
                if (isNetworkAvail) {
                    return null;
                } else {
                    return performOfflineAuthentication(authContext);
                }
            }
        }
    }

    @Override
    public void cancel() {
        OMLog.trace(TAG, "cancel");
        if (mAuthCompletionHandler != null) {
            mAuthCompletionHandler.cancel();
        }
    }

    @Override
    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {
        OMLog.debug(TAG, "isValid");
        if (authContext.getAuthenticatedMode() == AuthenticationMode.OFFLINE) {
            // validateOnline will not be used in this as its a offline/local
            // authentication service.
            idleTimeOut = false;
            Date currentTime = Calendar.getInstance().getTime();
            Date sessionExpiry = authContext.getSessionExpiry();

            // Non-zero check for getSessionExpInSecs() added to ignore session
            // expiry if session timeout value is 0.
            if (sessionExpiry != null
                    && authContext.getSessionExpInSecs() != 0
                    && (currentTime.after(sessionExpiry) || currentTime
                    .equals(sessionExpiry))) {
                OMLog.debug(TAG, " - Session is expired.");
                 /*
             * on session time out invalidate the remembered credentials ,
             * keeping only the username.
             */
                if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
                    OMLog.debug(TAG, " - Invalidating remembered credentials");
                    mASM.getRCUtility()
                            .inValidateRememberedCredentials();
                }
                authContext.deleteAuthContext(true, true, true, false, false);
                return false;
            }

            // Non-zero check for getIdleTimeExpInSecs() added to ignore idle
            // time expiry if idle timeout value is 0.
            Date idleTimeExpiry = authContext.getIdleTimeExpiry();
            if (idleTimeExpiry != null
                    && authContext.getIdleTimeExpInSecs() != 0
                    && (currentTime.after(idleTimeExpiry) || currentTime
                    .equals(idleTimeExpiry))) {
                OMLog.debug(TAG, " - Idle time is expired.");
                idleTimeOut = true;
                return false;
            } else {
                if (authContext.getIdleTimeExpInSecs() > 0) {
                    authContext.resetIdleTime();
                    OMLog.debug(TAG, " - Idle time is reset to : "
                            + authContext.getIdleTimeExpiry().getTime());
                }
            }
        }
        return true;
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
        if (isDeleteUnPwd) {
            String usernameFromContext = authContext.getUserName();
            if (TextUtils.isEmpty(usernameFromContext)) {
                OMLog.debug(TAG,
                        " - Invalid username to be removed from credential store.");
                return;
            }
            String credentialKey = authContext.getStorageKey() != null ? authContext
                    .getStorageKey() : mASM.getAppCredentialKey();
            String authenticationUrl = mASM.getMSS().getMobileSecurityConfig().getAuthenticationURL().toString();
            OMCredentialStore credService = mASM.getMSS().getCredentialStoreService();
            String identityFromContext = authContext.getIdentityDomain();
            credService.deleteCredential(createServerSpecificKey(authenticationUrl, credentialKey,
                    identityFromContext, usernameFromContext));
            storeOfflineCredentialsCount(false);
            OMLog.debug(TAG, "logout");
            OMLog.debug(TAG, "isDeleteUnPwd : " + isDeleteUnPwd + " isDeleteCookies : " + isDeleteCookies + "isLogoutCall : " + isLogoutCall);
            OMLog.debug(TAG, " - Offline credentials for the user "
                    + usernameFromContext
                    + " is removed from the credential store.");
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
        return Type.OFFLINE_SERVICE;
    }


    void handleAuthenticationCompleted(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) {
        OMLog.debug(TAG, "handleAuthenticationCompleted");
        OMCredential credObj = new OMCredential();
        Map<String, Object> inputParams = authContext.getInputParams();

        boolean storeCredential = false;
        String username = (String) inputParams.get(USERNAME_KEY);
        String passwordPlainText = (String) inputParams.get(PASSWORD_KEY);
        String authenticationUrl = authRequest.getAuthenticationURL().toString();
        if (!TextUtils.isEmpty(username) && !TextUtils.isEmpty(passwordPlainText)) {
            credObj.setUserName(username);

            // Here perform hashing when the algo is specified
            OMMobileSecurityConfiguration msc = mASM.getMSS().getMobileSecurityConfig();
            CryptoScheme scheme = msc.getCryptoScheme();
            OMCryptoService cryptoService = mASM.getMSS().getCryptoService();
            String encodedValue = passwordPlainText;
            try {
                if (CryptoScheme.isHashAlgorithm(scheme)) {
                    encodedValue = cryptoService.hash(passwordPlainText,
                            scheme, msc.getSaltLength(), true);
                } else {
                    /*Encryption is done by OMSecureStorageService. Hence, w.r.t OMCryptoService,
                    schemes other than hashing algorithm are to be treated as PLAINTEXT.*/
                    encodedValue = cryptoService.prefixAlgorithm(CryptoScheme.PLAINTEXT,
                            passwordPlainText);
                }
            } catch (CryptoException e) {
                OMLog.error(TAG,
                        " - " + e.getLocalizedMessage());
                Log.i(TAG, e.getLocalizedMessage(), e);
            }

            credObj.setUserPassword(encodedValue);
            storeCredential = true;
        }

        String tenantName = (String) inputParams.get(IDENTITY_DOMAIN_KEY);
        if (!TextUtils.isEmpty(tenantName)) {
            credObj.setIdentityDomain(tenantName);
        }
        // avoid storing of same credential , if last authentication was local .
        // it will result in over writing of the same credential again and again
        // .
        if (storeCredential
                && (authContext.getAuthenticatedMode() != AuthenticationMode.OFFLINE)) {
            String credentialKey = authContext.getStorageKey() != null ? authContext
                    .getStorageKey() : mASM.getAppCredentialKey();
            OMCredentialStore credService = mASM.getMSS().getCredentialStoreService();
            String serverSpecificKey = createServerSpecificKey(authenticationUrl, credentialKey,
                    tenantName, username);
            OMLog.debug(TAG, "Saving Offline Credentials for User: " + username);
            credService.addCredential(serverSpecificKey, credObj);
            storeOfflineCredentialsCount(true);
            authContext.setOfflineCredentialKey(serverSpecificKey);
        }
    }

    /**
     * This utility creates a key based on the current logged in users and server. We form
     * this key with the identity domain and user name of the logged in user.
     * The format is : <authentication url>_<identity domain>::<user name>_<credential key> .
     *
     * @param authenticationUrl
     * @param credentialKey
     * @param identityDomain
     * @param username
     * @return
     */
    static String createServerSpecificKey(String authenticationUrl, String credentialKey,
                                          String identityDomain, String username) {
        StringBuilder sb = new StringBuilder(authenticationUrl);
        sb.append("_");
        if (identityDomain != null) {
            sb.append(identityDomain);
        }
        sb.append("::");
        sb.append(username);
        sb.append("_");
        sb.append(credentialKey);
        return sb.toString();
    }

    private void storeOfflineCredentialsCount(boolean increment) {
        OMCredentialStore credService = mASM.getMSS()
                .getCredentialStoreService();
        int prevCount = credService.getInt(OFFLINE_CREDENTIAL_COUNT);
        if (increment)
            prevCount++;
        else
            prevCount--;
        if (prevCount < 0)
            prevCount = 0;
        credService.putInt(OFFLINE_CREDENTIAL_COUNT, prevCount);
    }

    private OMHTTPResponse performOfflineAuthentication(OMAuthenticationContext authContext) {
        Map<String, Object> inputParams = authContext.getInputParams();
        if (inputParams == null || inputParams.isEmpty()
                || !inputParams.containsKey(USERNAME_KEY)
                || !inputParams.containsKey(PASSWORD_KEY)
                || (authContext.getMobileException() != null && inputParams.containsKey(MOBILE_SECURITY_EXCEPTION))) {
            // Check for input username and pwd
            authContext.setStatus(OMAuthenticationContext.Status.COLLECT_OFFLINE_CREDENTIALS);
            return null;
        }
        // Since the credential are already available clear the request for
        // collecting credentials.
        inputParams.remove(COLLECT_OFFLINE_CREDENTIAL);

        String username = (String) inputParams.get(USERNAME_KEY);
        String password = (String) inputParams.get(PASSWORD_KEY);
        String tenantName = (String) inputParams.get(IDENTITY_DOMAIN_KEY);
        authContext.setUserName(username);
        String credentialKey = authContext.getStorageKey() != null ? authContext
                .getStorageKey() : mASM.getAppCredentialKey();
        String authenticationUrl = authContext.getAuthRequest().getAuthenticationURL().toString();
        String serverSpecificKey = createServerSpecificKey(authenticationUrl, credentialKey,
                tenantName, username);
        String userSpecificKey = createUserSpecificKey(credentialKey,
                tenantName, username);
        String debugUsername = username;
        OMLog.debug(TAG, "Performing offline authentication for user: "
                + debugUsername);

        if (!TextUtils.isEmpty(tenantName)) {
            username = tenantName + "." + username;
        }
        OMCredential credObj = retrieveOfflineCredential(serverSpecificKey);

        if (credObj == null) {
            // check if credential is available specific to user, irrespective
            // of authentication url for backward compatibility
            credObj = retrieveOfflineCredential(userSpecificKey);
            if (credObj != null) {
                OMLog.debug(TAG, "Offline Credentials available for userSpecificKey");
                OMCredentialStore credService = mASM.getMSS().getCredentialStoreService();
                credService.addCredential(serverSpecificKey, credObj);
                credService.deleteCredential(userSpecificKey);
                authContext.setOfflineCredentialKey(serverSpecificKey);
            }
        }

        boolean tenantAvailable = false;
        if (credObj != null) {
            OMLog.debug(TAG, "Offline Credentials available for user: "
                    + debugUsername);
            // username and password stored in the cred store.
            String usernameStored = credObj.getUserName();
            String passwordStored = credObj.getRawUserPassword();
            String tenantNameStored = credObj.getIdentityDomain();
            if (!TextUtils.isEmpty(tenantNameStored)) {
                tenantAvailable = true;
                usernameStored = tenantNameStored + "." + usernameStored;
            }

            if (!TextUtils.isEmpty(username) && !TextUtils.isEmpty(password)) {
                // find if password to be compared is to be hashed based on the
                // algo
                if (username.equals(usernameStored)) {
                    boolean isMatches = mASM.getMSS().getCryptoService().match(password,
                            passwordStored,
                            mASM.getMSS().getMobileSecurityConfig().getSaltLength());
                    if (isMatches) {
                        OMLog.debug(TAG, "Offline Credentials match for user: " + debugUsername);
                        authContext.setAuthenticatedMode(AuthenticationMode.OFFLINE);
                        authContext.setOfflineCredentialKey(serverSpecificKey);

                        OMAuthenticationContext prevContext = mASM
                                .retrieveAuthenticationContext();
                        OMAuthenticationScheme scheme = authContext
                                .getAuthenticationServiceManager().getMSS().getMobileSecurityConfig().getAuthenticationScheme();

                        OMLog.debug(TAG, "Case Offline Authentication with scheme: " + scheme);

                        if (prevContext != null) {
                            OMLog.debug(TAG,
                                    "Case [Offline Authentication with an existing authentication context]");

                            switch (scheme) {
                                case OAUTH20:
                                    // for Offline OAuth only.
                                    List<OAuthToken> prevTokens = prevContext
                                            .getOAuthTokenList();
                                    if (prevTokens != null
                                            && !prevTokens.isEmpty()) {
                                        OMLog.debug(TAG, "Adding the previously retained access tokens ("
                                                + prevTokens.size() + ") to the new auth context!");
                                        authContext.setOAuthTokenList(new ArrayList<OAuthToken>(prevTokens));
                                    }

                                case BASIC:
                                    // common for both basic and oauth.
                                    if (!username.equals(prevContext.getUserName())) {
                                        OMLog.debug(TAG, "Session for user: " + prevContext.getUserName()
                                                + " is already avaliable, hence clearing it off to complete offline authentication for user: "
                                                + username);
                                        prevContext.deleteAuthContext(true, true, true, false, false);
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }
                        if (scheme == OMAuthenticationScheme.OAUTH20) {
                                /* for OAuth lets keep the provider to be OAuth20 itself. This will help in
                                 maintaining minimum code changes in various existing entry points for OAuth APIs.*/
                            authContext.setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.OAUTH20);
                        } else {
                            authContext.setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.OFFLINE);
                        }
                        authContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
                        return null;
                    } else {
                        OMLog.debug(TAG,
                                "Offline Credentials mis-matched for user: "
                                        + debugUsername);
                        // fail the offline auth only when the offline cred of
                        // the
                        // presented username are present on the device and the
                        // password does
                        // not match.
                        authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
                        if (tenantAvailable) {
                            authContext.setException(new OMMobileSecurityException(OMErrorCode.UN_PWD_TENANT_INVALID));
                        } else {
                            authContext.setException(new OMMobileSecurityException(OMErrorCode.UN_PWD_INVALID));
                        }
                    }
                }
            }
        } else {
            OMLog.debug(TAG, "Offline Credentials not available for user: "
                    + username);
        }
        // don't fail offline auth if the credObj found is null, because we are
        // now storing the offline cred with username in the key,
        // so it may happen that we don't have offline credentials in the
        // store for the presented user, so don't fail.
        return null;
    }

    /**
     * This utility creates a key based on the current logged in users . We form
     * this key with the identity domain and user name of the logged in user.
     * The format is : <credential key>_<identity domain>::<user name> .
     *
     * @param credentialKey
     * @param identityDomain
     * @return
     */
    static String createUserSpecificKey(String credentialKey, String identityDomain, String username) {
        StringBuilder sb = new StringBuilder(credentialKey);
        sb.append("_");
        if (identityDomain != null) {
            sb.append(identityDomain);
        }
        sb.append("::");
        sb.append(username);
        return sb.toString();
    }

    private OMCredential retrieveOfflineCredential(String appCredKey) {
        String credentialKey = appCredKey;
        OMCredentialStore credService = mASM.getMSS().getCredentialStoreService();
        OMCredential credential = credService.getCredential(credentialKey);
        return credential;
    }

    boolean isIdleTimeOut() {
        return idleTimeOut;
    }

}
