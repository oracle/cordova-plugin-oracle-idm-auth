/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.os.Handler;
import android.text.TextUtils;
import android.webkit.WebViewDatabase;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.openID.OpenIDUserInfo;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OMFederatedMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.credentialstore.OMCredential;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.crypto.CryptoScheme;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.OFFLINE_CREDENTIAL_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.USERNAME_KEY;
import static oracle.idm.mobile.OMSecurityConstants.DOMAIN;
import static oracle.idm.mobile.OMSecurityConstants.EXPIRES;
import static oracle.idm.mobile.OMSecurityConstants.EXPIRY_DATE;
import static oracle.idm.mobile.OMSecurityConstants.EXPIRY_SECS;
import static oracle.idm.mobile.OMSecurityConstants.HTTP_ONLY;
import static oracle.idm.mobile.OMSecurityConstants.IS_HTTP_ONLY;
import static oracle.idm.mobile.OMSecurityConstants.IS_SECURE;
import static oracle.idm.mobile.OMSecurityConstants.OAUTH_ACCESS_TOKEN;
import static oracle.idm.mobile.OMSecurityConstants.OAUTH_TOKEN_SCOPE;
import static oracle.idm.mobile.OMSecurityConstants.PATH;
import static oracle.idm.mobile.OMSecurityConstants.SECURE;
import static oracle.idm.mobile.OMSecurityConstants.TOKEN_NAME;
import static oracle.idm.mobile.OMSecurityConstants.TOKEN_VALUE;


/**
 * OMAuthenticationContext class is the resultant object which is constructed
 * after a successful authentication with the server. It contains tokens
 * obtained from the server, expiry time, idle time, mode of authentication, type of
 * authentication provider and the user name for which the tokens are obtained.
 *
 */
public class OMAuthenticationContext {

    /**
     * @hide Note: AuthContext Status is kept separate for OpenID and OAuth to avoid code changes in lower layers.
     */
    enum Status {
        SUCCESS,
        FAILURE,
        CANCELED,
        IN_PROGRESS,
        INITIAL_VALIDATION_DONE,
        COLLECT_OFFLINE_CREDENTIALS,
        /**
         * Status used when the IDCS dynamic client registration is in progress for an OAuth client
         **/
        OAUTH_IDCS_CLIENT_REGISTRATION_IN_PROGRESS,
        /**
         * Status used when the IDCS dynamic client registration is done for an OAuth client
         **/
        OAUTH_IDCS_CLIENT_REGISTRATION_DONE,
        /**
         * Status used when the IDCS dynamic client registration is in progress for an OpenID client
         **/
        OPENID_IDCS_CLIENT_REGISTRATION_IN_PROGRESS,
        /**
         * Status used when the IDCS dynamic client registration is in progress for an OpenID client
         **/
        OPENID_IDCS_CLIENT_REGISTRATION_DONE,


        OAUTH_DYCR_DONE,
        OAUTH_PRE_AUTHZ_DONE,
        OAUTH_DYCR_IN_PROGRESS
    }

    public enum AuthenticationProvider {
        CBA,
        BASIC,
        OAUTH20,
        OFFLINE,
        FEDERATED,
        OPENIDCONNECT10
    }

    /**
     * Mentions the mechanism using which authentication was done.
     * {@link OMAuthenticationContext#getAuthenticationMechanism()} should be used
     * to determine the authentication mechanism.
     * <p>
     * Currently, it distinguishes authentication mechanism used in FedAuth. This is
     * required by SDK consumer to kill the app after logout in case of
     * Basic/NTLM./Kerberos. App kill is required because webview replays the
     * user credentials during next login even if SDK tries to clear it using
     * corres. android APIs.
     * Bug: https://code.google.com/p/android/issues/detail?id=22272
     *
     */
    public enum AuthenticationMechanism {
        /**
         * This means that federated authentication was done using form based
         * authentication.
         */
        FEDERATED,
        /**
         * Http Auth challenge was received during fedreated authentication. This
         * includes Http Basic Auth, Kerberos, NTLM, etc.
         */
        FEDERATED_HTTP_AUTH
    }

    public enum AuthenticationMode {
        ONLINE,
        OFFLINE
    }

    public enum TimeoutType {
        IDLE_TIMEOUT,
        SESSION_TIMEOUT
    }

    // ===---=== OWSM-MA Start ===---===

    // constants
    public static final String CREDENTIALS = "credentials";
    public static final String USERNAME_PROPERTY = "javax.xml.ws.security.auth.username";
    public static final String PASSWORD_PROPERTY = "javax.xml.ws.security.auth.password";
    public static final String ERROR = "Error";
    public static final String CREDENTIALS_UNAVAILABLE = "Credentials unavailable";
    public static final String COOKIES = "cookies";
    public static final String HEADERS = "headers";
    private static final String PROVIDER = "provider";
    private static final String TOKENS = "tokens";
    private static final String URL = "url";
    private static final String OWSM_MA_COOKIES = "owsmMACookies";

    //TODO @arunpras please confirm if this is required here or can we move this to OMKeyManager
    private static final String TAG = OMAuthenticationContext.class.getSimpleName();
    private static final String MA_PWD_ENCRYPTION_PASSPHRASE = "SDKOWSMKEY";
    private static final String MA_PWD_ENCRYPTION_SALT = "SDKOWSMSALT";
    private static final String MA_PWD_ENCRYPTION_PADDING = "pkcs7padding";
    private static final String MA_PWD_ENCRYPTION_MODE = "cbc";
    private static int MA_PWD_ENCRYPTION_ITERATIONS = 4096;
    private static int MA_PWD_ENCRYPTION_KEYSIZE = 128;
    private static int MA_PWD_ENCRYPTION_IV_LENGTH = 16;
    // ===---=== OWSM_MA end ===---===

    private Status mStatus;
    private String mStorageKey;
    private AuthenticationServiceManager mASM;
    private OMMobileSecurityException mException;
    private OMAuthenticationRequest mAuthRequest;
    private AuthenticationProvider authenticationProvider;
    private AuthenticationMode authenticatedMode = AuthenticationMode.ONLINE;
    private AuthenticationMechanism authenticationMechanism;
    private String offlineCredentialKey;
    private String identityDomain;
    Map<String, Object> mInputParams;
    private boolean authContextDeleted;
    private String userName;
    // Field used internally for validation
    private Date sessionExpiry;
    private Date idleTimeExpiry;
    private int sessionExpInSecs;
    private int idleTimeExpInSecs;
    private TimeoutManager mTimeoutManager;
    private static final String SESSION_EXPIRY = "sessionExpiry";
    private static final String IDLETIME_EXPIRY = "idleTimeExpiry";
    private static final String SESSION_EXPIRY_SECS = "sessionExpInSecs";
    private static final String IDLETIME_EXPIRY_SECS = "idleTimeExpInSecs";
    private static final String AUTHEN_MODE = "authenticatedMode";
    private String LOGOUT_TIMEOUT_VALUE = "logoutTimeoutValue";
    boolean isIdleTimeout = false;
    private List<OAuthToken> oAuthTokenList;
    private Map<String, OMToken> tokens;
    private Map<String, OMToken> owsmMACookies;

    private int logoutTimeout;
    private Handler mHandler;
    private Set<URI> mVisitedUrls;
    private List<OMCookie> mCookies;
    private OpenIDUserInfo mOpenIDUserInfo;
    private boolean isForceAuthentication;

    /**
     * Just idle time out has happened; session time out has not happened.
     */
    private boolean idleTimeExpired;

    OMAuthenticationContext(AuthenticationServiceManager asm, OMAuthenticationRequest authRequest, String storageKey) {
        mASM = asm;
        mStorageKey = storageKey;
        mAuthRequest = authRequest;
    }

    OMAuthenticationContext(AuthenticationServiceManager asm, String authContextString, String storageKey) {
        mASM = asm;
        mStorageKey = storageKey;
        populateFields(authContextString);
    }

    OMAuthenticationContext(Status status) {
        mStatus = status;
    }

    /**
     * Hold inputs collected from the app/user.
     * Note this is something that is totally internal to the SDK, and will contain more detailed info/params.
     *
     * @return
     */
    Map<String, Object> getInputParams() {
        if (mInputParams == null) {
            mInputParams = new HashMap<>();
        }
        return mInputParams;
    }

    void setStatus(Status status) {
        mStatus = status;
    }

    void setException(OMMobileSecurityException e) {
        mException = e;
    }

    OMMobileSecurityException getMobileException() {
        return mException;
    }

    Status getStatus() {
        return mStatus;
    }

    OMAuthenticationRequest getAuthRequest() {
        return mAuthRequest;
    }

    /**
     * Returns the type of authentication provider.
     *
     * @return {@link AuthenticationProvider}
     */
    public AuthenticationProvider getAuthenticationProvider() {
        return authenticationProvider;
    }

    void setAuthenticationProvider(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    public AuthenticationMode getAuthenticatedMode() {
        return authenticatedMode;
    }

    void setAuthenticatedMode(AuthenticationMode authenticatedMode) {
        this.authenticatedMode = authenticatedMode;
    }

    public AuthenticationMechanism getAuthenticationMechanism() {
        return authenticationMechanism;
    }

    void setForceAuthentication(
            boolean isForceAuthentication) {
        this.isForceAuthentication = isForceAuthentication;
    }

    public boolean getForceAuthentication() {
        return isForceAuthentication;
    }

    void setAuthenticationMechanism(
            AuthenticationMechanism authenticationMechanism) {
        this.authenticationMechanism = authenticationMechanism;
    }

    public void populateExpiryTime(OMMobileSecurityServiceCallback appCallback) {
        if (mASM != null && mASM.getMSS() != null) {//TODO CHECK identity domain NPE

            int sessionExp = mASM.getMSS().getMobileSecurityConfig().getSessionDuration();
            int expTime = (sessionExp > 0) ? sessionExp : 0;

            Calendar futureTime = Calendar.getInstance();
            futureTime.add(Calendar.SECOND, expTime);
            sessionExpiry = futureTime.getTime();
            sessionExpInSecs = expTime;

            int idleExp = mASM.getMSS().getMobileSecurityConfig().getIdleTime();
            if (idleExp > 0) {
                Calendar futureIdleTime = Calendar.getInstance();
                futureIdleTime.add(Calendar.SECOND, idleExp);
                idleTimeExpiry = futureIdleTime.getTime();
                idleTimeExpInSecs = idleExp;
            }
            mHandler = appCallback.getHandler();
            mTimeoutManager = new TimeoutManager(mASM.getMSS().getAuthenticationContextCallback(), this, mHandler);
			//TODO
            if (authenticationProvider == AuthenticationProvider.OAUTH20 && authenticatedMode == AuthenticationMode.OFFLINE && idleExp > 0) {
                mTimeoutManager.startIdleTimeoutTimer();
            } else if (authenticationProvider != AuthenticationProvider.OAUTH20) {
                if (idleExp > 0) {
                    mTimeoutManager.startIdleTimeoutTimer();
                }
                if (expTime > 0) {
                    mTimeoutManager.startSessionTimeoutTimer();
                }
            }
        }
    }

    public boolean resetTimer() {
        if (this.isValid()) {
            /*Timer is being reset twice. Once as part of isValid call, and second time because of mTimeoutManager.resetTimer().
            It involves lot of changes to get the status of timer being reset as part of isValid call, because of which it is done this way.
            Otherwise, just isValid() call is enough and mTimeoutManager.resetTimer() could have been removed.*/
            return resetIdleTime();
        } else {
            OMLog.debug(TAG, "Cannot reset the timer, authcontext not valid");
        }
        return false;
    }

    /**
     * Sets the credential key as the user defined key
     *
     * @param storageKey
     */
    void setStorageKey(String storageKey) {
        mStorageKey = storageKey;
    }

    public String getStorageKey() {
        return mStorageKey;
    }

    /**
     * Returns the offline credential key for this authentication context.
     *
     * @return
     * @hide
     */
    public String getOfflineCredentialKey() {
        return offlineCredentialKey;
    }

    /**
     * Sets the offline credential key for the authentication context.
     *
     * @param offlineCredentialKey
     */
    void setOfflineCredentialKey(String offlineCredentialKey) {
        this.offlineCredentialKey = offlineCredentialKey;
    }

    /**
     * Checks whether the {@link OMAuthenticationContext} is valid or not. Based
     * on the {@link AuthenticationProvider} the {@link AuthenticationService}
     * will internally validate the tokens and returns the result.
     * <p/>
     * This api is similar to {@link OMAuthenticationContext#isValid()} which by
     * default checks the validity of tokens online wherever required. However,
     * in this api the application can indicate whether the check needs to be
     * done online or locally. Please Note: If true is passed, this api can not
     * be called from the main thread of the application. It is recommended to
     * call this from a worker thread. Applications targeting Android 3.0 or
     * above will result in an exception if this is not followed.
     *
     * @param validateOnline boolean value which indicates that whether the check needs to
     *                       be performed online or only local.
     * @return
     */
    public boolean isValid(boolean validateOnline) {
        boolean valid = false;
        try {
            valid = isValidInternal(validateOnline);
        } catch (OMMobileSecurityException e) {
            OMLog.error(TAG, e.getMessage());
        }
        return valid;
    }

    /**
     * Checks whether the token is valid based on the expiry time.In case of
     * authentication using M&S server, if the expiry time has not been elapsed,
     * then SDK will check with M&S server, whether the tokens are actually
     * valid.
     * <p/>
     * So, it is recommended to call this method from a thread other than the UI
     * thread. In case, the apps are targeted for devices with Android 3.0 and
     * above, this method <b>should be</b> called from a thread other than UI
     * thread. Please note this api will perform validation of the tokens
     * against server in Mobile and Social authentication. For specific
     * preference refer to {@link OMAuthenticationContext#isValid(boolean)}
     * where we can control this behavior.
     *
     * @return true / false
     */
    public boolean isValid() {
        // since this is released api with default behavior is to validate
        // Online when applicable.
        return isValid(true);
    }

    /**
     * This is internal isValid which will be called from the public isValids.
     * This facilitates the public api preference for the validateOnline
     * preference.
     *
     * @param validateOnline true if online validation is needed else pass false.
     * @return
     * @throws OMMobileSecurityException if an exception occurs
     */
    private boolean isValidInternal(boolean validateOnline)
            throws OMMobileSecurityException {
        OMLog.debug(TAG, "__isValidInternal__");
        if (mASM == null) {
            return false;
        } else {
            if (mASM.getMSS().isLogoutInProgress()) {
                return false;
            }
            if (getAuthenticationProvider() == null) {
                return false;
            }
            if (getAuthenticationProvider() == AuthenticationProvider.OAUTH20 || getAuthenticationProvider() == AuthenticationProvider.OPENIDCONNECT10) {
                if (getOAuthTokenList().isEmpty()
                        && getAuthenticatedMode() == AuthenticationMode.ONLINE) {
                    return false;
                }
            }
            boolean isValid = true;

            if (mASM.getMSS().retrieveAuthenticationContext() == null) {
                return false;
            }
            if (mASM != null) {
                // Since the list of authentication services are lazily loaded, we
                // will no have all the authentication service instances to validate
                // the token. Hence load all the services here and perform the
                // validation. Once the work is done, unload all the services to
                // release the memory
                mASM.loadAllAuthenticationServices();
                OMLog.debug(TAG, "AuthContext validity check online ? "
                        + validateOnline);

                String credentialKey = this.mStorageKey;
                String authenticationUrl = mASM.getMSS().getMobileSecurityConfig().getAuthenticationURL().toString();

                String serverSpecificKey = OfflineAuthenticationService
                        .createServerSpecificKey(authenticationUrl, credentialKey, getIdentityDomain(),
                                getUserName());
                OMCredential credential = mASM.getMSS()
                        .getCredentialStoreService().getCredential(serverSpecificKey);
                boolean credentialsAvailable = false;
                if (credential != null
                        && !TextUtils.isEmpty(credential.getUserName())
                        && !TextUtils.isEmpty(credential.getUserPassword())) {
                    credentialsAvailable = true;
                }

                for (AuthenticationService authService : mASM
                        .getAuthServiceMap().values()) {
                    // As this is the old/existing api we are passsing true,
                    // since the default behavior was to check online whenever
                    // possible
                    isValid = authService.isValid(this, validateOnline);

                    if (!isValid) {
                        // Remove from the credential store as well
                        boolean isDeleteUnPwd = !(mASM.getMSS()
                                .getMobileSecurityConfig()
                                .isOfflineAuthenticationAllowed());

                        boolean isDeleteTokensAndCookies = true;
                        boolean justRetainIdleTimeExpiryAsEpoch = false;

                        if (authService instanceof BasicAuthenticationService) {
                            if (authContextDeleted) {
                                break;
                            }
                            BasicAuthenticationService basicAuthenticationService = ((BasicAuthenticationService) authService);
                            /**
                             * once the session is expired then remove the
                             * credentials completely from the store.
                             */
                            isDeleteUnPwd = basicAuthenticationService
                                    .isSessionTimedOut();
                            idleTimeExpired = basicAuthenticationService
                                    .isIdleTimeOut();
                            isDeleteTokensAndCookies = !(idleTimeExpired && credentialsAvailable);

                        } else if (authService instanceof OfflineAuthenticationService) {
                            idleTimeExpired = ((OfflineAuthenticationService) authService)
                                    .isIdleTimeOut();
                            isDeleteTokensAndCookies = !(idleTimeExpired && credentialsAvailable);
                        }

                        deleteAuthContext(isDeleteUnPwd,
                                isDeleteTokensAndCookies, isDeleteTokensAndCookies,
                                false, justRetainIdleTimeExpiryAsEpoch);
                        if (authService instanceof BasicAuthenticationService
                                && ((BasicAuthenticationService) authService)
                                .isSessionTimedOut()
                                || !(authService instanceof BasicAuthenticationService)) {
                        /*
                         * Setting this to true so that deleteAuthContext() is
                         * not called again when
                         * OMAuthenticationContext#isValid() is called
                         * subsequently. If it is called, it would lead to
                         * unnecessary invocation of logout url again.
                         */
                            authContextDeleted = true;
                        }
                    /* since its not a logout call */
                        break;
                    }
                }

                mASM.unloadAuthServices();
            }

            return isValid;
        }
    }

    /**
     * Checks the validity of the OAuth tokens. If a token that matches the
     * request scopes is expired, it is refreshed if the refreshExpiredTokens
     * flag passed is true.
     *
     * @param scopes               The set of OAuth scopes to check in the token
     * @param refreshExpiredTokens {@code}true if the expired tokens should be refreshed.
     * @return true / false depending upon the validity of the tokens.
     */
    public boolean isValid(Set<String> scopes, boolean refreshExpiredTokens) {
        boolean isValid = false;
        try {
            isValid = isValidInternal(scopes, refreshExpiredTokens);
        } catch (OMMobileSecurityException e) {
            OMLog.error(TAG, e.getMessage());
        }
        return isValid;
    }

    private boolean isValidInternal(Set<String> scopes,
                                    boolean refreshExpiredTokens) throws OMMobileSecurityException {
        boolean isValid = false;
        // list to store the matching tokens with the scopes passed
        if (authenticationProvider == AuthenticationProvider.OAUTH20
                || authenticationProvider == AuthenticationProvider.OPENIDCONNECT10) {
            if (mASM != null) {
                // loading OAuth20 service in map

                AuthenticationService.Type serviceType;
                if (authenticationProvider == AuthenticationProvider.OAUTH20) {
                    serviceType = mASM.getOAuthServiceType();
                } else {
                    serviceType = AuthenticationService.Type.OPENIDCONNECT10;
                }
                if (serviceType != null) {
                    mASM.getAuthServiceMap()
                            .put(serviceType, // TODO handle for all grant types
                                    mASM.getAuthService(serviceType));
                    OAuthAuthenticationService oAuthService = (OAuthAuthenticationService) mASM
                            .getAuthServiceMap().get(serviceType);
                    if (oAuthService != null) {
                        OMLog.info(TAG, "Checking validity for : " + oAuthService.getType().name());
                        isValid = oAuthService.isValid(this, scopes,
                                refreshExpiredTokens);
                    } else
                        isValid = false;
                    mASM.getAuthServiceMap().remove(serviceType);
                }
            }
        }
        return isValid;
    }

    /**
     * Returns the identity domain for which this authentication context is
     * created.
     *
     * @return the identityDomain
     */
    public String getIdentityDomain() {
        return identityDomain;
    }

    /**
     * Returns the username for which this authentication context is created.
     *
     * @return username string
     */
    public String getUserName() {
        return userName;
    }

    void setUserName(String userName) {
        this.userName = userName;
    }

    void setSessionExpiry(Date sessionExpiry) {
        this.sessionExpiry = sessionExpiry;
    }

    void setSessionExpInSecs(int sessionExpInSecs) {
        this.sessionExpInSecs = sessionExpInSecs;
    }

    int getSessionExpInSecs() {
        return sessionExpInSecs;
    }

    int getIdleTimeExpInSecs() {
        return idleTimeExpInSecs;
    }

    boolean resetIdleTime() {
        if (idleTimeExpInSecs > 0) {
            Calendar futureTime = Calendar.getInstance();
            futureTime.add(Calendar.SECOND, idleTimeExpInSecs);
            idleTimeExpiry = futureTime.getTime();
            return mTimeoutManager.resetTimer();
        } else {
            return false;
        }
    }


    /**
     * Gets the session expiry time for this authentication context.
     *
     * @return session expiry time.
     */
    public Date getSessionExpiry() {
        return sessionExpiry;
    }

    /**
     * Gets the idle time expiry for this authentication context.
     *
     * @return idle time expiry.
     */
    public Date getIdleTimeExpiry() {
        return idleTimeExpiry;
    }

    AuthenticationServiceManager getAuthenticationServiceManager() {
        return mASM;
    }

    /**
     * From the given authentication context string, remove the values whichever
     * is sent as true and return the rest of the string as a json string. This
     * is used in the case of deleting the values from the store based on
     * various conditions such as forget device, remove user token when logout,
     * remove offline credentials etc.,
     *
     * @param isDeleteUnPwd                   should we delete user name and password
     * @param isDeleteCookies                 should we delete cookies
     * @param justRetainIdleTimeExpiryAsEpoch whether everything should be deleted and just the idle time
     *                                        expiry should be retained as Epoch
     */
    void deleteAuthContext(boolean isDeleteUnPwd,
                           boolean isDeleteCookies, boolean isDeleteToken,
                           boolean isLogoutCall, boolean justRetainIdleTimeExpiryAsEpoch) {

        String TAG = OMAuthenticationContext.TAG + "_deleteAuthContext";

        if (mASM != null) {
            /*
             * Instead of removing cached instance here, it will be removed in
             * OMMobileSecurityService#onLogoutCompleted(). This change is
             * required so that SDK can clear the cookies set by OWSM MA
             * (OMAuthenticationContext#getOWSMMACookies()) after logout is done
             * by corresponding Authentication services.
             */
            if (isDeleteUnPwd
                    && isDeleteCookies && !isLogoutCall) {
                /*
                 * The cached instance should be removed here itself, if it is
                 * session timeout and not logout call, i.e when isValid is
                 * called.
                 */
                mASM.setAuthenticationContext(null);
            }

            OMCredentialStore css = mASM.getMSS().getCredentialStoreService();
            String credentialKey = getStorageKey() != null ? getStorageKey() : mASM.getAppCredentialKey();
            AuthenticationService authService = null;
            do {
                authService = mASM.getStateTransition().getLogoutState(
                        authService);
                OMLog.debug(TAG, "Logout authService: " + authService);
                if (authService != null) {
                    authService.logout(this, isDeleteUnPwd, isDeleteCookies, isDeleteToken,
                            isLogoutCall);
                }
            }
            while (authService != null);
            if (isDeleteUnPwd && isDeleteCookies) {
                //no op
                //TODO To check with Jyotsna why this is required. Ideally auth services can be unloaded irrespctive of these flags.
            } else {
                mASM.unloadAuthServices();
            }
        }
    }

    void setOpenIdUserInfo(OpenIDUserInfo info) {
        OMLog.debug(TAG, "Setting openID User info" + ((info != null) ? (" for user: " + info.getDisplayName()) : " null "));
        mOpenIDUserInfo = info;
    }

    public OpenIDUserInfo getOpenIDUserInfo() {
        if (authenticationProvider != AuthenticationProvider.OPENIDCONNECT10) {
            return null;
        }
        return mOpenIDUserInfo;
    }

    private void populateFields(String authContextString) {
        try {
            JSONObject jsonObject = new JSONObject(authContextString);
            this.userName = jsonObject.optString(USERNAME_KEY, "");
            this.identityDomain = jsonObject.optString(IDENTITY_DOMAIN_KEY, "");
            this.offlineCredentialKey = jsonObject.optString(
                    OFFLINE_CREDENTIAL_KEY, "");
            long sessionExp = jsonObject.optLong(SESSION_EXPIRY, -1);
            int sessionExpInSecs = jsonObject.optInt(SESSION_EXPIRY_SECS, -1);

            if (sessionExp != -1 && sessionExpInSecs != -1) {
                this.sessionExpiry = new Date(sessionExp);
                this.sessionExpInSecs = sessionExpInSecs;
            }

            long idleTimeExp = jsonObject.optLong(IDLETIME_EXPIRY, -1);
            int idleTimeExpInSecs = jsonObject.optInt(IDLETIME_EXPIRY_SECS, -1);

            if (idleTimeExp != -1 && idleTimeExpInSecs != -1) {
                this.idleTimeExpiry = new Date(idleTimeExp);
                this.idleTimeExpInSecs = idleTimeExpInSecs;
            }

            JSONArray jsonArray = jsonObject.optJSONArray(TOKENS);
            this.tokens = convertJSONArrayToMap(jsonArray);

            jsonArray = jsonObject.optJSONArray(OWSM_MA_COOKIES);
            this.owsmMACookies = convertJSONArrayToMap(jsonArray);

            mStatus = Status.SUCCESS;
            this.authenticatedMode = AuthenticationMode.valueOf(jsonObject
                    .optString(AUTHEN_MODE, AuthenticationMode.ONLINE.toString()));
            logoutTimeout = jsonObject.optInt(LOGOUT_TIMEOUT_VALUE);
        } catch (JSONException e) {
            OMLog.error(TAG + "_populateFields", e.getLocalizedMessage());
        }
    }

    String getUserPassword() {
        String password = null;
        OMMobileSecurityService mss = mASM.getMSS();
        OMCredentialStore credService = mss.getCredentialStoreService();
        if (!TextUtils.isEmpty(offlineCredentialKey)) {
            OMCredential credential = credService.getCredential(offlineCredentialKey);
            if (credential != null) {
                CryptoScheme scheme = mss.getMobileSecurityConfig()
                        .getCryptoScheme();
                if (CryptoScheme.isHashAlgorithm(scheme)) {
                    // Since the password is hashed, returning an empty
                    // String.
                    password = "";
                } else {
                    /* Since the password is available in plaintext (already decrypted by SecureStorageService),
                    just removing the prefix.*/
                    password = credential.getUserPassword();
                }
            }
        } else {
            OMLog.error(TAG, "Offline Key not set[SDK error]");
        }
        return password;
    }

    int getLogoutTimeout() {
        return logoutTimeout;
    }

    void setLogoutTimeout(int logoutTimeout) {
        this.logoutTimeout = logoutTimeout;
    }

    /**
     * This method performs the logout from the server. Clear the details stored
     * in the credential store. If the forgetDevice is true, then it will clear
     * the CRH handles as well; otherwise it will clear only the tokens stored.
     *
     * @param forgetDevice true if CRH also needs to be deleted(which is forget device)
     */
    @SuppressWarnings("deprecated")
    public void logout(boolean forgetDevice) {
        mASM.getMSS().setLogoutInProgress(true);
        boolean justRetainIdleTimeExpiryAsEpoch = false;

        if (forgetDevice) {
            if (authenticationProvider == AuthenticationProvider.FEDERATED
                    || authenticationProvider == AuthenticationProvider.OAUTH20) {
                /*
                 * Clearing username and password which may be stored in
                 * WebViewDatabase if authentication is done using embedded
                 * webview.
                 */

                //TODO ajulka see what we can do for OAuth here.
                WebViewDatabase webViewDatabase = WebViewDatabase
                        .getInstance(mASM.getApplicationContext());
                webViewDatabase.clearUsernamePassword();
                webViewDatabase.clearFormData();
                OMLog.debug(TAG, "Logout(true): Cleared username,password and form data");
            }
            // removing the credentials for the given url
            deleteAuthContext(true, true, true, true,
                    justRetainIdleTimeExpiryAsEpoch);
            // remove the user preferences as well
            if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
                mASM.getRCUtility().removeAll();
            }

        } else {
            deleteAuthContext(false, true, true, true,
                    justRetainIdleTimeExpiryAsEpoch);
            if (mASM.getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
                mASM.getRCUtility().inValidateRememberedCredentials();
            }
        }
    }

    /**
     * This method will be called internally to clear the fields which are not
     * necessary once the authentication operation is completed.
     */
    void clearFields() {
        if (mAuthRequest != null && mAuthRequest.getAuthenticationURL() != null) {
            mASM.getMSS().getMobileSecurityConfig()
                    .setAuthenticationURL(mAuthRequest.getAuthenticationURL());
        }
        this.mAuthRequest = null;

        String userNameFromMap = (String) getInputParams().get(USERNAME_KEY);
        if (userNameFromMap != null) {
            this.userName = userNameFromMap;
        }
        this.identityDomain = (String) getInputParams().get(IDENTITY_DOMAIN_KEY);
        this.getInputParams().clear();
    }

    /**
     * This method is used internally to clear all the fields of this object
     * once the authentication is failure.
     */
    void clearAllFields() {
        mASM = null;
        mAuthRequest = null;
        this.idleTimeExpiry = null;
        this.sessionExpiry = null;
        this.sessionExpInSecs = 0;
        this.idleTimeExpInSecs = 0;
        this.tokens = null;

        String userNameFromMap = (String) getInputParams().get(USERNAME_KEY);
        if (userNameFromMap != null) {
            this.userName = userNameFromMap;
        }
        this.getInputParams().clear();
        this.authenticationProvider = null;
    }

    boolean checkIdleTimeout() {
        Date currentTime = Calendar.getInstance().getTime();
        if (sessionExpiry != null
                && getSessionExpInSecs() != 0
                && (currentTime.after(sessionExpiry) || currentTime
                .equals(sessionExpiry))) {
            return false;
        }
        if (idleTimeExpiry != null
                && getIdleTimeExpInSecs() != 0
                && (currentTime.after(idleTimeExpiry) || currentTime
                .equals(idleTimeExpiry))) {
            isIdleTimeout = true;
        }
        OMLog.debug(TAG, "checkIdleTimeout in authcontext " + isIdleTimeout);
        return isIdleTimeout;
    }

    void setIdleTimeout(boolean isIdleTimeout) {
        this.isIdleTimeout = isIdleTimeout;
    }

    boolean isIdleTimeout() {
        return isIdleTimeout;
    }

    /**
     * @return TimeoutManager
     * @hide
     */
    public TimeoutManager getTimeoutManager() {
        return mTimeoutManager;
    }

    void setOAuthTokenList(List<OAuthToken> newTokenList) {
        this.oAuthTokenList = newTokenList;
    }

    /**
     * Returns all access tokens obtained as part of OAuth.
     * @return
     */
    public List<OAuthToken> getOAuthTokenList() {
        if (oAuthTokenList == null) {
            oAuthTokenList = new ArrayList<>();
        }
        return oAuthTokenList;
    }


    private boolean isOAuthRelated() {

        boolean isOAuth = false;
        if (authenticationProvider == AuthenticationProvider.OAUTH20 || authenticationProvider == AuthenticationProvider.OPENIDCONNECT10) {
            isOAuth = true;
        } else if (authenticationProvider == AuthenticationProvider.FEDERATED) {
            if (((OMFederatedMobileSecurityConfiguration) mASM.getMSS().getMobileSecurityConfig()).parseTokenRelayResponse()) {
                isOAuth = true;
            }
        }
        OMLog.info(TAG, "isOAuthRelated : " + isOAuth);
        return isOAuth;
    }

    /**
     * This method returns a list of available OAuth2.0 access tokens based on
     * the Scopes passed. If null is passed as scopes then the SDK will return
     * all the non expired access tokens . Other wise it will return all the
     * access tokens whose scopes contains all the scopes passed in the request
     * .
     *
     * @param scopes {@link List} of scopes for which we want to get the access
     *               tokens .
     * @return {@link List} of Access tokens matching the criteria .
     */
    public List<OMToken> getTokens(Set<String> scopes) {
        List<OMToken> matchedTokens = new ArrayList<OMToken>();
        /*
         * In case of FedAuth, we get OAuth access token from Token Relay
         * service.
         */
       /* if (this.authenticationProvider != AuthenticationProvider.OAUTH20
                && !(authenticationProvider == AuthenticationProvider.FEDERATED && ((OMFederatedMobileSecurityConfiguration) mASM
                .getMSS().getMobileSecurityConfig())
                .parseTokenRelayResponse())) {
            return null;
        }*/

        if (!isOAuthRelated()) {
            return null;
        }
        if (scopes == null || scopes.size() == 0) {
            for (OMToken token : getOAuthTokenList()) {
                matchedTokens.add(token);
            }
        } else {
            for (OMToken token : getOAuthTokenList()) {
                OAuthToken oAuthToken = (OAuthToken) token;
                if (oAuthToken.getScopes() != null) {
                    if (oAuthToken.getScopes().containsAll(scopes)) {
                        if (!token.isTokenExpired()) {
                            // return only if token is not expired
                            matchedTokens.add(token);
                        }
                    }
                } else {
                    // return auxillary tokens also as these are without scopes
                    // and an oauth access token is always associated with a
                    // scope if not set a default scopes is associated with the
                    // token.
                    matchedTokens.add(token);
                }
            }
        }
        return matchedTokens;
    }

    /**
     * This method returns a Map of requested credential information from the
     * credential store. It also contains custom headers to be injected in the
     * web service request, if any. Currently, this method supports the
     * following keys: <br />
     * <br />
     * <p/>
     * {@link #CREDENTIALS} - Returns credentials of the user associated with this
     * authentication context. Format of the returned map :
     * {{@link #USERNAME_PROPERTY}:"username_value",
     * {@link #PASSWORD_PROPERTY}:"password_value",
     * {@link #HEADERS}:{"headerName1":"headerValue1","headerName2":"headerValue2",...}
     * } <br />
     * <br />
     * {@link OMSecurityConstants#OAUTH_ACCESS_TOKEN} - Returns OAuth access tokens associated with
     * this authentication context.
     * <p/>
     * Format of the returned map : {"oauth_access_token1":"value1",
     * "oauth_access_token2":"value2",...,
     * "{@link #HEADERS}":{"headerName1":"headerValue1"
     * ,"headerName2":"headerValue2",...}}
     *
     * @param keys a String array of the information requested. e.g. credentials
     *             or tokens.
     * @return map of requested credential information.
     */
    public Map<String, Object> getCredentialInformation(String[] keys) {
        Map<String, Object> credentialInfo = new HashMap<String, Object>();
        for (String key : keys) {
            if (key.equalsIgnoreCase(CREDENTIALS)) {
                String password = getUserPassword();
                if (TextUtils.isEmpty(password)) {
                    credentialInfo.put(ERROR, CREDENTIALS_UNAVAILABLE);
                } else {
                    credentialInfo.put(USERNAME_PROPERTY, getUserName());
                    credentialInfo.put(PASSWORD_PROPERTY, password);
                }
            } else {
                try {
                    credentialInfo.putAll(getTokensMapForCredInfo(key));
                } catch (JSONException e) {
                    OMLog.error(TAG, "getCredentialInformation(" + key + "): "
                            + e.getMessage(), e);
                }
            }
        }
        Map<String, String> headers = getCustomHeaders();
        if (!headers.isEmpty()) {
            credentialInfo.put(HEADERS, headers);
        }
        return credentialInfo;
    }


    /**
     * This method stores the credential information <code>credInfo</code>
     * passed in this authentication context. Currently, this method only
     * supports cookies. It sets the cookies passed in the map
     * <code>credInfo</code> to the cookie store of the mobile app.
     *
     * @param credInfo Map of the values to set. Format of the map expected in case
     *                 of cookies: {"cookie1Name_cookie1Domain": {"name":"cookieName"
     *                 "domain", "cookieDomain" "expiresdate",
     *                 "cookieExpiryInMilliseconds" ... }, ...}
     */
    public void setCredentialInformation(Map<String, Object> credInfo) {
        for (Map.Entry<String, Object> entry : credInfo.entrySet()) {
            Map<String, String> cookieValues = (Map<String, String>) entry
                    .getValue();
            String tokenName = cookieValues.get(TOKEN_NAME);
            String url = cookieValues.get(URL);
            String tokenValue = cookieValues.get(TOKEN_VALUE);
            String expiryDateStr = cookieValues.get(EXPIRY_DATE);

            String domain = cookieValues.get(DOMAIN);
            boolean httpOnly = Boolean.parseBoolean(cookieValues
                    .get(IS_HTTP_ONLY));
            boolean secure = Boolean.parseBoolean(cookieValues.get(IS_SECURE));
            String path = cookieValues.get(PATH);
            OMToken cookie = new OMCookie(url, tokenName, tokenValue, domain,
                    path, expiryDateStr, httpOnly, secure);
            String cookieNameWithHostAppended = entry.getKey();
            getOWSMMACookies().put(cookieNameWithHostAppended, cookie);
            OMLog.debug(TAG,
                    "Cookie obtained from OWSM MA: " + cookie.toString());

            Map<String, OMToken> tokens = new HashMap<String, OMToken>();
            tokens.put(cookieNameWithHostAppended, cookie);
            mASM.storeCookieString(tokens, false);
        }

        updateAuthContextWithOWSMCookies();
    }

    /**
     * This updates the authContext string stored in SharedPreferences with the
     * new set of OWSM MA cookies.
     */
    private void updateAuthContextWithOWSMCookies() {
        boolean authContextPersistenceAllowed = mASM.getMSS()
                .getMobileSecurityConfig().isAuthContextPersistenceAllowed();
        if (authContextPersistenceAllowed) {
            OMCredentialStore css = mASM.getMSS()
                    .getCredentialStoreService();
            String credentialKey = getStorageKey() != null ? getStorageKey()
                    : mASM.getAppCredentialKey();

            String authContextString = css.getAuthContext(credentialKey);
            try {
                JSONObject authContextJSONObject = new JSONObject(
                        authContextString);
                authContextJSONObject.putOpt(OWSM_MA_COOKIES,
                        convertMapToJSONArray(getOWSMMACookies()));
                String newAuthContext = authContextJSONObject.toString();
                css.addAuthContext(credentialKey, newAuthContext);
                OMLog.debug(TAG + "_updateAuthContextWithOWSMCookies",
                        "authentication context for the key " + credentialKey
                                + " in the credential store is : "
                                + newAuthContext);
            } catch (JSONException e) {
                OMLog.error(TAG + "_updateAuthContextWithOWSMCookies",
                        e.getMessage(), e);
            }

        }
    }

    private JSONArray convertMapToJSONArray(Map<String, OMToken> tokens)
            throws JSONException {
        JSONArray jsonArray = new JSONArray();
        for (Map.Entry<String, OMToken> entry : tokens.entrySet()) {
            OMToken token = entry.getValue();

            JSONObject tokenJson = new JSONObject();
            tokenJson.put(URL, token.getUrl());
            tokenJson.put(TOKEN_NAME, token.getName());
            tokenJson.put(TOKEN_VALUE, token.getValue());

            if (token.getExpiryTime() != null) {
                tokenJson.put(EXPIRY_SECS, token.getExpiryTime().getTime());
            }
            if (token.getDomain() != null) {
                tokenJson.put(DOMAIN, token.getDomain());
            }
            if (token.getPath() != null) {
                tokenJson.put(PATH, token.getPath());
            }
            tokenJson.put(HTTP_ONLY, token.isHttpOnly());
            tokenJson.put(SECURE, token.isSecure());

            JSONObject jsonToken = new JSONObject();
            jsonToken.put(entry.getKey(), tokenJson);

            jsonArray.put(jsonToken);
        }
        return jsonArray;
    }

    private Map<String, OMToken> convertJSONArrayToMap(JSONArray jsonArray)
            throws JSONException {
        if (jsonArray != null) {
            Map<String, OMToken> tokens = new HashMap<String, OMToken>();
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject tokenObj = jsonArray.getJSONObject(i);

                @SuppressWarnings("rawtypes")
                Iterator itr = tokenObj.keys();
                String key = (String) itr.next();

                JSONObject value = tokenObj.getJSONObject(key);

                String url = value.optString(URL);
                String tokenName = value.optString(TOKEN_NAME, "");
                String tokenValue = value.optString(TOKEN_VALUE, "");
                long expiryStr = value.optLong(EXPIRY_SECS, -1);

                Date expiry = null;
                if (expiryStr != -1) {
                    expiry = new Date(expiryStr);
                }

                String domain = value.optString(DOMAIN, null);
                String path = value.optString(PATH, null);
                boolean httpOnly = value.optBoolean(HTTP_ONLY);
                boolean secure = value.optBoolean(SECURE);

                OMToken token = new OMToken(url, tokenName, tokenValue, domain,
                        path, expiry, httpOnly, secure);
                tokens.put(key, token);
            }

            return tokens;
        }
        return null;
    }

    /**
     * This returns the cookies corresponding to the given URL, as returned by
     * {@link OMCookieManager#getCookie(String)}. The return map will
     * also contain the custom headers if includeHeaders flag is true.
     *
     * @param url            Url for which request params are required.
     * @param includeHeaders flag to indicate, if custom headers are required.
     * @return Format of the returned map : {{@link #COOKIES}:{@link OMCookieManager#getCookie(String)},
     * "{@link #HEADERS}":{"headerName1":"headerValue1"
     * ,"headerName2":"headerValue2",...}}
     */
    public Map<String, Object> getRequestParams(String url,
                                                boolean includeHeaders) {
        Map<String, Object> params = new HashMap<String, Object>();
        String cookieString = OMCookieManager.getInstance().getCookie(url);
        if (!TextUtils.isEmpty(cookieString)) {
            params.put(COOKIES, cookieString);
        }
        Map<String, String> headers = getCustomHeaders();
        if (includeHeaders && !headers.isEmpty()) {
            params.put(HEADERS, headers);
        }
        return params;
    }

    /**
     * This returns the custom headers which are to be added in REST calls made by the app.
     * This is formed from the values set using the following properties:
     * <ul>
     * <li> {@link OMMobileSecurityService#OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT}
     * <li> {@link OMMobileSecurityService#OM_PROP_SEND_IDENTITY_DOMAIN_HEADER_TO_MOBILE_AGENT}
     * <li> {@link OMMobileSecurityService#OM_PROP_IDENTITY_DOMAIN_HEADER_NAME}
     * <li> {@link OMMobileSecurityService#OM_PROP_IDENTITY_DOMAIN_NAME}
     * </ul>
     */
    public Map<String, String> getCustomHeaders() {
        Map<String, String> headers = new HashMap<>();
        if (mASM == null) {
            return headers;
        }
        OMMobileSecurityConfiguration config = mASM.getMSS().getMobileSecurityConfig();
        if (config.getCustomHeadersMobileAgent() != null
                && !config.getCustomHeadersMobileAgent().isEmpty()) {
            headers.putAll(config.getCustomHeadersMobileAgent());
        }
        if (!TextUtils.isEmpty(identityDomain)
                && config.isSendIdDomainToMobileAgent()) {
            headers.put(config.getIdentityDomainHeaderName(), identityDomain);
        }
        return headers;
    }

    // returns map for tokens if at all the valid keys are passed other wise
    // returns nothing.
    private Map<String, Object> getTokensMapForCredInfo(String requestedToken)
            throws JSONException {
        Map<String, Object> tokensMap = new HashMap<String, Object>();

        if (OMSecurityConstants.OAUTH_ACCESS_TOKEN
                .equalsIgnoreCase(requestedToken)) {
            int count = 1;
            
           /* if (getAuthenticationProvider() == AuthenticationProvider.OAUTH20
                    || (getAuthenticationProvider() == AuthenticationProvider.FEDERATED && ((OMFederatedMobileSecurityConfiguration) mASM
                    .getMSS()
                    .getMobileSecurityConfig())
                    .parseTokenRelayResponse())) {*/

            if (isOAuthRelated()) {
                // can have oauth access tokens, user_assertion and
                // client_assertion
                // populate OAuth access tokens.
                for (OMToken token : getOAuthTokenList()) {
                    Map<String, String> tokenValues = new HashMap<String, String>();
                    tokenValues.put(TOKEN_NAME, token.getName());
                    tokenValues.put(TOKEN_VALUE, token.getValue());
                    tokenValues.put(EXPIRES, token.getExpiryTime()
                            .toString());
                    Set<String> scopes = ((OAuthToken) token).getScopes();
                    if (scopes != null && !scopes.isEmpty()) {
                        tokenValues.put(OAUTH_TOKEN_SCOPE, scopes.toString());
                    }
                    tokensMap.put(OAUTH_ACCESS_TOKEN + count, tokenValues);
                    count++;
                }
            }
        }
        // handle other token keys later.
        return tokensMap;
    }

    /**
     * Gets a map of token name as key and value as instance of {@link OMToken}.
     *
     * @return Map instance
     */
    public Map<String, OMToken> getTokens() {
        if (tokens == null) {
            tokens = new HashMap<String, OMToken>();
        }

        return tokens;
    }

    public Map<String, OMToken> getOWSMMACookies() {
        if (owsmMACookies == null) {
            owsmMACookies = new HashMap<String, OMToken>();
        }

        return owsmMACookies;
    }


    void setTokens(Map<String, OMToken> tokens) {
        this.tokens = tokens;
    }

    public Set<URI> getVisitedUrls() {
        return mVisitedUrls;
    }

    void setCookies(List<OMCookie> cookies) {
        mCookies = cookies;
    }

    public List<OMCookie> getCookies() {
        return mCookies;
    }

    void setVisitedUrls(Set<URI> visitedUrls) {
        mVisitedUrls = visitedUrls;
    }

    /**
     * Deletes the cookies locally to be on safe side, although server might have deleted them
     * as part of invoking logout url. Cookies have to be deleted locally only after logout url is invoked.
     * If they are deleted before invoking logout url, it will result in dangling sessions at server side.
     */
    public void deleteCookies() {
        OMLog.trace(TAG, "deleteCookies");
        OMCookieManager.getInstance().removeSessionCookies(mASM.getApplicationContext(), mCookies);
    }

}
