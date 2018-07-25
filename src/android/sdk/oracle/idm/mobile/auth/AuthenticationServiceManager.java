/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.content.Context;
import android.os.AsyncTask;
import android.text.TextUtils;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMExceptionEvent;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.logout.FedAuthLogoutCompletionHandler;
import oracle.idm.mobile.auth.logout.OAuthAuthorizationCodeLogoutHandler;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMAuthenticationScheme;
import oracle.idm.mobile.configuration.OMBasicMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMFederatedMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMMSOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.connection.CBAExceptionEvent;
import oracle.idm.mobile.connection.InvalidCredentialEvent;
import oracle.idm.mobile.connection.InvalidRedirectExceptionEvent;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.connection.SSLExceptionEvent;
import oracle.idm.mobile.credentialstore.OMCredential;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.LogUtils;

import static oracle.idm.mobile.OMSecurityConstants.COOKIE_EXPIRY_DATE_PATTERN;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION;
import static oracle.idm.mobile.OMSecurityConstants.OAUTH_MS_VALID_CLIENT_ASSERTION_PRESENT;
import static oracle.idm.mobile.OMSecurityConstants.Param.COLLECT_OFFLINE_CREDENTIAL;


/**
 * AuthenticationServiceManager orchestrates the entire authentication flow.
 * the communication is as follows:
 * <p/>
 * [APP]                                   --- authenticate ----------------> [OMMobileSecurityService]
 * <p/>
 * [OMMobileSecurityService]         --- startAuthentication ---------> [ASM]
 * <p/>
 * [ASM]                                   --- determineInitialState -------> [ASM]
 * <p/>
 * [ASM]                                   --- collectLoginChallengeInput -------> [AuthenticationService]
 * <p/>
 * [AuthenticationService]                 --- createChallengeRequest ------> [OMAuthenticationCompletionHandler]
 * <p/>
 * [OMAuthenticationCompletionHandler]     --- onAuthenticationChallenge ---> [OMMobileSecurityServiceCallback]
 * <p/>
 * [OMMobileSecurityServiceCallback] --- proceed ---------------------> [OMAuthenticationCompletionHandler]
 * <p/>
 * [OMAuthenticationCompletionHandler]     --- onInput ---------------------> [AuthenticationService]
 * <p/>
 * [AuthenticationService]                 --- onInputAvailable ------------> [ASM]
 * <p/>
 * [ASM]                                   --- doStateTransition -----------> [ASM]
 * <p/>
 * [ASM]                                   --- handleAuthentication --------> [AuthenticationService]
 * <p/>
 * [AuthenticationService]                 --- onAuthDone ------------------> [ASM]
 * <p/>
 * [ASM]                                   --- onAuthenticationCompleted ---> [OMMobileSecurityServiceCallback]
 * <p/>
 * TODO -  2-way SSL
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class AuthenticationServiceManager {
    private static final String TAG = AuthenticationServiceManager.class.getSimpleName();
    private static final String OFFLINE_AUTH_RETRY_COUNT = "offlineAuthRetryCount";
    private OMMobileSecurityService mMSS;
    private AuthStateTransition mStateTransition;
    private OMMobileSecurityServiceCallback mAppCallback;
    private Map<AuthenticationService.Type, AuthenticationService> mAuthServices;
    //map holding each authentication service type and their respective completion handlers
    private Map<AuthenticationService.Type, OMAuthenticationCompletionHandler> mAuthServiceHandlers;
    private ASMInputController mASMInputController;
    private OAuthConnectionsUtil mOAuthConnectionsUtil;
    private OMAuthenticationContext mAuthContext;
    /**
     * This is used to store user input (username, password) and authentication
     * exception details which need to be populated in the challenge
     * when onAuthenticationChallenge is called again (e.g: after
     * a failed authentication attempt because of invalid credentials)
     */
    private OMAuthenticationContext mTemporaryAuthContext;
    private RCUtility mRCUtility;

    private boolean isBasic;
    private boolean isOAuth;
    private boolean isFedAuth;
    private boolean isOfflineAllowed;
    private boolean isCBAAllowed;
    private boolean isOpenID;
    private boolean isClientRegistration;
    private OAuthMSToken mClientAssertion;

    public AuthenticationServiceManager(OMMobileSecurityService mss) {
        mMSS = mss;
        initialize();
    }

    private void initialize() {
        OMLog.info(TAG, "initialize");
        initAuthServiceHandlers();
    }

    public OAuthConnectionsUtil getOAuthConnectionsUtil() {
        if (mOAuthConnectionsUtil == null &&
                getMSS().getMobileSecurityConfig() instanceof OMOAuthMobileSecurityConfiguration) {
            mOAuthConnectionsUtil = new OAuthConnectionsUtil(getApplicationContext(),
                    (OMOAuthMobileSecurityConfiguration) getMSS().getMobileSecurityConfig(),
                    null);
        }
        return mOAuthConnectionsUtil;
    }

    boolean isOAuthOrOpenID() {
        return (isOpenID || isOAuth);
    }

    public boolean isClientRegistrationRequired() {
        return isClientRegistration;
    }

    private void initAuthServiceHandlers() {
        OMLog.info(TAG, "initAuthServiceHandlers");
        OMMobileSecurityConfiguration config = getMSS().getMobileSecurityConfig();
        isBasic = (config instanceof OMBasicMobileSecurityConfiguration);
        isOAuth = (config instanceof OMOAuthMobileSecurityConfiguration);
        isFedAuth = (config instanceof OMFederatedMobileSecurityConfiguration);
        isOfflineAllowed = config.isOfflineAuthenticationAllowed();
        isCBAAllowed = (getMSS().getMobileSecurityConfig().getAuthenticationScheme()) == OMAuthenticationScheme.CBA;
        isOpenID = config.getAuthenticationScheme() == OMAuthenticationScheme.OPENIDCONNECT10;
        isClientRegistration = isOAuthOrOpenID() && ((OMOAuthMobileSecurityConfiguration) mMSS.getMobileSecurityConfig()).isClientRegistrationRequired();
        /*TODO Abhishek Possible bug: If authenticate() is called from Feature 1 with appCallback1, and then if authenticate() is called from Feature 2
          with appCallback2, then after authentication from Feature 1, callback will be invoked on appCallback2.
          Solution: Create new instance of AuthenticationHandler for every authentication attempt. Store FedAuthHandler alone in the map for cancel functionality. */
        mAuthServiceHandlers = new HashMap<>();
        if (isBasic)
            mAuthServiceHandlers.put(AuthenticationService.Type.BASIC_SERVICE, new BasicAuthCompletionHandler(getMSS().getMobileSecurityConfig(), getCallback()));
        if (isOAuth) {
            //here lets put the right completion handler to be used as per the given grant type.
            OAuthAuthorizationGrantType grantType = ((OMOAuthMobileSecurityConfiguration) config).getOAuthzGrantType();
            OMAuthenticationCompletionHandler handler = null;
            switch (grantType) {
                case AUTHORIZATION_CODE:
                    mAuthServiceHandlers.put(AuthenticationService.Type.OAUTH20_AC_SERVICE, new OAuthAuthorizationCodeCompletionHandler(this, config, false, getCallback()));
                    break;
                case RESOURCE_OWNER:
                    mAuthServiceHandlers.put(AuthenticationService.Type.OAUTH20_RO_SERVICE, new OAuthResourceOwnerCompletionHandler(config, getCallback()));
                    if (getMSS().getMobileSecurityConfig() instanceof OMMSOAuthMobileSecurityConfiguration) {
                        mAuthServiceHandlers.put(AuthenticationService.Type.OAUTH_MS_PREAUTHZ, new OAuthMSPreAuthzCodeAuthCompletionHandler(config, getCallback()));
                        mAuthServiceHandlers.put(AuthenticationService.Type.OAUTH_MS_DYCR, new OAuthMSPreAuthzCodeAuthCompletionHandler(config, getCallback()));
                    }
                    break;
                case CLIENT_CREDENTIALS:
                    //no op
                    break;
                default:
                    OMLog.error(TAG, "No Completion handler defined for grant type : " + grantType);
                    sendFailure(getCallback(), mAuthContext, new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR));
                    break;
            }
        }
        if (isOfflineAllowed)
            mAuthServiceHandlers.put(AuthenticationService.Type.OFFLINE_SERVICE, new OfflineAuthCompletionHandler(getMSS().getMobileSecurityConfig(), getCallback()));
        if (isFedAuth)
            mAuthServiceHandlers.put(AuthenticationService.Type.FED_AUTH_SERVICE, new FedAuthCompletionHandler(this, getMSS().getMobileSecurityConfig(), getCallback()));
        if (isCBAAllowed) {
            OMLog.info(TAG, "CBA Config!");
            mAuthServiceHandlers.put(AuthenticationService.Type.CBA_SERVICE, null);//since the completion handler is provided by the ASM OTB, just provided a dummy value
        }
        if (isOpenID) {
            mAuthServiceHandlers.put(AuthenticationService.Type.OPENIDCONNECT10, new OAuthAuthorizationCodeCompletionHandler(this, getMSS().getMobileSecurityConfig(), false, getCallback()));
        }
        if (isClientRegistration) {
            mAuthServiceHandlers.put(AuthenticationService.Type.CLIENT_REGISTRATION_SERVICE, new OAuthAuthorizationCodeCompletionHandler(this, getMSS().getMobileSecurityConfig(), true, getCallback()));
        }
    }

    OMMobileSecurityServiceCallback getCallback() {
        return mMSS.getCallback();
    }

    public ASMInputController getASMInputController() {
        return mASMInputController;
    }

    Map<AuthenticationService.Type, AuthenticationService> getAuthServiceMap() {
        if (mAuthServices == null) {
            mAuthServices = new ConcurrentHashMap<>();
        }
        return mAuthServices;
    }

    RCUtility getRCUtility() {
        if (mRCUtility == null) {
            OMLog.info(TAG, "Initializing RCUtility");
            mRCUtility = new RCUtility(getApplicationContext(), getMSS().getMobileSecurityConfig(),
                    getMSS().getCredentialStoreService());
        }
        return mRCUtility;
    }


    //unloads the auth services from the map.
    void unloadAuthServices() {
        Map<AuthenticationService.Type, AuthenticationService> authServiceMap = getAuthServiceMap();
        if (!authServiceMap.isEmpty()) {
            authServiceMap.remove(AuthenticationService.Type.OFFLINE_SERVICE);
            authServiceMap.remove(AuthenticationService.Type.BASIC_SERVICE);

            if (getOAuthConnectionsUtil() != null)
                authServiceMap.remove(getOAuthServiceType());
            OMLog.info(TAG, " unloaded all the auth services");
        }
    }


    AuthenticationService.Type getOAuthServiceType() {
        if (getOAuthConnectionsUtil() != null) {
            OAuthAuthorizationGrantType type = getOAuthConnectionsUtil().getOAuthGrantType();
            switch (type) {
                case AUTHORIZATION_CODE:
                    return AuthenticationService.Type.OAUTH20_AC_SERVICE;
                case RESOURCE_OWNER:
                    return AuthenticationService.Type.OAUTH20_RO_SERVICE;
                case CLIENT_CREDENTIALS:
                    return AuthenticationService.Type.OAUTH20_CC_SERVICE;
                default:
                    OMLog.error(TAG, "No Service type for grant type: " + type);
            }
        }
        OMLog.info(TAG, "Not an OAuth use case");
        //simply return OAuth RC
        return AuthenticationService.Type.OAUTH20_RO_SERVICE;
    }

    private void checkBeforeLoad(Map<AuthenticationService.Type, AuthenticationService> authServices, AuthenticationService.Type serviceName) {
        if (!authServices.containsKey(serviceName)) {
            AuthenticationService authenticationService = getAuthService(serviceName);
            if (authenticationService != null) {
                authServices.put(serviceName, authenticationService);
            }
        }
    }

    void loadAllAuthenticationServices() {

        Map<AuthenticationService.Type, AuthenticationService> authServices = getAuthServiceMap();
        AuthenticationService.Type serviceName;
        if (isBasic) {
            checkBeforeLoad(authServices, AuthenticationService.Type.BASIC_SERVICE);
        }
        if (isOfflineAllowed) {
            checkBeforeLoad(authServices, AuthenticationService.Type.OFFLINE_SERVICE);
        }
        if (isFedAuth) {
            checkBeforeLoad(authServices, AuthenticationService.Type.FED_AUTH_SERVICE);
        }
        if (isOAuth) {
            checkBeforeLoad(authServices, getOAuthServiceType());
        }
        if (isCBAAllowed) {
            checkBeforeLoad(authServices, AuthenticationService.Type.CBA_SERVICE);
        }
        if (isOpenID) {
            checkBeforeLoad(authServices, AuthenticationService.Type.OPENIDCONNECT10);
        }
        if (isClientRegistration) {
            checkBeforeLoad(authServices, AuthenticationService.Type.CLIENT_REGISTRATION_SERVICE);
        }
    }

    public AuthenticationService getAuthService(AuthenticationService.Type type) {
        AuthenticationService authService = getAuthServiceMap().get(type);
        if (authService != null) {
            return authService;
        }
        //get handler completion handler for the given type.
        OMAuthenticationCompletionHandler completionHandler = mAuthServiceHandlers.get(type);
        OAuthConnectionsUtil oAuthConnectionsUtil;
        if (completionHandler != null) {
            switch (type) {
                case OFFLINE_SERVICE:
                    authService = new OfflineAuthenticationService(this, completionHandler);
                    break;
                case BASIC_SERVICE:
                    authService = new BasicAuthenticationService(this, completionHandler);
                    break;
                case FED_AUTH_SERVICE:
                    authService = new FederatedAuthenticationService(this, completionHandler, new FedAuthLogoutCompletionHandler(getCallback()));
                    break;
                case OAUTH20_RO_SERVICE:
                    authService = new OAuthResourceOwnerService(this, completionHandler);
                    break;
                case OAUTH20_AC_SERVICE:
                    oAuthConnectionsUtil = getOAuthConnectionsUtil();
                    authService = new OAuthAuthorizationCodeService(this, completionHandler,
                            new OAuthAuthorizationCodeLogoutHandler(oAuthConnectionsUtil.getBrowserMode(),
                                    oAuthConnectionsUtil.getOAuthState(), getCallback()));
                    break;
                case CLIENT_REGISTRATION_SERVICE:
                    oAuthConnectionsUtil = getOAuthConnectionsUtil();
                    authService = new IDCSClientRegistrationService(this, completionHandler,
                            new OAuthAuthorizationCodeLogoutHandler(oAuthConnectionsUtil.getBrowserMode(),
                                    oAuthConnectionsUtil.getOAuthState(), getCallback()));
                    break;
                case OPENIDCONNECT10:
                    oAuthConnectionsUtil = getOAuthConnectionsUtil();
                    authService = new OpenIDConnect10AuthenticationService(this, completionHandler,
                            new OAuthAuthorizationCodeLogoutHandler(oAuthConnectionsUtil.getBrowserMode(),
                                    oAuthConnectionsUtil.getOAuthState(), getCallback()));//TODO change this to open ID
                    break;
                case OAUTH_MS_PREAUTHZ:
                    authService = new OAuthMSPreAuthZCodeService(this, completionHandler);
                    break;
                case OAUTH_MS_DYCR:
                    authService = new OAuthMSTwoLeggedDYCRService(this, completionHandler);
            }
        } else {
            //handle no input related services here!!
            OMLog.info(TAG, "No completion handler impl for type: " + type);
            if (type == AuthenticationService.Type.CBA_SERVICE) {
                //since this is a service which does not rely on app/user input
                authService = new CBAAuthenticationService(this, null);
            } else if (type == AuthenticationService.Type.OAUTH20_CC_SERVICE) {
                authService = new OAuthClientCredentialService(this, null);
            } else if (type == AuthenticationService.Type.REFRESH_TOKEN_SERVICE) {
                authService = new RefreshTokenAuthenticationService(this, null);
            }
        }
        if (authService != null) {
            //add this to the map.
            getAuthServiceMap().put(type, authService);
        }

        return authService;
    }

    OMAuthenticationCompletionHandler getAuthenticationCompletionHandler(AuthenticationService.Type type) {
        if (mAuthServiceHandlers != null) {
            return mAuthServiceHandlers.get(type);
        } else {
            return null;
        }
    }

    /**
     * This method returns an instance of {@link AuthStateTransition} which takes
     * care of deciding on the next step to complete the authentication request
     * and also populates the authentication context instance passed in with the
     * appropriate values from each service response. By default SDK constructs
     * an instance of {@link DefaultStateTransition}.
     *
     * @return an instance of {@link AuthStateTransition}
     */
    AuthStateTransition getStateTransition() {
        if (mStateTransition == null) {
            mStateTransition = new DefaultStateTransition(this);
        }
        return mStateTransition;
    }


    public void startAuthenticationProcess(OMAuthenticationRequest authRequest) {
        OMLog.info(TAG, "startAuthenticationProcess");
        boolean isForceAuthentication = false;
        //determine initial state
        //do stuff required before authentication process.
        OMAuthenticationContext existingAuthContext = retrieveAuthenticationContext();
        String authKey = getMSS().getMobileSecurityConfig().getAuthenticationKey();
        OMAuthenticationContext newAuthContext = new OMAuthenticationContext(this, authRequest, authKey);
        boolean isIdleTimeout = false;
        boolean useRefreshToken = false;
        if (existingAuthContext != null) {
            boolean isValid;
            if (authRequest.getAuthScheme() == OMAuthenticationScheme.OAUTH20
                    || authRequest.getAuthScheme() == OMAuthenticationScheme.OPENIDCONNECT10) {
                // If authContext is not valid with local checks, SDK tries to use refresh token.
                isValid = existingAuthContext.isValid(
                        ((OMOAuthMobileSecurityConfiguration) getMSS().getMobileSecurityConfig()).getOAuthScopes(),
                        false);
            } else {
                isValid = existingAuthContext.isValid(false);
            }
            if (isValid) {
                if (authRequest.isForceAuthentication()) {
                    OMCookieManager.getInstance().removeSessionCookies(getApplicationContext());
                    isForceAuthentication = true;
                } else {
                    OMLog.debug(TAG, "Existing authentication context is valid.");
                    existingAuthContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
                    sendSuccess(getMSS().getCallback(), existingAuthContext);
                    return;
                }
            } else {
                if ((authRequest.getAuthScheme() == OMAuthenticationScheme.OAUTH20
                        || authRequest.getAuthScheme() == OMAuthenticationScheme.OPENIDCONNECT10)
                        && existingAuthContext.hasRefreshToken()) {
                    newAuthContext.copyFromAuthContext(existingAuthContext);
                    useRefreshToken = true;
                }
                /*Check if idleTimeout of previous authContext has occurred,
                 * and set the idleTimeout flag in present authContext */
                isIdleTimeout = existingAuthContext.checkIdleTimeout();
                TimeoutManager timeoutManager = existingAuthContext.getTimeoutManager();
                if (timeoutManager != null) {
                    timeoutManager.stopTimers();
                }
            }
        }

        authRequest.setUseRefreshToken(useRefreshToken);

        //determine OAuth?
//        if (authRequest.getAuthScheme() == OMAuthenticationScheme.OAUTH20) {
//            mOAuthConnectionsUtil = new OAuthConnectionsUtil(authRequest);
//        }


        setTemporaryAuthenticationContext(newAuthContext);
        newAuthContext.setIdleTimeout(isIdleTimeout);
        //populate the inputParams MAP as required
        //may contain flags data like remember cred, or some specific input as when required.
        newAuthContext.setLogoutTimeout(authRequest.getLogoutTimeout());
        newAuthContext.setForceAuthentication(isForceAuthentication);
        AuthenticationService authService = null;
        try {
            authService = getStateTransition().getInitialState(authRequest);
        } catch (OMMobileSecurityException e) {

            OMLog.error(TAG, e.getMessage());
            mMSS.getCallback().onAuthenticationCompleted(mMSS, null, e);
        }
        if (authRequest.getAuthScheme() == OMAuthenticationScheme.OAUTH20) {
            OAuthConnectionsUtil oauthConnectionUtil = getOAuthConnectionsUtil();
            // M&S OAuth update params for MS OAuth cases
            if (oauthConnectionUtil != null && oauthConnectionUtil.getOAuthType() == OAuthConnectionsUtil.OAuthType.MSOAUTH) {
                updateInputParamsForMSOAuth(newAuthContext);
            }
        }
        //lets check for auto login.
        if (getMSS().getMobileSecurityConfig().isAutoLoginEnabled()) {
            boolean autoLoginEnabled = true;
            // now check if we have auto login credentials are stored and have auto
            // login selected from the UI in the previous successful authentication.
            boolean isAutoLoginFromStore = (getRCUtility().getAutoLoginUIPrefFromStore() == RCUtility.OPTION_SELECTED_BY_USER);
            if (isAutoLoginFromStore) {
                OMCredential autoLoginCredential = getRCUtility()
                        .retrieveRememberedCredentials();
                // replay the credentials as we found auto login credentials
                // in the store and also the feature is enabled from the UI.
                // if yes replay them by adding them in the input param map
                if (autoLoginCredential != null) {
                    String username = autoLoginCredential.getUserName();
                    String password = autoLoginCredential.getUserPassword();
                    String identity = autoLoginCredential.getIdentityDomain();
                    if ((username != null && username.length() > 0)
                            && (password != null && password.length() > 0)) {
                        OMLog.debug(TAG,
                                "Replaying the username and password from the store");
                        OMLog.debug(TAG, "username : " + username);
                        OMLog.debug(TAG, "iddomain : " + identity);
                        newAuthContext.getInputParams().put(OMSecurityConstants.Challenge.USERNAME_KEY, username);
                        newAuthContext.getInputParams().put(OMSecurityConstants.Challenge.PASSWORD_KEY, password);
                        if (identity != null && identity.length() > 0) {
                            newAuthContext.getInputParams().put(OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY,
                                    identity);
                        }
                    }
                }
            }
        }

        getMSS().refreshConnectionHandler(OMSecurityConstants.Flags.CONNECTION_FORCE_RESET, true);
        processAuthRequest(mMSS.getCallback(), authRequest, authService, newAuthContext);
    }

    private void updateInputParamsForMSOAuth(OMAuthenticationContext authContext) {
        if (!authContext.getInputParams().containsKey(OAUTH_MS_VALID_CLIENT_ASSERTION_PRESENT)) {
            OAuthMSToken clientAssertion = retrieveClientAssertion();
            if (clientAssertion != null) {
                boolean isExpired = clientAssertion.isTokenExpired();
                // just for collect input params.
                if (!isExpired)
                    authContext.getInputParams().put(
                            OAUTH_MS_VALID_CLIENT_ASSERTION_PRESENT, true);
                OMLog.debug(TAG + "_updateInputParamsForMSOAuth",
                        "client assertion valid. Updated the input params!");
            }
        }
    }

    public Context getApplicationContext() {
        return getMSS().getApplicationContext();
    }

    public OMMobileSecurityService getMSS() {
        return mMSS;
    }

    /**
     * Intermediate API which invokes the
     *
     * @param request
     * @param authService
     */

    // should be called from the UI or the caller thread
    // the engine should have done the required state transitioning(authService) before calling this API.
    public void processAuthRequest(OMMobileSecurityServiceCallback callback, OMAuthenticationRequest request, AuthenticationService authService, OMAuthenticationContext authContext) {
        OMLog.info(TAG, "processAuthRequest");
        if (authService != null) {
            mASMInputController = new ASMInputControllerImpl(callback, request, authService, authContext);
            authService.collectLoginChallengeInput(authContext.getInputParams(), mASMInputController);
        }
    }

    private void onInvalidRedirectReported(final InvalidRedirectExceptionEvent event, OMAuthenticationRequest request, AuthenticationService authenticationService, OMAuthenticationContext context) {
        InvalidRedirectExceptionEvent.Type type = event.getRedirectionType();
        if (event.getRedirectionType() == InvalidRedirectExceptionEvent.Type.UNKNOWN) {
            OMLog.error(TAG, "InvalidRedirectType : " + type + " Not Supported");
            sendFailure(getCallback(), context, new OMMobileSecurityException(OMErrorCode.INVALID_REDIRECTION_PROTOCOL_MISMATCH));
            return;
        }
        OMAuthenticationChallenge redirectChallenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.INVALID_REDIRECT_ENCOUNTERED);
        redirectChallenge.addChallengeField(OMSecurityConstants.Challenge.INVALID_REDIRECT_TYPE_KEY, type);
        ASMInvalidRedirectHandler redirectHandler = new ASMInvalidRedirectHandler(this, request, authenticationService, context, type);
        redirectHandler.createChallengeRequest(getMSS(), redirectChallenge, null);
    }


    static class ASMInvalidRedirectHandler extends OMAuthenticationCompletionHandler {
        private static final String TAG = ASMInvalidRedirectHandler.class.getSimpleName();
        private AuthenticationServiceManager iASM;
        private AuthenticationService iAuthService;
        private OMAuthenticationContext iAuthContext;
        private OMAuthenticationRequest iAuthRequest;
        private InvalidRedirectExceptionEvent.Type iType;

        protected ASMInvalidRedirectHandler(AuthenticationServiceManager asm, OMAuthenticationRequest request, AuthenticationService authService, OMAuthenticationContext authContext, InvalidRedirectExceptionEvent.Type type) {
            super(asm.getMSS().getMobileSecurityConfig(), asm.getCallback());
            iASM = asm;
            iAuthRequest = request;
            iAuthService = authService;
            iAuthContext = authContext;
            iType = type;
        }

        @Override
        protected void createChallengeRequest(final OMMobileSecurityService mss, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
            iASM.getCallback().onAuthenticationChallenge(mss, challenge, this);
        }

        @Override
        public void proceed(Map<String, Object> responseFields) {
            OMLog.info(TAG, "proceed");
            OMLog.info(TAG, "Application wants to proceed with invalid redirect");
            try {
                validateResponseFields(responseFields);
                int flag = 0;
                switch (iType) {
                    case HTTP_TO_HTTPS:
                        flag = OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTP_TO_HTTPS_REDIRECT;
                        break;
                    case HTTPS_TO_HTTP:
                        flag = OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTPS_TO_HTTP_REDIRECT;
                        break;
                    default:
                        break;
                }
                iASM.getMSS().refreshConnectionHandler(flag, true);//since we are setting
                iASM.processAuthRequest(iASM.getCallback(), iAuthRequest, iAuthService, iAuthContext);
            } catch (OMMobileSecurityException e) {
                //not likely
                OMLog.debug(TAG, "Response fields are not valid. Error : " + e.getErrorMessage());
                iASM.sendFailure(iASM.getCallback(), iAuthContext, e);
            }
        }

        @Override
        public void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {
            switch (iType) {
                case HTTPS_TO_HTTP:
                case HTTP_TO_HTTPS:
                    break;
                default:
                    throw new OMMobileSecurityException(OMErrorCode.INVALID_REDIRECTION_PROTOCOL_MISMATCH);
            }
        }

        @Override
        public void cancel() {
            OMLog.debug(TAG, "cancel redirect operation");
            //not likely
            iASM.sendFailure(iASM.getCallback(), iAuthContext, new OMMobileSecurityException(OMErrorCode.USER_CANCELED_INVALID_REDIRECT_OPERATION));
        }
    }


    /**
     * suppose to spawn new instance every time a new input is supplied from the handler.
     */
    final class AuthenticationAsyncTask extends AsyncTask<Void, Void, OMHTTPResponse> {

        final private String TAG = AuthenticationServiceManager.TAG + "." + AuthenticationAsyncTask.class.getSimpleName();
        final private AuthenticationService aAuthService;
        final private OMAuthenticationRequest aAuthRequest;
        final private OMAuthenticationContext aAuthContext;
        final private OMMobileSecurityServiceCallback aCallback;
        private OMMobileSecurityException aMSE;
        private boolean aRequireAppInput;

        AuthenticationAsyncTask(OMMobileSecurityServiceCallback callback, OMAuthenticationRequest authRequest, AuthenticationService authService, OMAuthenticationContext authContext) {
            aCallback = callback;
            aAuthRequest = authRequest;
            aAuthService = authService;
            aAuthContext = authContext;
        }

        @Override
        protected OMHTTPResponse doInBackground(Void... params) {
            if (aAuthService != null) {
                OMLog.info(TAG, "doInBackground authService: " + aAuthService.getType());
                try {
                    return aAuthService.handleAuthentication(aAuthRequest, aAuthContext);
                } catch (OMMobileSecurityException e) {
                    aMSE = e;
                    aAuthContext.setStatus(OMAuthenticationContext.Status.FAILURE);
                    aAuthContext.setException(e);
                    OMLog.error(TAG, e.getErrorMessage(), e);
                }
            } else {
                OMLog.info(TAG, "doInBackground authService: null");
            }
            return null;
        }

        @Override
        protected void onPostExecute(OMHTTPResponse response) {
            OMLog.info(TAG, "onPostExecute");
            OMAuthenticationContext.Status status = aAuthContext.getStatus();
            OMLog.debug(TAG, "Authentication context status : " + status);
            //lets handle SSL related failure here.
            if (aMSE != null) {
                OMExceptionEvent ee = aMSE.getExceptionEvent();
                if (ee != null) {
                    if (ee instanceof SSLExceptionEvent) {
                        //one way SSL
                        OMLog.info(TAG, "Untrusted server certificate scenario");
                        SSLExceptionEvent sslEvent = (SSLExceptionEvent) ee;
                        aRequireAppInput = true;
                        AuthenticationService.onUntrustedServerCertificate(AuthenticationServiceManager.this, sslEvent.getCertificateChain(),
                                sslEvent.getAuthType(), aAuthRequest, aAuthService, aAuthContext);
                        return;
                    } else if (ee instanceof InvalidCredentialEvent) {
                        aRequireAppInput = true;
                        sendFailureAfterRetry(aCallback, aAuthContext);
                        return;
                    } else if (ee instanceof CBAExceptionEvent) {
                        OMLog.info(TAG, "Client certificate required scenario");
                        aRequireAppInput = true;
                        AuthenticationService.onClientCertificateRequired(AuthenticationServiceManager.this, (CBAExceptionEvent) ee,
                                aAuthRequest, aAuthService, aAuthContext);
                        return;
                    } else if (ee instanceof InvalidRedirectExceptionEvent) {
                        OMLog.info(TAG, "Invalid redirect reported scenario");
                        aRequireAppInput = true;
                        onInvalidRedirectReported((InvalidRedirectExceptionEvent) ee, aAuthRequest, aAuthService, aAuthContext);
                        return;
                    } else {
                        sendFailureAfterRetry(aCallback, aAuthContext);
                    }
                    return;
                }
                if (aAuthService instanceof CBAAuthenticationService ||
                        aAuthService instanceof OAuthClientCredentialService) {
                    sendFailure(aCallback, aAuthContext, aMSE);
                    return;
                }
            } else {
                OMLog.debug(TAG, "No exception raised in background thread");
            }

            AuthenticationService authenticationService = null;
            try {
                authenticationService = getStateTransition().doStateTransition(response, aAuthContext);
            } catch (OMMobileSecurityException e) {
                OMLog.error(TAG + "_onPostExecute", e.getLocalizedMessage(), e);
                aAuthContext.setStatus(OMAuthenticationContext.Status.FAILURE);
                aAuthContext.setException(e);
            }
            OMLog.debug(TAG + "_onPostExecute", "Authentication service is "
                    + (authenticationService != null ? authenticationService.getClass().getName() : ""));
            OMLog.debug(TAG + "_onPostExecute", "Authentication context status is "
                    + (aAuthContext.getStatus() != null ? aAuthContext.getStatus().name() : ""));
            if (status == OMAuthenticationContext.Status.SUCCESS) {
                handleAuthenticationCompleted(aAuthRequest, aAuthContext, aCallback);
                sendSuccess(aCallback, aAuthContext);
            } else if (aAuthContext.getStatus() == OMAuthenticationContext.Status.FAILURE) {
                OMLog.error(TAG, "Authentication Context Status : FAILURE and does require app input? " + aRequireAppInput);
                if (aRequireAppInput) {
                    OMLog.info(TAG, "Avoiding further clean up as we wait for application input in order to proceed");
                    return;
                }
                sendFailureAfterRetry(aCallback, aAuthContext);
            } else if (status == OMAuthenticationContext.Status.IN_PROGRESS || status == OMAuthenticationContext.Status.INITIAL_VALIDATION_DONE
                    || status == OMAuthenticationContext.Status.OAUTH_PRE_AUTHZ_DONE || status == OMAuthenticationContext.Status.OAUTH_DYCR_IN_PROGRESS
                    || status == OMAuthenticationContext.Status.OAUTH_DYCR_DONE || status == OMAuthenticationContext.Status.OAUTH_IDCS_CLIENT_REGISTRATION_DONE
                    || status == OMAuthenticationContext.Status.OPENID_IDCS_CLIENT_REGISTRATION_DONE) {
                if (authenticationService != null) {
                    processAuthRequest(aCallback, aAuthRequest, authenticationService, aAuthContext);
                } else {
                    sendFailure(aCallback, aAuthContext, null);
                }
            } else if (status == OMAuthenticationContext.Status.COLLECT_OFFLINE_CREDENTIALS) {
                aAuthContext.setStatus(OMAuthenticationContext.Status.IN_PROGRESS);
                aAuthContext.getInputParams().put(COLLECT_OFFLINE_CREDENTIAL, true);
                processAuthRequest(aCallback, aAuthRequest, authenticationService, aAuthContext);
            } else {
                OMLog.error(TAG, "status code invalid some thing wrong!!");
            }
        }

        @Override
        protected void onCancelled() {
            OMLog.debug(TAG, "onCancelled: Authentication is cancelled and doInBackground(Object[]) has finished.");
            super.onCancelled();
        }

    }


    /**
     * Constructs the cookie string that can used to store in the cookie manager
     * from the given map of tokens.
     *
     * @param tokens            map of tokens
     * @param decodeCookieValue URL decode the cookie value before setting the same in cookie
     *                          store
     */
    public void storeCookieString(Map<String, OMToken> tokens,
                                  boolean decodeCookieValue) {
        StringBuilder cookieValue;
        SimpleDateFormat sdf = new SimpleDateFormat(COOKIE_EXPIRY_DATE_PATTERN);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
        for (Map.Entry<String, OMToken> entry : tokens.entrySet()) {
            OMToken token = entry.getValue();
            String cookieName = token.getName();
            if (cookieName.equals(OMSecurityConstants.OAUTH_ACCESS_TOKEN)
                    || token.getUrl() == null) {
                continue;
            }
            try {
                cookieValue = new StringBuilder();
                Date expiryDate = token.getExpiryTime();
                if (expiryDate != null) {
                    if (expiryDate.before(new Date())) {
                        /*
                         * This cookie has expired. The only way to mark a
                         * cookie as expired/deleted, is to mention the cookie
                         * value as empty. If the Set-Cookie value which is
                         * passed to CookieManager#setCookie(url, cookie)
                         * contains expires as a date in the past, then the
                         * cookie will be ignored.
                         */
                        token.setExpiryTime(null);
                        token.setValue("");
                    }
                }
                cookieValue.append(cookieName).append("=");
                if (decodeCookieValue) {
                    cookieValue.append(URLDecoder.decode(token.getValue(),
                            "utf8"));
                } else {
                    cookieValue.append(token.getValue());
                }

                URL visitedURL = new URL(token.getUrl());
                String domain = token.getDomain();
                if (domain != null && !visitedURL.getHost().equals(domain)) {
                    // As per RFC 2109, if the domain is not specified
                    // explicitly in Set-Cookie header, then it defaults to
                    // request-host. If the domain is explicitly mentioned to
                    // request-host without a preceding dot, it will create a
                    // cookie with domain explicitly as "."+request-host. So, if
                    // the domain is default domain, then either domain need not
                    // be specified in set-cookie header value as is done here
                    // or it can be mentioned explicitly by pre-pending it with
                    // a dot.
                    cookieValue.append("; domain=").append(token.getDomain());
                }
                if (token.getPath() != null) {
                    cookieValue.append("; path=").append(token.getPath());
                }
                if (token.getExpiryTime() != null) {
                    cookieValue.append("; expires=").append(
                            sdf.format(token.getExpiryTime()));
                }
                if (token.isHttpOnly()) {
                    cookieValue.append("; httpOnly");
                }
                if (token.isSecure()) {
                    cookieValue.append("; secure");
                }
                OMCookieManager.getInstance().setCookie(token.getUrl(), cookieValue.toString());
                OMLog.debug(TAG + "_storeInCookieManager",
                        "The cookie stored in cookie manager is : "
                                + cookieValue.toString());
            } catch (UnsupportedEncodingException e) {
                OMLog.error(TAG + "_constructcookieValue",
                        e.getLocalizedMessage(), e);
            } catch (MalformedURLException e) {
                OMLog.error(TAG + "_constructcookieValue",
                        e.getLocalizedMessage(), e);
            }
        }
    }

    /**
     * ASM impl for handling input received by the handler for each authentication service.
     * Should initialize this for each call to MSS#authenticate()
     *
     */
    class ASMInputControllerImpl implements ASMInputController {
        private final String TAG = ASMInputControllerImpl.class.getSimpleName();
        AuthenticationAsyncTask cAuthTask;
        AuthenticationService cAuthService;
        OMAuthenticationRequest cAuthRequest;
        OMMobileSecurityServiceCallback cCallback;
        OMAuthenticationContext cAuthContext;

        public ASMInputControllerImpl(OMMobileSecurityServiceCallback callback, OMAuthenticationRequest authRequest, AuthenticationService authService, OMAuthenticationContext authContext) {
            cCallback = callback;
            cAuthRequest = authRequest;
            cAuthService = authService;
            cAuthContext = authContext;
        }

        @Override
        public void onInputAvailable(Map<String, Object> input) {
            //we have the required inputs, now lets delegate the authentication task to a back ground task.
            if (shouldCancel()) {
                cAuthTask.cancel(true);
            }
            OMLog.info(TAG, "onInputsAvailable ");
            if (input != null && input.containsKey(OMSecurityConstants.Param.LOGIN_FAILURE_URL_HIT)) {
                OMLog.error(TAG, "Authentication has failed and log in failure url has been hit.");
                sendFailure(cCallback, cAuthContext, new OMMobileSecurityException(OMErrorCode.AUTHENTICATION_FAILED));
                return;
            }
            if (input != null) {
                cAuthContext.getInputParams().putAll(input);
            }
            cAuthTask = new AuthenticationAsyncTask(cCallback, cAuthRequest, cAuthService, cAuthContext);
            cAuthTask.execute();
        }

        @Override
        public void onInputError(OMErrorCode error) {
            OMLog.trace(TAG, "onError : " + error.toString());
            //based on this device whether we need to retry or simply error out.
            cAuthContext.setStatus(OMAuthenticationContext.Status.FAILURE);
            cAuthContext.setException(new OMMobileSecurityException(error));
            sendFailureAfterRetry(cCallback, cAuthContext);
        }

        @Override
        public void onCancel() {
            OMLog.trace(TAG, "onCancel");
            if (shouldCancel()) {
                OMLog.trace(TAG, "cancelling the already running task");
                cAuthTask.cancel(true);
                cAuthTask = null;
            }
            cAuthContext.setStatus(OMAuthenticationContext.Status.CANCELED);
            sendFailure(cCallback, cAuthContext, new OMMobileSecurityException(OMErrorCode.USER_CANCELED_AUTHENTICATION));
        }

        private boolean shouldCancel() {
            return (cAuthTask != null && (cAuthTask.getStatus() == AsyncTask.Status.PENDING || cAuthTask.getStatus() == AsyncTask.Status.RUNNING));
        }
    }


    void handleAuthenticationCompleted(OMAuthenticationRequest authRequest,
                                       OMAuthenticationContext authContext, OMMobileSecurityServiceCallback appCallback) {

        authContext.populateExpiryTime(appCallback);
        /*
         * After offline authentication, the new authContext will not be having
         * any tokens. Hence, obtaining the tokens from previous authContext and
         * updating it in the new one.
         */
        if (authContext.getAuthenticatedMode() == OMAuthenticationContext.AuthenticationMode.OFFLINE) {
            try {
                OMAuthenticationContext previousAuthContext = getMSS()
                        .retrieveAuthenticationContext();
                if (previousAuthContext != null) {
                    if (previousAuthContext.getTokens() != null) {
                        authContext.setTokens(previousAuthContext.getTokens());
                    }
                    if (previousAuthContext.getCookies() != null) {
                        authContext.setCookies(previousAuthContext.getCookies());
                    }
                    /*
                     * Session expiry should be same as the previous one as just
                     * offline authentication is done.
                     */
                    authContext.setSessionExpiry(previousAuthContext
                            .getSessionExpiry());
                    OMLog.debug(TAG,
                            "Corrected session expiry: "
                                    + authContext.getSessionExpiry());
                    authContext.setSessionExpInSecs(previousAuthContext
                            .getSessionExpInSecs());
                }
            } catch (OMMobileSecurityException e) {
                OMLog.error(TAG + "_handleAuthenticationCompleted",
                        "Could not retrieve previous authContext" + e.getMessage());
            }

        }
        //IDCS- Client Registration
        OMAuthenticationContext.AuthenticationProvider provider = authContext.getAuthenticationProvider();
        if ((provider == OMAuthenticationContext.AuthenticationProvider.OPENIDCONNECT10 || provider == OMAuthenticationContext.AuthenticationProvider.OAUTH20)) {

            OMOAuthMobileSecurityConfiguration oAuthConfig = (OMOAuthMobileSecurityConfiguration) mMSS.getMobileSecurityConfig();
            if (oAuthConfig.isClientRegistrationRequired()) {
                OMLog.debug(TAG, "_handleAuthenticationCompleted : client registration with OpenID/OAuth use-case");
                String loginHint;
                if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.OPENIDCONNECT10) {
                    loginHint = authContext.getOpenIDUserInfo().getUsername();
                } else {
                    loginHint = oAuthConfig.getLoginHint();
                }
                IDCSClientRegistrationService clRegService = (IDCSClientRegistrationService) getAuthService(AuthenticationService.Type.CLIENT_REGISTRATION_SERVICE);
                clRegService.storeIDCSClientRegistrationToken(mMSS.getMobileSecurityConfig().getAuthenticationURL().toString(), loginHint,
                        (IDCSClientRegistrationToken) authContext.getTokens().get(OMSecurityConstants.CLIENT_REGISTRATION_TOKEN));
            }
        }


        // update the local map
        setAuthenticationContext(authContext);

        if (mMSS.getMobileSecurityConfig().

                isOfflineAuthenticationAllowed()

                && authContext.getAuthenticatedMode() != OMAuthenticationContext.AuthenticationMode.OFFLINE)

        {
            // delegate the call to offline auth service to store the
            // credentials

            OfflineAuthenticationService offlineService = (OfflineAuthenticationService) getAuthService(AuthenticationService.Type.OFFLINE_SERVICE);
            offlineService.handleAuthenticationCompleted(authRequest,
                    authContext);
        }

        /*
         * Has to store the auth context into the credential store if
         * AuthContextPersistence is allowed.
         */
        String credentialKey = authContext.getStorageKey() != null ?
                authContext.getStorageKey() : getAppCredentialKey();

        String authContextString = authContext.toString(true);
        if (mMSS.getMobileSecurityConfig().isAuthContextPersistenceAllowed()) {
            mMSS.getCredentialStoreService().addAuthContext(credentialKey,
                    authContextString);

            OMLog.debug(TAG, "Authentication context for the key " + credentialKey
                    + " stored in the credential store is  : ");

        } else {
            OMLog.debug(TAG, "Authentication context for the key "
                    + credentialKey
                    + " is not stored in the credential store as this is a secure mode. AuthContext in-memory : ");

        }
        if (authContextString != null && OMSecurityConstants.DEBUG) {
            try {
                LogUtils.log("AuthContext: " +
                        new JSONObject(authContextString).toString(3));
            } catch (JSONException e) {
                OMLog.error(TAG, e.getMessage(), e);
            }
        }

        // RC
        // store the values in store only if the RC feature is enabled and if
        // its a fresh authentication other wise if authentication is valid and
        // SDK returns, the remember credentials flags will be over ridden by
        // default values.
        //TODO add alreadyAuthenticated flag as done in old SDK.
        if (getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
            getRCUtility().storeRememberCredentialsToStore(
                    authContext);
        }
        // RC

    }

    /**
     * This method is used internally by the BasicAuthenticationService to reset
     * the failure count when the session is expired.
     */
    void resetFailureCount(OMAuthenticationContext authContext) {
        OMCredentialStore credService = getMSS().getCredentialStoreService();
        credService.deleteRetryCount(getOfflineCredentialKey(authContext));
    }

    int getFailureCount(OMAuthenticationContext authContext) {
        int failureCount;
        OMCredentialStore credService = getMSS().getCredentialStoreService();
        failureCount = credService.getRetryCount(getOfflineCredentialKey(authContext));
        return failureCount;
    }

    void setAuthenticationContext(OMAuthenticationContext authContext) {
        this.mAuthContext = authContext;
        setTemporaryAuthenticationContext(authContext);
        if (authContext == null) {
            OMLog.debug(TAG + "_setAuthenticationContext",
                    "Cleared in-memory authContext");
        } else {
            OMLog.debug(TAG + "_setAuthenticationContext",
                    "Updated in-memory authContext");
        }
    }

    public OMAuthenticationContext getAuthenticationContext() {
        return mAuthContext;
    }

    public void setTemporaryAuthenticationContext(OMAuthenticationContext temporaryAuthContext) {
        this.mTemporaryAuthContext = temporaryAuthContext;
    }

    public OMAuthenticationContext getTemporaryAuthenticationContext() {
        return mTemporaryAuthContext;
    }

    /**
     * Can be called by the client application to find out whether there is a
     * valid authentication context already available in the credential store
     *
     * @return {@link OMAuthenticationContext} instance
     */
    public OMAuthenticationContext retrieveAuthenticationContext() {
        String storageKey;
        if (mAuthContext != null) {
            storageKey = mAuthContext.getStorageKey() != null ? mAuthContext
                    .getStorageKey() : getAppCredentialKey();
        } else {
            storageKey = getMSS()
                    .getMobileSecurityConfig().getAuthenticationKey();
        }
        if (storageKey == null) {
            storageKey = getAppCredentialKey();
        }
        return retrieveAuthenticationContext(storageKey);
    }

    /**
     * Can be called by the client application to find out whether there is a
     * valid authentication context already available in the credential store
     *
     * @param storageKey key against which the authentication context is stored.
     * @return {@link OMAuthenticationContext} instance
     */
    OMAuthenticationContext retrieveAuthenticationContext(String storageKey) {
        if (storageKey == null) {
            storageKey = getAppCredentialKey();
        }
        if (mAuthContext != null) {
            String authCredKey = mAuthContext.getStorageKey() != null ? mAuthContext
                    .getStorageKey() : getAppCredentialKey();
            if (authCredKey != null && !authCredKey.equals(storageKey)) {
                setAuthenticationContext(null);
            }
        }

        // Now try to fetch from the credential store
        if (mAuthContext == null) {
            String authContextString = getMSS().getCredentialStoreService()
                    .getAuthContext(storageKey);

            if (OMSecurityConstants.DEBUG
                    && !TextUtils.isEmpty(authContextString)) {
                OMLog.trace(TAG,
                        " Authentication context for the key " + storageKey
                                + " retrieved from the credential store is  : ");
                try {
                    LogUtils.log(new JSONObject(authContextString).toString(3));
                } catch (JSONException e) {
                    OMLog.error(TAG, e.getMessage(), e);
                }
            }

            if (authContextString != null) {
                OMAuthenticationContext authContext = new OMAuthenticationContext(this,
                        authContextString, storageKey);
                setAuthenticationContext(authContext);
                mAuthContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
            }
        } else {
            OMLog.debug(TAG,
                    " Authentication context is present in in-memory");
        }

        return mAuthContext;
    }

    private void resetRedirectionPreferences() {
        OMLog.info(TAG, "Resetting the redirection preferences");
        getMSS().refreshConnectionHandler(OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTP_TO_HTTPS_REDIRECT, true);
        getMSS().refreshConnectionHandler(OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTPS_TO_HTTP_REDIRECT, false);
    }

    private void sendSuccess(OMMobileSecurityServiceCallback callback,
                             OMAuthenticationContext authContext) {
        resetRedirectionPreferences();//redirect preferences are only valid for that network request for security.
        authContext.clearFields();
        setAuthenticationContext(authContext);
        callback.onAuthenticationCompleted(getMSS(), authContext, null);
//        setAuthenticationCallback(null);
        // resetting the failure count to 0 since it is successful
        // authentication
        resetFailureCount(authContext);
    }


    public void sendFailure(OMMobileSecurityServiceCallback callback,
                            OMAuthenticationContext authContext, OMMobileSecurityException exception) {
        // failure attempt is already reached.
        //  setAuthenticationCallback(null);

        if (exception == null) {
            exception = new OMMobileSecurityException(
                    OMErrorCode.AUTHENTICATION_FAILED);
        }

        if (authContext == null) {
            authContext = new OMAuthenticationContext(OMAuthenticationContext.Status.FAILURE);
            authContext.setException(exception);
        } else {
            authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
            authContext.deleteAuthContext(true, true, true, false);
            authContext.setException(exception);
            authContext.clearAllFields();
        }
        // RC
        if (getMSS().getMobileSecurityConfig().isAnyRCFeatureEnabled()) {
            //in case of auth failure lets remove password and set the auto login to false, to avoid looping.
            getRCUtility().inValidateRememberedCredentials();
            getRCUtility().setAutoLoginUIPrefToStore(false);
        }
        // RC
        if (authContext.getMobileException().getError() == OMErrorCode.MAX_RETRIES_REACHED) {
            resetFailureCount(authContext);
        }
        OMLog.error(TAG, "sendFailure -> errorCode : " + exception.getError().getErrorCode() + " errorMessage: " + exception.getErrorMessage());
        callback.onAuthenticationCompleted(getMSS(), null, exception);
    }

    private void sendFailureAfterRetry(OMMobileSecurityServiceCallback callback, OMAuthenticationContext authContext) {
        updateFailureCount(authContext);
        int failureCount = getFailureCount(authContext);
        OMMobileSecurityException exception = authContext.getMobileException();
        OMLog.debug(TAG, "[sendFailureAfterRetry] Failure count is " + failureCount);
        boolean isErrorRecoverable = false;

        // throw authentication challenge in recoverable error scenarios
        //TODO add recoverable error scenarios
        if (exception != null) {
            if ((failureCount < mMSS.getMobileSecurityConfig().getMaxFailureAttempts())) {
                if (isInvalidCredentialErrorMessage(exception.getErrorMessage().toLowerCase())) {
                    isErrorRecoverable = true;
                } else {
                    for (OMErrorCode code : OMErrorCode.getRecoverableErrorCodes()) {
                        if (code != exception.getError()) {
                            continue;
                        }
                        isErrorRecoverable = true;
                    }
                }
                if (isErrorRecoverable) {
                    OMExceptionEvent exceptionEvent = exception.getExceptionEvent();
                    if (exceptionEvent != null && exceptionEvent instanceof InvalidCredentialEvent) {
                        ((InvalidCredentialEvent) exceptionEvent).setRetryCount(failureCount);
                    }
                    authContext.getInputParams().put(MOBILE_SECURITY_EXCEPTION, exception);
                    AuthenticationService authService = null;
                    try {
                        authService = getStateTransition().getInitialState(authContext.getAuthRequest());
                    } catch (OMMobileSecurityException e) {

                        OMLog.error(TAG, e.getMessage());
                        mMSS.getCallback().onAuthenticationCompleted(mMSS, null, e);
                    }
                    processAuthRequest(callback, authContext.getAuthRequest(), authService, authContext);
                    return;
                }
            } else {
                //maximum retries have reached
                exception = new OMMobileSecurityException(OMErrorCode.MAX_RETRIES_REACHED);
            }
        }
        //send control back to application as either one of the following is true:
        //1.exception from lower layers is null -> AUTHENTICATION_FAILED is returned.
        //2.exception error is not recoverable -> in this case same exception is returned to app.
        //3.user exhausted its retry counts -> in this case MAX_RETIRES is returned.
        sendFailure(callback, authContext, exception);
    }

    String getAppCredentialKey() {
        String applicationId = getMSS().getMobileSecurityConfig().getApplicationId();
        return applicationId;
    }

    /**
     * @param oAuthConnUtil
     * @hide
     */
    public void setOAuthConnUtil(OAuthConnectionsUtil oAuthConnUtil) {
        this.mOAuthConnectionsUtil = oAuthConnUtil;
    }

    public void cancel() {
        OMLog.trace(TAG, "cancel");
        AuthenticationService authService = null;
        do {
            authService = getStateTransition().getCancelState(authService);
            if (authService != null)
                authService.cancel();
        }
        while (authService != null);
    }

    private void updateFailureCount(OMAuthenticationContext authContext) {
        int failureCount;
        OMMobileSecurityException mse = authContext.getMobileException();
        String errorCode = mse.getErrorCode();
        if (mse != null && ((errorCode.equals(OMErrorCode.UN_PWD_INVALID.getErrorCode()))
                || (Arrays.asList(OMErrorCode.getOAuthKnownErrorCodes()).contains(mse.getError())
                && isInvalidCredentialErrorMessage(mse.getErrorMessage().toLowerCase())))) {
            failureCount = getFailureCount(authContext);
            ++failureCount;
            OMCredentialStore credService = getMSS().getCredentialStoreService();
            credService.addRetryCount(getOfflineCredentialKey(authContext), failureCount);
        }
    }

    private String getOfflineCredentialKey(OMAuthenticationContext authContext) {
        String credentialKey = authContext.getStorageKey();
        String authenticationUrl = getMSS().getMobileSecurityConfig().getAuthenticationURL().toString();

        return OfflineAuthenticationService.createServerSpecificKey(authenticationUrl, credentialKey, authContext.getIdentityDomain(),
                authContext.getUserName());
    }

    /*
       Method to check if the message contains invalid credentials error
     */
    private boolean isInvalidCredentialErrorMessage(String message) {
        boolean isInvalidCredentialErrorMessage = false;
        if (message.contains("password")) {
            isInvalidCredentialErrorMessage = true;
        }
        return isInvalidCredentialErrorMessage;
    }

    /**
     * This method returns the client assertion associated with the current
     * authentication session.
     *
     * @return
     */
    OAuthMSToken retrieveClientAssertion() {
        if (mClientAssertion == null) {

            try {
                mClientAssertion = getClientAssertionFromStore();
            } catch (JSONException e) {
                OMLog.error(TAG + "_retrieveClientAssertion", e.getLocalizedMessage(), e);
            }
        }
        return mClientAssertion;
    }

    /**
     * This method should only be called to set a new client assertion.
     *
     * @param clientAssertionToken
     */
    void setClientAssertion(OAuthMSToken clientAssertionToken) {
        mClientAssertion = clientAssertionToken;
        putClientAssertionToStore(clientAssertionToken);
    }

    /**
     * This method removes the client assertion of the current authentication
     * session. To be called from the authentication service for logout(true)
     * cases.
     */
    void removeClientAssertion() {
        getMSS().getCredentialStoreService().remove(
                getKeyForClientAssertion());
        mClientAssertion = null;
    }

    private OAuthMSToken getClientAssertionFromStore() throws JSONException {
        String key = getKeyForClientAssertion();
        String clientAssertionFromStore = getMSS().getCredentialStoreService().getString(key);
        if (clientAssertionFromStore != null) {
            OMLog.debug(TAG, "client assertion retrieved from store!");
            return new OAuthMSToken(clientAssertionFromStore);
        }
        return null;
    }

    private String getKeyForClientAssertion() {
        OMOAuthMobileSecurityConfiguration oAuthConfig = (OMOAuthMobileSecurityConfiguration) getMSS()
                .getMobileSecurityConfig();
        return oAuthConfig.getAuthenticationURL().toString() + "_"
                + oAuthConfig.getOAuthClientID() + "_"
                + OMSecurityConstants.OAUTH_MS_CLIENT_ASSERTION_SUFFIX;
    }

    private void putClientAssertionToStore(OAuthMSToken clientAssertionToken) {
        String key = getKeyForClientAssertion();
        getMSS().getCredentialStoreService().putString(key,
                clientAssertionToken.toString());
        OMLog.debug(TAG, "client assertion added to store!");
    }
}
