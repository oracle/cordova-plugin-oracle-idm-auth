/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.net.Uri;
import android.text.TextUtils;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMMobileSecurityService;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPRequest;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.auth.OMAuthenticationContext.AuthenticationMode;

/**
 * Base class for authentication service for each grant type in OAuth2.0
 *
 */
abstract class OAuthAuthenticationService extends AuthenticationService {
    private static String TAG = OAuthAuthenticationService.class.getSimpleName();
    private static final String BASIC_AUTH_HEADER = "Basic ";
    private WeakHashMap<String, Object> mParamMap;
    protected OMMobileSecurityException logoutException;
    protected OMOAuthMobileSecurityConfiguration mConfig;
    protected boolean enableReqResVerbose = false;// should be false in production code
    private String mIdentityClaims;

    OAuthAuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler handler) {
        super(asm, handler);
        mConfig = (OMOAuthMobileSecurityConfiguration) asm.getMSS().getMobileSecurityConfig();
    }

    OAuthAuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler loginHandler, OMLogoutCompletionHandler logoutHandler) {
        super(asm, loginHandler, logoutHandler);
        mConfig = (OMOAuthMobileSecurityConfiguration) asm.getMSS().getMobileSecurityConfig();
    }

    @Override
    public void cancel() {
        //should be common for all grant types
    }


    boolean isValidInternalAccessToken(OMAuthenticationContext authContext, boolean validateOnline) {
        String TAG = OAuthAuthenticationService.TAG + "_isValidInternalAT";
        // In OAuth we are not using this boolean as of now, but in future if we
        // have a validate end-point we can use the same.
        boolean result = false;
        // holds true for OAuth20/OpenID Online and Offline authentication
        AuthenticationMode authMode = authContext.getAuthenticatedMode();

        if (authMode == AuthenticationMode.OFFLINE) {
            return isIdleTimeout(authContext);
        } else if (authMode == AuthenticationMode.ONLINE) {
            // no tokens, return false.
            if (authContext.getOAuthTokenList().isEmpty()) {
                return false;
            }
        }

        // common for both offline and online, as we are retaining the access
        // tokens after offline authentication is done.
        // check if the AccessToken is expired ?
        for (OMToken token : authContext.getOAuthTokenList()) {
            // if we have any access token which is valid then return true
            if (isAccessToken(token) && !token.isTokenExpired()) {
                result = true;
                break;
            }
        }
        OMLog.debug(TAG, "Authenticated Mode: " + authMode + ", isValid : "
                + result);
        return result;
    }

    void clearOAuthTokens(OMAuthenticationContext authContext, boolean isLogoutCall) {
        List<OAuthToken> tokensToDelete = new ArrayList<OAuthToken>();

        if (mASM.getMSS().getMobileSecurityConfig()
                .isOfflineAuthenticationAllowed()
                && !isLogoutCall) {
            for (OAuthToken token : authContext.getOAuthTokenList()) {
                if (!token.hasRefreshToken()) {
                    tokensToDelete.add(token);
                }
            }

            OMLog.debug(TAG,
                    "Since Offline authentication is allowed retaining "
                            + (authContext.getOAuthTokenList().size() - tokensToDelete
                            .size())
                            + " access token(s), having a refresh token.");
        } else {
            tokensToDelete.addAll(authContext.getOAuthTokenList());
        }
        OMLog.debug(TAG, "Cleared " + tokensToDelete.size()
                + " OAuth access token(s)!");
        authContext.getOAuthTokenList().removeAll(tokensToDelete);
        authContext.getTokens().clear();
    }

    private OMAuthenticationChallenge getLogoutChallenge() {
        OMAuthenticationChallenge challenge;

        if (mConfig.getOAuthBrowserMode() == OMMobileSecurityConfiguration.BrowserMode.EMBEDDED) {
            challenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.EMBEDDED_WEBVIEW_REQUIRED);

        } else {
            challenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.EXTERNAL_BROWSER_INVOCATION_REQUIRED);
            challenge.addChallengeField(OMSecurityConstants.Challenge.EXTERNAL_BROWSER_LOAD_URL,
                    mASM.getOAuthConnectionsUtil().getLogoutUrl(mASM.getAuthenticationContext()));
        }
        return challenge;
    }

    @Override
    public void collectLogoutChallengeInput(Map<String, Object> inputParams, AuthServiceInputCallback callback) {
        OMLog.debug(TAG, "CollectionLogoutChallengeInput - if application wants to invoke the logout URL");
        mLogoutCompletionHandler.createLogoutChallengeRequest(mASM.getMSS(), getLogoutChallenge(), callback);
    }

    @Override
    public void handleLogout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
    }

    /**
     * Internal API which returns an empty param map to be used by all the OAuth
     * Authentication services.
     *
     * @return
     */
    protected WeakHashMap<String, Object> getEmptyParamHashMap() {
        if (mParamMap == null) {
            mParamMap = new WeakHashMap<String, Object>();
        }
        mParamMap.clear();
        return mParamMap;
    }

    /**
     * Given an input param map which contains error/error description, this api
     * processes the map and returns a {@link OMMobileSecurityException} based
     * on the error present.
     *
     * @param params
     * @return
     */
    protected OMMobileSecurityException onError(Map<String, Object> params) {
        Object errorObj = params.get(OAuthConnectionsUtil.OAuthResponseParameters.ERROR.getValue());
        Object errorDescriptionObj = params
                .get(OAuthConnectionsUtil.OAuthResponseParameters.ERROR_DESCRIPTION.getValue());
        //log server response
        OMLog.error(TAG, "Error Response from Server -> error: " + errorObj + " error_description: " + errorDescriptionObj);
        String errorDescription = null;
        if (errorObj != null) {
            String error = (String) errorObj;
            // OMErrorCode omErrorCode = null;
            OMErrorCode omErrorCode = null;
            String undefined = "undefined";
            StringBuilder errorSB = new StringBuilder();

            for (OMErrorCode knownError : OMErrorCode.getOAuthKnownErrorCodes()) {
                if (error.equals(knownError.getErrorString())) {
                    omErrorCode = knownError;
                    if (errorDescriptionObj == null) {
                        errorDescription = knownError.getErrorDescription();
                    } else {
                        errorDescription = (String) errorDescriptionObj;
                    }
                    break;
                }
            }
            if (errorDescription != null) {
                errorSB.append(errorDescription);
            } else {
                errorSB.append(undefined);
            }
            return new OMMobileSecurityException(omErrorCode, errorDescription);
        }
        return null;
    }

    /**
     * Given a pay-load and configuration, this method creates a back channel
     * request to fetch the token and returns the response from the server. Any
     * error during this process will be reported by throwing the
     * {@link OMMobileSecurityException}.
     *
     * @param payload
     * @param oAuthConfig
     * @param identityDomain
     * @return
     * @throws OMMobileSecurityException
     */
    protected String getToken(String payload,
                              OMOAuthMobileSecurityConfiguration oAuthConfig,
                              String identityDomain) throws OMMobileSecurityException {

        HashMap<String, String> headers = new HashMap<String, String>();

        // this internally will send the client auth header if the client is
        // confidential or the app explicitly specified this using
        // initialization property.
        if (oAuthConfig.isConfidentialClient()
                || oAuthConfig.includeClientAuthHeader()) {
            OMLog.debug(TAG, "Client Auth Header Added!");
            try {
                headers.put(OMSecurityConstants.OAUTH_AUTHORIZATION_HEADER,
                        BASIC_AUTH_HEADER
                                + mASM.getOAuthConnectionsUtil().getClientAuthHeader());
            } catch (UnsupportedEncodingException e) {
                OMLog.error(TAG, e.getMessage(), e);
            }
        }

        if (oAuthConfig.sendIdentityDomainInHeader()
                && !TextUtils.isEmpty(identityDomain)) {
            // add domain name header if specified by app.
            headers.put(oAuthConfig.getIdentityDomainHeaderName(),
                    identityDomain);
            OMLog.debug(TAG,
                    "Identity Domain header "
                            + oAuthConfig.getIdentityDomainHeaderName() + " : "
                            + identityDomain + " set!");

        }

        if (!oAuthConfig.getCustomAuthHeaders().isEmpty()) {
            headers.putAll(oAuthConfig.getCustomAuthHeaders());
            OMLog.debug(TAG, "Custom Auth headers added!");
        }

        OMHTTPResponse response = mASM.getMSS().getConnectionHandler().httpPost(
                oAuthConfig.getOAuthTokenEndpoint(), headers, payload,
                OMSecurityConstants.ConnectionConstants.OAUTH20_CONTENT_TYPE.getValue(), (OMHTTPRequest.REQUIRE_RESPONSE_CODE | OMHTTPRequest.REQUIRE_RESPONSE_STRING));
        if (response != null && response.getResponseCode() == HttpURLConnection.HTTP_OK) {
            return response.getResponseStringOnSuccess();
        } else {
            try {
                if (response != null) {
                    OMLog.error(TAG, "Error getting the token response : " + response.getResponseStringOnFailure());
                    parseJsonForOAuthError(new JSONObject(response.getResponseStringOnFailure()));
                }
            } catch (JSONException e) {
                OMLog.error(TAG, "Error while parsing OAuth error string", e);
                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
            }
        }
        return null;
    }

    // if its an OAuth2.0 error then report the same.
    private void parseJsonForOAuthError(JSONObject errorObj)
            throws OMMobileSecurityException {
        String error = errorObj.optString(OAuthConnectionsUtil.OAuthResponseParameters.ERROR.getValue());
        String errorDescription = errorObj.optString(OAuthConnectionsUtil.OAuthResponseParameters.ERROR_DESCRIPTION.getValue());
        OMErrorCode errorCode = null;
        String undefined = "undefined";
        StringBuilder errorSB = new StringBuilder();
        if (error != null) {
            for (OMErrorCode knownError : OMErrorCode.getOAuthKnownErrorCodes()) {
                if (knownError.getErrorString()
                        .equalsIgnoreCase(error)) {
                    errorCode = knownError;
                    if (TextUtils.isEmpty(errorDescription)) {
                        // Usually happens with google , it does not send
                        // error_description
                        errorDescription = knownError.getErrorDescription();
                    }
                    if (errorDescription != null) {
                        errorSB.append(errorDescription);
                    }
                    // very unlikely this case will arise.
                    else {
                        errorSB.append(undefined);
                    }
                    break;
                }
            }
            if (errorCode != null) {
                // This is an OAuth known error so lets report this.
                throw new OMMobileSecurityException(errorCode, errorSB.toString());
            } else if (!TextUtils.isEmpty(error)) {
                /*
                 * for MS OAuth for now this is a known error. Will add other
                 * errors when encountered.
                 */
                if (("IDAAS-62001").equals(error)) {

                    throw new OMMobileSecurityException(
                            OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
                }
            }
            //not an oAuth related error,
        } else {
            //throw it any ways
            throw new OMMobileSecurityException(OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
        }
    }

    /**
     * Given a token response this method will create an access token
     * (OAuthToken) and returns the same. This returns null if the operation
     * fails.
     *
     * @param tokenString
     * @return
     * @throws JSONException
     */
    protected OAuthToken onAccessToken(String tokenString) throws JSONException {
        OAuthToken accessToken = null;
        try {
            accessToken = new OAuthToken(tokenString);
        } catch (JSONException e) {
            OMLog.error(TAG, "Error while parsing the access token : " + tokenString);
            throw e;
        }

        Set<String> scopeSetForToken;
        Set<String> scopesFromConfig = mASM.getOAuthConnectionsUtil().getOAuthScopes();
        if (scopesFromConfig == null || scopesFromConfig.size() == 0) {
            // if no scopes are given in the config then add default scope
            // to this token.
            scopeSetForToken = mASM.getOAuthConnectionsUtil().getDefaultOAuthScope();
        } else {
            // add all the scopes passed in the config to this token object.
            scopeSetForToken = new HashSet<String>();
            scopeSetForToken.addAll(scopesFromConfig);
        }
        accessToken.setName(OMSecurityConstants.OAUTH_ACCESS_TOKEN);
        accessToken.setScopes(scopeSetForToken);
        OMLog.debug(TAG, "onAccessToken");
        return accessToken;
    }

    /**
     * Internal API which handles the authentication completion after fetching
     * an access token.
     *
     * @param authContext
     * @param accessToken
     * @throws OMMobileSecurityException
     */
    protected void onAuthSuccess(OMAuthenticationContext authContext,
                                 OAuthToken accessToken, OMAuthenticationContext.AuthenticationProvider provider) throws OMMobileSecurityException {
        OMLog.debug(TAG, "onAuthSuccess!");
        ArrayList<OAuthToken> newTokenList = new ArrayList<OAuthToken>();
        newTokenList.add(accessToken);
        // adding any auxiliary tokens generated during the auth process to
        // the token list.
        for (Map.Entry<String, OMToken> token : authContext.getTokens().entrySet()) {

            if (token.getValue() instanceof OAuthToken) {
                newTokenList.add((OAuthToken) token.getValue());
                OMLog.debug(TAG, "Added auxiliary token : " + token.getKey()
                        + " to the token list!");
            }
        }

        // if we have access tokens from previous context add them to
        // the
        // newly created context .
        OMAuthenticationContext prevContext;
        prevContext = mASM.getMSS().retrieveAuthenticationContext();
        if (prevContext != null) {
            ArrayList<OAuthToken> prevTokenList = (ArrayList<OAuthToken>) prevContext
                    .getOAuthTokenList();

            for (OAuthToken token : prevTokenList) {
                if (token != null
                        && OMSecurityConstants.OAUTH_ACCESS_TOKEN.equals(token
                        .getName())) {
                    newTokenList.add(token);
                    OMLog.debug(TAG,
                            "Added access token from prev context to the token list!");
                }
            }
        }
        authContext.setAuthenticationProvider(provider);
        authContext.setOAuthTokenList(newTokenList);
        authContext.setStatus(OMAuthenticationContext.Status.SUCCESS);
        OMLog.debug(TAG, "Done!");
    }

    private boolean isIdleTimeout(OMAuthenticationContext authContext) {
        Date idleTimeExpiry = authContext.getIdleTimeExpiry();
        Date currentTime = Calendar.getInstance().getTime();

        /*
         * Non-zero checks for getSessionExpInSecs() and getIdleTimeExpInSecs()
         * added to ignore session/idle time expiry if session/idle timeout
         * value is 0.
         */
        if (idleTimeExpiry == null || authContext.getIdleTimeExpInSecs() == 0) {
            return true;
        } else if (idleTimeExpiry != null
                && (currentTime.after(idleTimeExpiry) || currentTime
                .equals(idleTimeExpiry))) {
            OMLog.debug(TAG + "_isValid", "Idle time is expired.");
            return false;
        } else {
            authContext.resetIdleTime();
            OMLog.debug(TAG + "_isValid",
                    "Idle time is reset to : "
                            + authContext.getIdleTimeExpiry());
            return true;
        }
    }

    /**
     * Internal API which returns true if the token is an OAuth access token.
     *
     * @param token
     * @return
     */
    protected boolean isAccessToken(OMToken token) {
        return (OMSecurityConstants.OAUTH_ACCESS_TOKEN).equals(token.getName());
    }

    /*
 * Internal API which will check the validity of the oAuth tokens if the
 * token which matches the request scopes is expired , we will refresh if
 * the refreshExpiredToken boolean is true
 */
    // common for All OAuth Authentication Services.
    boolean isValid(OMAuthenticationContext authContext,
                    Set<String> requiredScopes, boolean refreshExpiredToken)
            throws OMMobileSecurityException {
        OMLog.debug(TAG, "isValid(scopes)");

        OMAuthenticationContext.AuthenticationProvider provider = authContext.getAuthenticationProvider();
        if (provider == OMAuthenticationContext.AuthenticationProvider.OPENIDCONNECT10 || provider == OMAuthenticationContext.AuthenticationProvider.OAUTH20) {
            boolean result = false;
            boolean triedRefreshing = false, isExpired = false;
            int initialSize = authContext.getOAuthTokenList().size();
        /*
         * all the access tokens matching the passed scopes
         */
            List<OAuthToken> accessTokens = new ArrayList<>();

        /*
         * defensive copy of tokens from the authentication context to work
         * with.
         */
            List<OAuthToken> oauthTokens = new ArrayList<>(
                    authContext.getOAuthTokenList());
            AuthenticationMode authMode = authContext.getAuthenticatedMode();
            OMLog.debug(TAG, "authenticated mode: " + authMode);
            if (authContext.getOAuthTokenList().isEmpty()
                    && (authMode == AuthenticationMode.ONLINE)) {
                return false;
            }
            // common for both Remote and Offline.
            Iterator<OAuthToken> itr = oauthTokens.iterator();
            while (itr.hasNext()) {
                OAuthToken token = itr.next();
                if (isAccessToken(token)) {
                    // do this only for access tokens.
                    if (requiredScopes != null && requiredScopes.size() > 0) {
                        if (token.getScopes().size() > 0) {
                            if (token.getScopes().containsAll(requiredScopes)) {
                                accessTokens.add(token);
                                // removing these tokens from context for now
                                itr.remove();
                            }
                        }
                    } else {
                        // just add all the tokens if no scopes are passed.
                        accessTokens.add(token);
                        // remove this token from the context.
                        itr.remove();
                    }
                }
            }
            if (accessTokens.isEmpty()) {
                OMLog.debug(TAG, "No Valid access tokens, so return false");
                // no access tokens.
                return false;
            }
            // now sort this list based on the scopes so.We basically pick the first
            // token from the matching tokens list (based on the scopes) which is
            // expired
            if (accessTokens.size() > 1)
                Collections.sort(accessTokens, new OAuthTokenComparator());
            Iterator<OAuthToken> tokenitr = accessTokens.iterator();
            OAuthToken refreshedToken = null;
            while (tokenitr.hasNext()) {
                OAuthToken oAuthToken = tokenitr.next();
                if (!isAccessToken(oAuthToken))
                    continue;
                if (oAuthToken.isTokenExpired()) {
                    OMLog.debug(TAG, "Access Token is expired!");
                    if (!TextUtils.isEmpty(oAuthToken.getRefreshTokenValue())) {
                        if (refreshExpiredToken) {
                            String refreshTokenResponse;
                            String oldRefreshTokenValue = oAuthToken
                                    .getRefreshTokenValue();
                            WeakHashMap<String, Object> params = new WeakHashMap<String, Object>();
                            params.put(
                                    OMSecurityConstants.Param.OAUTH_REFRESH_TOKEN_VALUE,
                                    oldRefreshTokenValue);
                            triedRefreshing = true;
                            try {
                                refreshTokenResponse = getToken(
                                        mASM.getOAuthConnectionsUtil()
                                                .getBackChannelRequestForRefreshingAccessToken(
                                                        params),
                                        (OMOAuthMobileSecurityConfiguration) mASM.getMSS()
                                                .getMobileSecurityConfig(),
                                        authContext.getIdentityDomain());
                                if (refreshTokenResponse != null) {
                                    refreshedToken = onAccessToken(refreshTokenResponse);
                                    if (refreshedToken != null) {
                                        refreshedToken.setScopes(oAuthToken
                                                .getScopes());
                                        // if new token has no refresh value , then use the old refresh token value.
                                        if (refreshedToken.getRefreshTokenValue() == null) {
                                            refreshedToken
                                                    .setRefreshTokenValue(oldRefreshTokenValue);
                                        }
                                        // removing if we have refreshed this token
                                        // .
                                        tokenitr.remove();
                                        result = true;
                                        break;
                                    }
                                } else {
                                    // try other token object
                                    continue;
                                }

                            } catch (UnsupportedEncodingException e) {
                                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR); //TODO check error code
                            } catch (JSONException e) {
                                throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR); //TODO
                            }
                        } else {
                            result = false;
                            break;
                        }
                    } else {
                        OMLog.debug(TAG, "No refresh token available for the expired access token!");
                        // check for other matching the criteria
                        continue;
                    }
                } else {
                    OMLog.debug(TAG, "Access Token not expired!");

                    // the token is not expired so isValid should return true.
                    // no further checking required.
                    result = true;
                    break;
                }
            }
            if (triedRefreshing && refreshedToken != null) {
                OMLog.debug(TAG, "Refreshed the expired access token!");
                accessTokens.add(refreshedToken);
                if (authContext.getAuthenticatedMode() == AuthenticationMode.OFFLINE) {
                    OMLog.debug(TAG, "Changed the authenticate mode from LOCAL to REMOTE, since the expired access token was refreshed.");
                    // MCS offline OAuth Requirement.
                    authContext.setAuthenticatedMode(AuthenticationMode.ONLINE);
                }
            } else {
                if (isExpired) {
                    OMLog.debug(TAG, "No access token refreshed!");
                    result = false;
                }
            }
            oauthTokens.addAll(accessTokens);
            authContext.setOAuthTokenList(oauthTokens);
            int finalSize = authContext.getOAuthTokenList().size();
            if (initialSize != finalSize) {
                // not likely
                OMLog.error(TAG, "This is Odd - token difference in the iterators:"
                        + (initialSize - finalSize)
                        + ". This seems to be a code issue.");
            }

            OMLog.debug(TAG, "" + result);
            return result;
        } else {
            OMLog.debug(TAG, "Not an openID or OAuth config returning true!");
            return true;
        }
    }

    /**
     * This will validate the redirect response from the user agent(external and
     * embedded), this is common for all the OAuthAuthenticationService
     * involving a browser.
     *
     * @throws OMMobileSecurityException
     */
    protected void validateAndUpdateInputParams(
            final HashMap<String, Object> inputParams)
            throws OMMobileSecurityException {
        if (inputParams == null
                || inputParams.isEmpty()
                || !inputParams
                .containsKey(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY)) {
            // Validate input params
            throw new OMMobileSecurityException(
                    OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
        }
        Object redirectResponse = inputParams
                .get(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY);
        Uri redirectResponseUri = null;
        if (redirectResponse instanceof String) {
            redirectResponseUri = Uri.parse((String) redirectResponse);
        } else if (redirectResponse instanceof Uri) {
            redirectResponseUri = (Uri) redirectResponse;
        }

        if (redirectResponseUri != null) {
            String fragment = redirectResponseUri.getEncodedFragment();
            String query = redirectResponseUri.getEncodedQuery();
            try {
                // FIXME
                // Not a good way to get the access token or error objects in
                // the implicit type.
                // Implicit is not supported in the OAM OAuth so not at the
                // priority
                // now.
                if (query != null) {
                    JSONObject queryJSON;
                    queryJSON = parseRedirectResponseUri(inputParams,
                            redirectResponseUri);
                    inputParams.put(OMSecurityConstants.Param.OAUTH_FRONT_CHANNEL_RESPONSE_JSON, queryJSON);

                } else if (fragment != null) {
                    JSONObject fragJSON = parseFragmentString(inputParams,
                            fragment);
                    inputParams.put(OMSecurityConstants.Param.OAUTH_FRONT_CHANNEL_RESPONSE_JSON, fragJSON);
                }

            } catch (JSONException e) {
                OMLog.error(TAG, "Error while processing JSON response " + e.getMessage());
                throw new OMMobileSecurityException(OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
            }
        } else {
            OMLog.error(TAG, "Unable to retrieve redirect response ");
            throw new OMMobileSecurityException(OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
        }
        String stateFromResponse = (String) inputParams
                .get(OAuthConnectionsUtil.OAuthResponseParameters.STATE.getValue());
        // to prevent Cross-Site Request Forgery attack.
        // throw exception when the state parameter is not present in the
        // Response as SDK always sends the same in front channel request
        if (stateFromResponse == null
                || !stateFromResponse.equals(mASM.getOAuthConnectionsUtil()
                .getOAuthState())) {
            OMLog.error(TAG, "Invalid state recovered from the response.");
            throw new OMMobileSecurityException(
                    OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
        }

    }

    /**
     * populates the params with the response values retrieved from the URI
     * fragment.It also returns the result as a JSONObject.
     *
     * @param params
     * @param fragmentString
     * @throws JSONException
     */
    protected JSONObject parseFragmentString(Map<String, Object> params,
                                             String fragmentString) throws JSONException {
        JSONObject jsonObject = new JSONObject();
        // to store various parameters passed in a fragment
        String[] nameValuePairs = fragmentString.split("&");
        for (String nameValue : nameValuePairs) {
            // after parsing each parameter pair, splitting into name and value
            // now
            String[] nameValues = nameValue.split("=");
            params.put(nameValues[0], nameValues[1]);
            jsonObject.put(nameValues[0], nameValues[1]);
        }
        return jsonObject;
    }

    /**
     * populates the input params with the response from the redirect URI from
     * the browser. It also returns the result as a JSONObject.
     *
     * @param params
     * @param redirectUri
     * @throws JSONException
     */
    protected JSONObject parseRedirectResponseUri(Map<String, Object> params,
                                                  Uri redirectUri) throws JSONException {
        JSONObject jsonObject = new JSONObject();
        for (OAuthConnectionsUtil.OAuthResponseParameters name : OAuthConnectionsUtil.OAuthResponseParameters.values()) {
            String value = redirectUri.getQueryParameter(name.getValue());
            if (value != null) {
                params.put(name.getValue(), value);
                jsonObject.put(name.getValue(), value);
            }
        }
        return jsonObject;
    }

    protected String getIdentityClaims() throws JSONException {
        OMMobileSecurityService mss = mASM.getMSS();
        if (mIdentityClaims == null) {
            String tempString = mss.getMobileSecurityConfig().getIdentityClaims(mss.getApplicationContext(),
                    mss.getCredentialStoreService());
            JSONObject temp = new JSONObject(tempString);
            mIdentityClaims = temp.optString(IdentityContext.DEVICE_PROFILE);
        }
        return mIdentityClaims;
    }

    /**
     * This method determines client assertion type if at all it is applicable.
     * Also this method fails the authentication process is client assertion is not available with the SDK.
     *
     * @param authContext
     * @param params
     * @return
     * @throws OMMobileSecurityException
     */
    protected boolean updateParamsForClientAssertionForTokenRequest(
            OMAuthenticationContext authContext,
            WeakHashMap<String, Object> params)
            throws OMMobileSecurityException {
        OAuthMSToken clientAssertion = mConfig.getOAuthClientAssertion();
        OAuthConnectionsUtil.OAuthClientAssertionType type = determineClientAssertionType();
        if (OAuthConnectionsUtil.OAuthClientAssertionType.MS_OAUTH == type) {
            // if MS OAuth re-use the client assertion.
            OAuthMSToken oAuthClientAssertion = mASM.retrieveClientAssertion();
            if (oAuthClientAssertion != null) {
                params.put(OMSecurityConstants.Param.OAUTH_CLIENT_ASSERTION,
                        oAuthClientAssertion);
                return true;
            } else {
                // fail
                throw new OMMobileSecurityException(OMErrorCode.OAUTH_MS_CLIENT_ASSERTION_INVALID);
            }
        } else if (OAuthConnectionsUtil.OAuthClientAssertionType.IDCS == type) {
            //For IDCS Client Registration
            IDCSClientRegistrationToken idcsClientRegistrationToken = (IDCSClientRegistrationToken) authContext.getTokens().get(OMSecurityConstants.CLIENT_REGISTRATION_TOKEN);
            if (idcsClientRegistrationToken != null) {
                params.put(OMSecurityConstants.Param.OAUTH_CLIENT_ASSERTION,
                        idcsClientRegistrationToken);
                return true;
            } else {
                // fail
                throw new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_TOKEN_NOT_AVAILABLE);
            }
        } else if (clientAssertion != null) {
            // check if the client assertion is made available by app during
            // init.
            params.put(OMSecurityConstants.Param.OAUTH_CLIENT_ASSERTION,
                    clientAssertion);
            return true;
        }
        return false;
    }

    protected OAuthConnectionsUtil.OAuthClientAssertionType determineClientAssertionType() {

        OAuthConnectionsUtil.OAuthClientAssertionType type = null;
        if (mConfig.isClientRegistrationRequired() && mASM.getOAuthConnectionsUtil().getOAuthType() == OAuthConnectionsUtil.OAuthType.STANDARD) {
            type = OAuthConnectionsUtil.OAuthClientAssertionType.IDCS;
        } else if (mASM.getOAuthConnectionsUtil().getOAuthType() == OAuthConnectionsUtil.OAuthType.MSOAUTH) {
            type = OAuthConnectionsUtil.OAuthClientAssertionType.MS_OAUTH;
        }
        OMLog.debug(TAG, "determineClientAssertionType : " + type);
        return type;
    }

    /**
     * Helper class to sort tokens holding scopes in ascending order.
     *
     */
    private class OAuthTokenComparator implements Comparator<OAuthToken> {
        @Override
        public int compare(OAuthToken token1, OAuthToken token2) {
            if (token1.getScopes().size() == token2.getScopes().size()) {
                return 0;
            } else {
                if (token1.getScopes().size() < token2.getScopes().size()) {
                    return -1;
                } else {
                    return 1;
                }
            }
        }
    }
}
