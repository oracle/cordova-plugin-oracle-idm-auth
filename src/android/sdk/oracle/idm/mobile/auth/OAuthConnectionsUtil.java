/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.content.Context;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import org.json.JSONException;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.openID.OpenIDToken;
import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMMSOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOICMobileSecurityConfiguration;
import oracle.idm.mobile.crypto.CryptoScheme;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.PASSWORD_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.USERNAME_KEY;
import static oracle.idm.mobile.configuration.OAuthAuthorizationGrantType.RESOURCE_OWNER;

/**
 * Utility class for OAuth connection to server.
 */
public class OAuthConnectionsUtil {

    private static String TAG = OAuthConnectionsUtil.class.getSimpleName();
    private static SecureRandom secureRandom = new SecureRandom();
    private static final int OAUTH_PKCE_DEFAULT_CODE_VERIFIER_ENTROPY = 64;
    private static final int OAUTH_PKCE_DEFAULT_ENCODING = Base64.NO_PADDING | Base64.NO_WRAP | Base64.URL_SAFE;

    private static final String OAUTH_PKCE_DEFAULT_CHARSET = "US-ASCII";
    private static final String OAUTH_PKCE_DEFAULT_CODE_VERIFIER_CHALLENGE_METHOD = CryptoScheme.SHA256.getValue();


    static final String AMPERSAND = "&";
    static final String QUERY_START = "?";
    // OAuth2.0 request constant as per RFC 6749
    static final String OAUTH_CODE_REQ = "code=";
    static final String OAUTH_SCOPE_REQ = "scope=";
    static final String OAUTH_STATE_REQ = "state=";
    static final String OPENID_NONCE_REQ = "nonce=";
    static final String OAUTH_PKCE_CODE_CHALLENGE_REQ = "code_challenge=";
    static final String OAUTH_PKCE_CODE_CHALLENGE_METHOD_REQ_SHA256 = "code_challenge_method=S256";
    static final String OAUTH_PKCE_CODE_VERIFIER_REQ = "code_verifier=";
    static final String OAUTH_USERNAME_REQ = "username=";
    static final String OAUTH_PASSWORD_REQ = "password=";
    static final String OAUTH_CLIENT_ID_REQ = "client_id=";
    static final String OAUTH_GRANT_TYPE_REQ = "grant_type=";
    static final String OAUTH_REDIRECT_URI_REQ = "redirect_uri=";
    static final String OAUTH_RESPONSE_TYPE_REQ = "response_type=";
    static final String DEFAULT_SCOPE_BY_SDK = "idmmobileSDKDefaultScope";

    //OAuth2.0 standard grant types
    static final String OAUTH_RESPONSE_TYPE_CODE = "code";
    static final String OAUTH_RESPONSE_TYPE_TOKEN = "token";
    static final String OAUTH_GRANT_TYPE_PASSWORD = "password";
    static final String OAUTH_GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
    static final String OAUTH_GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    static final String OAUTH_GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    static final String OAUTH_REFRESH_TOKEN_REQ = "refresh_token=";

    // M&S OAuth constants
    static final String OAUTH_MS_PRE_AUTHZ_CODE_REQ = "oracle_pre_authz_code=";
    static final String OAUTH_MS_PRE_AUTHZ_CODE_PARAM = "OAuthMSPreAuthZCodeParam";
    static final String OAUTH_MS_REQUESTED_ASSERTIONS_REQ = "oracle_requested_assertions=";
    static final String OAUTH_MS_DEVICE_PROFILE_REQ = "oracle_device_profile=";
    static final String OAUTH_MS_GRANT_TYPE_PRE_AUTHZ_CODE = "oracle-idm:/oauth/assertion-type/client-identity/mobile-client-pre-authz-code-client";
    public static final String OAUTH_TOKEN_TYPE_SAML2_CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";
    public static final String OAUTH_TOKEN_TYPE_JWT_CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    static final String OAUTH_CLIENT_ASSERTION_TYPE_REQ = "client_assertion_type=";
    static final String OAUTH_CLIENT_ASSERTION_REQ = "client_assertion=";

    // IDCS constants

    private static final String IDCS_DYNAMIC_CLIENT_REGISTRATION_SCOPE = "urn:opc:idm:t.app.register";
    private static final String IDCS_POST_LOGOUT_REDIRECT_URI_REQ = "post_logout_redirect_uri=";
    private static final String IDCS_ID_TOKEN_REQ = "id_token_hint=";

    private static final String HOST_FACEBOOK = ".facebook.com/";

    private String oAuthState;
    private String openIDNonce;
    private Set<String> oAuthScopes;
    private OMAuthenticationRequest mRequest;
    private boolean enableRequestVerbose = false;// should be false in production code
    private OAuthAuthorizationGrantType mOAuthGrantType;
    private OMOAuthMobileSecurityConfiguration oAuthConfig;

    private Set<String> defaultScopeSet;
    private boolean isOpenID = false;
    private OAuthType mOAuthType;
    //private static SecureRandom secureRandom = new SecureRandom();TODO for authz code

    private String mCodeVerifier;

    private boolean mUsePKCE;

    private boolean mRegisterClient;

    /**
     * Returns the type of OAuth flow.
     */
    public enum OAuthType {
        STANDARD, MSOAUTH
    }

    public enum OAuthClientAssertionType {
        MS_OAUTH, IDCS
    }

    // OAuth2.0 Response Parameters/ Known Errors as per RFC 6749
    public enum OAuthResponseParameters {
        ACCESS_TOKEN("access_token"), ERROR("error"), ERROR_DESCRIPTION(
                "error_description"), CODE("code"), REFRESH_TOKEN(
                "refresh_token"), TOKEN_TYPE("token_type"), EXPIRES_IN(
                "expires_in"), STATE("state"), TOKEN_ID("token_id"), ID_TOKEN(
                "id_token"), NONCE("nonce");

        private String responseValue;

        OAuthResponseParameters(String responseValue) {
            this.responseValue = responseValue;
        }

        public String getValue() {
            return this.responseValue;
        }
    }

    public OAuthConnectionsUtil(OMAuthenticationRequest request) {
        OMLog.info(OMSecurityConstants.TAG, "[OAuthConnectionsUtil] initialized");
        mRequest = request;
    }

    public OAuthConnectionsUtil(Context context,
                                final OMOAuthMobileSecurityConfiguration oAuthConfig,
                                final Set<String> oAuthScopes) {
        if (oAuthConfig == null) {
            throw new IllegalArgumentException(
                    "OAuthConnection arguments can not be null");
        }
        mOAuthType = (oAuthConfig instanceof OMMSOAuthMobileSecurityConfiguration) ? OAuthType.MSOAUTH
                : OAuthType.STANDARD;
        if (oAuthConfig instanceof OMOICMobileSecurityConfiguration) {
            isOpenID = true;
            OMLog.debug(TAG, "This is openID Configuration Use case");
            generateNonce();
        }
        this.oAuthConfig = oAuthConfig;
        this.mOAuthGrantType = oAuthConfig.getOAuthzGrantType();

        // if no scope is passed use the default from the configuration obj.
        if (oAuthScopes == null) {
            this.oAuthScopes = oAuthConfig.getOAuthScopes();
        } else
            this.oAuthScopes = oAuthScopes;

        mUsePKCE = oAuthConfig.isPKCEEnabled() && isDefaultCodeChallengeMethodSupported();
        OMLog.debug(TAG, "OAuthConnection Utils -> Use PKCE : " + mUsePKCE);
        mRegisterClient = oAuthConfig.isClientRegistrationRequired();
        OMLog.debug(TAG, "OAuthConnection Utils -> Register Client : " + mRegisterClient);

    }


    public OMMobileSecurityConfiguration.BrowserMode getBrowserMode() {
        return oAuthConfig.getOAuthBrowserMode();
    }

    /**
     * Utility to form a back channel request(for HTTP post) based on the
     * different Authorization grant types. This Request is compliant with RFC
     * 6749
     *
     * @param grantType Authorization grant type .
     * @param paramMap  This will contain the required query parameters based on the
     *                  grant type . For example for Authorization code flow it will
     *                  have code parameter For Resource owner credentials it will
     *                  have username and password
     * @return
     * @throws UnsupportedEncodingException
     * @throws JSONException
     */
    public String getBackChannelRequestForAccessToken(
            OAuthAuthorizationGrantType grantType,
            Map<String, Object> paramMap)
            throws UnsupportedEncodingException, JSONException {
        OMLog.debug(TAG, "getBackChannelRequestForAccessToken : " + " grantType : " + grantType);

        StringBuilder payload = getBackChannelRequestForAccessTokenInternal(grantType, paramMap);
        boolean isConfidentialClient = !TextUtils.isEmpty(oAuthConfig
                .getOAuthClientSecret());
        // according to the latest M&S changes if the client is sending the
        // client authentication header then client id is not required to be
        // passed in the access token request payload.
        /*client_id is required to be added in payload for facebook */
        if (!isConfidentialClient || isHostFacebook()) {
            // usually for M&S mobile client, google and facebook installed app clients, OAF
            // public
            // clients.

            updatePayloadWithClientID(payload, oAuthConfig.getOAuthClientID());

        }
        OMLog.debug(TAG, "OAuthClient Type = "
                + ((isConfidentialClient ? "confidential!"
                : "non-confidential!")));

        if (enableRequestVerbose) {
            OMLog.debug(TAG, "--> Request for fetching access token for grant type "
                    + grantType + "  " + payload.toString());
        }
        return payload.toString();
    }


    private void updatePayloadWithClientID(StringBuilder payload, String clientID) throws UnsupportedEncodingException {
        OMLog.debug(TAG, "updating payload with client ID : " + clientID);
        payload.append(OAUTH_CLIENT_ID_REQ
                + getURLEncodedString(clientID));
        payload.append(AMPERSAND);
    }

    private StringBuilder getBackChannelRequestForAccessTokenInternal(OAuthAuthorizationGrantType grantType,
                                                                      Map<String, Object> paramMap) throws UnsupportedEncodingException {
        StringBuilder payload = new StringBuilder();
        switch (grantType) {
            case RESOURCE_OWNER:
                payload.append(OAUTH_GRANT_TYPE_REQ
                        + getURLEncodedString(OAUTH_GRANT_TYPE_PASSWORD));
                payload.append(AMPERSAND);
                payload.append(OAUTH_USERNAME_REQ
                        + getURLEncodedString((String) paramMap
                        .get(USERNAME_KEY)));
                payload.append(AMPERSAND);
                payload.append(OAUTH_PASSWORD_REQ
                        + getURLEncodedString((String) paramMap
                        .get(PASSWORD_KEY)));
                payload.append(AMPERSAND);
                // resource owner credentials grant type we send scopes also.

                addScopesToPayload(payload, oAuthScopes);
                break;
            case CLIENT_CREDENTIALS:
                payload.append(OAUTH_GRANT_TYPE_REQ
                        + getURLEncodedString(OAUTH_GRANT_TYPE_CLIENT_CREDENTIALS));
                payload.append(AMPERSAND);
                addScopesToPayload(payload, oAuthScopes);
                break;
            case AUTHORIZATION_CODE:
                payload.append(OAUTH_CODE_REQ
                        + paramMap.get(OAuthResponseParameters.CODE
                        .getValue()));
                payload.append(AMPERSAND);
                payload.append(OAUTH_GRANT_TYPE_REQ
                        + getURLEncodedString(OAUTH_GRANT_TYPE_AUTHORIZATION_CODE));
                payload.append(AMPERSAND);
                payload.append(OAUTH_REDIRECT_URI_REQ
                        + getURLEncodedString(oAuthConfig
                        .getOAuthRedirectEndpoint()));
                payload.append(AMPERSAND);
                if (mUsePKCE) {
                    //lets add code verifier
                    if (getCodeVerifier() != null) {
                        payload.append(OAUTH_PKCE_CODE_VERIFIER_REQ
                                + getCodeVerifier());
                        payload.append(AMPERSAND);
                    }
                }
                break;
            default:
                break;
        }

        return payload;
    }

    public String getBackChannelRequestForAccessTokenUsingClientAssertion(
            OAuthAuthorizationGrantType grantType,
            Map<String, Object> paramMap, OAuthConnectionsUtil.OAuthClientAssertionType type) throws UnsupportedEncodingException {
        OMLog.debug(TAG, "getBackChannelRequestForAccessTokenUsingClientAssertion: " + " grantType : " + grantType + " Assertion type: " + type);

        StringBuilder payload = getBackChannelRequestForAccessTokenInternal(grantType, paramMap);
        boolean isConfidentialClient = !TextUtils.isEmpty(oAuthConfig
                .getOAuthClientSecret());

        OAuthToken clientAssertion = (OAuthToken) paramMap
                .get(OMSecurityConstants.Param.OAUTH_CLIENT_ASSERTION);
        if (clientAssertion != null) {
            addClientAssertionToPayload(payload, clientAssertion);
        }
        if (!isConfidentialClient) {
            String clientID = oAuthConfig.getOAuthClientID();
            if (type == OAuthClientAssertionType.IDCS) {
                if (((IDCSClientRegistrationToken) clientAssertion).getClientID() != null) {
                    clientID = ((IDCSClientRegistrationToken) clientAssertion).getClientID();
                }
            }
            //for IDCS Client Registration we need to take the client ID from the Client Registration token itself.
            updatePayloadWithClientID(payload, clientID);
        }

        OMLog.debug(TAG, "OAuthClient Type = "
                + ((isConfidentialClient ? "confidential!"
                : "non-confidential!")));

        if (enableRequestVerbose) {
            OMLog.debug(TAG, "--> Request for fetching access token for grant type "
                    + grantType + "  " + payload.toString());
        }
        return payload.toString();
    }

    /**
     * Typically in M&S OAuth flows for mobile client we need to add the client
     * assertion in the payload. So this method should be called whenever
     * applicable.
     *
     * @param clientAssertion
     */
    private void addClientAssertionToPayload(StringBuilder payload,
                                             OAuthToken clientAssertion) {
        if (clientAssertion != null) {
            String assertionType = clientAssertion.getTokenType();
            payload.append(OAUTH_CLIENT_ASSERTION_TYPE_REQ);
            payload.append(assertionType);
            payload.append(AMPERSAND);
            payload.append(OAUTH_CLIENT_ASSERTION_REQ);
            payload.append(clientAssertion.getValue());
            payload.append(AMPERSAND);
        }
    }

    /**
     * Lighter helper method for returning the authorization grant type
     * requested in the mobile security configuration.
     *
     * @return
     */
    public OAuthAuthorizationGrantType getOAuthGrantType() {
        return mOAuthGrantType;
    }

    /**
     * Utility to generate a Request String to be used by the user
     * agent[external and embedded]. The format of the request is in accordance
     * with RFC 6749
     *
     * @return Request String
     * @throws UnsupportedEncodingException
     */
    public String getFrontChannelRequestForAccessToken(boolean appendScopes) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        {
            StringBuilder request = new StringBuilder();
            request.append(oAuthConfig.getOAuthAuthorizationEndpoint());
            request.append(QUERY_START);
            request.append(OAUTH_CLIENT_ID_REQ
                    + getURLEncodedString(oAuthConfig.getOAuthClientID()));
            request.append(AMPERSAND);
            switch (oAuthConfig.getOAuthzGrantType()) {
                case IMPLICIT:
                    request.append(OAUTH_RESPONSE_TYPE_REQ
                            + getURLEncodedString(OAUTH_RESPONSE_TYPE_TOKEN));
                    request.append(AMPERSAND);
                    break;
                case AUTHORIZATION_CODE:
                    request.append(OAUTH_RESPONSE_TYPE_REQ
                            + getURLEncodedString(OAUTH_RESPONSE_TYPE_CODE));
                    request.append(AMPERSAND);
                    break;
                default:
                    break;
            }
            if (oAuthConfig.getOAuthRedirectEndpoint() != null) {
                request.append(OAUTH_REDIRECT_URI_REQ
                        + getURLEncodedString(oAuthConfig
                        .getOAuthRedirectEndpoint()));
                request.append(AMPERSAND);
            }
            request.append(OAUTH_STATE_REQ + getURLEncodedString(getOAuthState()));
            request.append(AMPERSAND);
            if (appendScopes) {
                addScopesToPayload(request, oAuthScopes);
            }
            if (oAuthConfig instanceof OMOICMobileSecurityConfiguration) {
                OMLog.debug(TAG, "Open ID Use case, add nonce!");
                request.append(OPENID_NONCE_REQ + openIDNonce);
            }

            //for now lets add the PKCE for openID use cases
            if (mUsePKCE) {
                request.append(AMPERSAND);
                request.append(OAUTH_PKCE_CODE_CHALLENGE_REQ + generateCodeVerifierChallenge());
                request.append(AMPERSAND);
                request.append(OAUTH_PKCE_CODE_CHALLENGE_METHOD_REQ_SHA256);
            }

            //--->   Logging <--- //
            if (enableRequestVerbose) {
                OMLog.debug(TAG,
                        "--> Request front channel for : Access TOKEN : "
                                + oAuthConfig.getOAuthzGrantType() + " : "
                                + request.toString());
            }
            return request.toString();
        }
    }

    public String getFrontChannelRequestForClientRegistration() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        {
            OMLog.debug(TAG, "getFrontChannelRequestForClientRegistration");
            StringBuilder request = new StringBuilder();
            request.append(oAuthConfig.getOAuthAuthorizationEndpoint());
            request.append(QUERY_START);
            request.append(OAUTH_CLIENT_ID_REQ
                    + getURLEncodedString(oAuthConfig.getOAuthClientID()));
            request.append(AMPERSAND);

            request.append(OAUTH_RESPONSE_TYPE_REQ
                    + getURLEncodedString(OAUTH_RESPONSE_TYPE_CODE));
            request.append(AMPERSAND);

            if (oAuthConfig.getOAuthRedirectEndpoint() != null) {
                request.append(OAUTH_REDIRECT_URI_REQ
                        + getURLEncodedString(oAuthConfig
                        .getOAuthRedirectEndpoint()));
                request.append(AMPERSAND);
            }
            request.append(OAUTH_STATE_REQ + getURLEncodedString(getOAuthState()));
            request.append(AMPERSAND);
            Set<String> registerScopes = new HashSet<>();
            registerScopes.add(IDCS_DYNAMIC_CLIENT_REGISTRATION_SCOPE);
            addScopesToPayload(request, registerScopes);

            //for now lets add the PKCE for openID use cases
            if (isDefaultCodeChallengeMethodSupported()) {
                OMLog.debug(TAG, "Adding PKCE!");
                request.append(AMPERSAND);
                request.append(OAUTH_PKCE_CODE_CHALLENGE_REQ + generateCodeVerifierChallenge());
                request.append(AMPERSAND);
                request.append(OAUTH_PKCE_CODE_CHALLENGE_METHOD_REQ_SHA256);
            }

            //--->   Logging <--- //
            if (enableRequestVerbose) {
                OMLog.debug(TAG,
                        "--> Request front channel for : CLIENT REGISTRATION TOKEN : "
                                + oAuthConfig.getOAuthzGrantType() + " : "
                                + request.toString());
            }
            return request.toString();
        }
    }


    private void generateNonce() {
        // generate a 10 digit number.
        openIDNonce = String.valueOf((long) (secureRandom.nextDouble() * 9999999999L + 100000000L));
        OMLog.info(TAG, "Generated Nonce: " + openIDNonce);
    }


    private String generateRandomCodeVerifier() {
        byte[] verifierBytes = new byte[OAUTH_PKCE_DEFAULT_CODE_VERIFIER_ENTROPY];
        secureRandom.nextBytes(verifierBytes);
        String verifier = Base64.encodeToString(verifierBytes, OAUTH_PKCE_DEFAULT_ENCODING);
        return verifier;
    }

    private String getCodeVerifier() {
        return mCodeVerifier;
    }

    private String generateCodeVerifierChallenge() throws NoSuchAlgorithmException {

        if (mCodeVerifier == null) {
            mCodeVerifier = generateRandomCodeVerifier();
        }

        MessageDigest digest = MessageDigest.getInstance(OAUTH_PKCE_DEFAULT_CODE_VERIFIER_CHALLENGE_METHOD);
        digest.update(mCodeVerifier.getBytes());
        byte[] digestedBytes = digest.digest();
        String challenge = Base64.encodeToString(digestedBytes, OAUTH_PKCE_DEFAULT_ENCODING);
        return challenge;
    }

    private boolean isDefaultCodeChallengeMethodSupported() {
        try {
            MessageDigest.getInstance(OAUTH_PKCE_DEFAULT_CODE_VERIFIER_CHALLENGE_METHOD);
            return true;
        } catch (NoSuchAlgorithmException e) {
            OMLog.error(TAG, "PKCE-- " + OAUTH_PKCE_DEFAULT_CODE_VERIFIER_CHALLENGE_METHOD + " not supported");
            return false;
        }
    }

    private String getCodeVerifierChallengeMethod() {
        try {
            MessageDigest.getInstance(OAUTH_PKCE_DEFAULT_CODE_VERIFIER_CHALLENGE_METHOD);
            return OAUTH_PKCE_DEFAULT_CODE_VERIFIER_CHALLENGE_METHOD;
        } catch (NoSuchAlgorithmException e) {
            //should have already been caught if the caller calls isDefaultCodeChallengeMethodSupported before
            mUsePKCE = false;
            OMLog.error(TAG, "PKCE--" + OAUTH_PKCE_DEFAULT_CODE_VERIFIER_CHALLENGE_METHOD + " not supported");
            return null;
        }
    }

    private String getURLEncodedString(String input)
            throws UnsupportedEncodingException {
        return URLEncoder.encode(input, OAUTH_PKCE_DEFAULT_CHARSET);
    }

    /**
     * This method should be used by the grant types which require to add scope
     * in the request payload.
     *
     * @param payload
     * @throws UnsupportedEncodingException
     */
    private void addScopesToPayload(StringBuilder payload, Set<String> scopes)
            throws UnsupportedEncodingException {
        String localTag = TAG + "_addScopesToPayload";
        StringBuilder scopeString = new StringBuilder();
        if (scopes != null && !scopes.isEmpty()) {
            /*
             * for multiple scopes send all scopes with a space delimited
             * format. the space also needs to be URL encoded.
             */
            for (String scope : scopes) {
                if (scope == null) {
                    Log.v(localTag, "scope is null, hence skipping it");
                    continue;
                }
                scopeString.append(getURLEncodedString(scope));
                scopeString.append("%20");
            }
            if (scopeString.length() >= 3) {
                /* remove the extra space */
                int startIndex = scopeString.length() - 3;
                scopeString.delete(startIndex, startIndex + 3);
            }
        }

        if (!TextUtils.isEmpty(scopeString)) {
            payload.append(OAUTH_SCOPE_REQ + scopeString.toString());
            payload.append(AMPERSAND);
        }
    }

    /**
     * generates a random state parameter for the OAuthConnection Object .
     *
     * @return
     */
    public String getOAuthState() {
        if (oAuthState == null) {
            // generate a 6 digit number.
            oAuthState = (int) (secureRandom.nextDouble() * 999999 + 10000)
                    + "";
        }
        return oAuthState;
    }

    public String getOpenIDNonce() {
        return openIDNonce;
    }

    /**
     * Light weight helper utility that returns true if the present OAuth
     * configuration is a 2-legged grant type( resource owner, assertion, oam
     * credentials).
     * <p/>
     * This will be helpful in view customization and Remember credentials use
     * cases.
     *
     * @return
     */
    public boolean isTwoLeggedGrantType() {
        if (oAuthConfig != null) {
            OAuthAuthorizationGrantType grantType = oAuthConfig
                    .getOAuthzGrantType();
            if (grantType == RESOURCE_OWNER) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns true if host is facebook
     */
    private boolean isHostFacebook() {
        return oAuthConfig.getOAuthTokenEndpoint().toString().toLowerCase().contains(HOST_FACEBOOK);
    }

    /**
     * Returns scopes associated with the current authentication
     *
     * @return
     */
    public Set<String> getOAuthScopes() {
        return oAuthScopes;
    }

    Set<String> getDefaultOAuthScope() {
        if (defaultScopeSet == null) {
            defaultScopeSet = new HashSet<>();
            defaultScopeSet.add(DEFAULT_SCOPE_BY_SDK);
        }
        return defaultScopeSet;
    }

    public String getClientAuthHeader() throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder(oAuthConfig.getOAuthClientID());
        sb.append(":");
        if (!TextUtils.isEmpty(oAuthConfig.getOAuthClientSecret())) {
            sb.append(oAuthConfig.getOAuthClientSecret());
        }

        return Base64.encodeToString(sb.toString().getBytes("UTF-8"),
                Base64.NO_WRAP);
    }

    public String getBackChannelRequestForRefreshingAccessToken(
            WeakHashMap<String, Object> params)
            throws UnsupportedEncodingException {
        StringBuilder payload = new StringBuilder();
        if (!oAuthConfig.isConfidentialClient()) {
            payload.append(OAUTH_CLIENT_ID_REQ
                    + getURLEncodedString(oAuthConfig.getOAuthClientID()));
            payload.append(AMPERSAND);
        }
        payload.append(OAUTH_REFRESH_TOKEN_REQ
                + getURLEncodedString(((String) params
                .get(OMSecurityConstants.Param.OAUTH_REFRESH_TOKEN_VALUE))));
        payload.append(AMPERSAND);
        payload.append(OAUTH_GRANT_TYPE_REQ
                + getURLEncodedString(OAUTH_GRANT_TYPE_REFRESH_TOKEN));
        payload.append(AMPERSAND);

        if (enableRequestVerbose) {
            OMLog.debug(TAG,
                    "--> Request for refreshing : ACCESS TOKEN "
                            + payload.toString());
        }
        return payload.toString();
    }

    /**
     * Helper to return the type of authentication flow.
     *
     * @return Standard: For standard OAuth flows. MSOAuth: for Mobile and
     * Social proprietary mobile flows.
     */
    public OAuthType getOAuthType() {
        return mOAuthType;
    }

    public String getLogoutUrl(OMAuthenticationContext authenticationContext) {
        if (oAuthConfig.getLogoutUrl() == null) {
            return null;
        }
        StringBuilder logoutUrl = new StringBuilder(oAuthConfig.getLogoutUrl().toString());
        if (oAuthConfig instanceof OMOICMobileSecurityConfiguration) {
            String redirectEndpoint = oAuthConfig.getOAuthRedirectEndpoint();
            try {
                redirectEndpoint = getURLEncodedString(redirectEndpoint);
            } catch (UnsupportedEncodingException e) {
                OMLog.error(TAG, e.getMessage(), e);
            }

            logoutUrl.append(QUERY_START)
                    .append(IDCS_POST_LOGOUT_REDIRECT_URI_REQ)
                    .append(redirectEndpoint)
                    .append(AMPERSAND)
                    .append(OAUTH_STATE_REQ)
                    .append(getOAuthState());
            OpenIDToken idToken = null;
            if (authenticationContext != null) {
                idToken = (OpenIDToken) authenticationContext.getTokens().get(OpenIDToken.OPENID_CONNECT_TOKEN);
            }
            if (idToken != null) {
                logoutUrl.append(AMPERSAND)
                        .append(IDCS_ID_TOKEN_REQ)
                        .append(idToken.getValue());
            }
        }
        return logoutUrl.toString();
    }
}
