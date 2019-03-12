/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.text.TextUtils;

import org.json.JSONException;

import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.auth.openID.OpenIDToken;
import oracle.idm.mobile.auth.openID.OpenIDTokenService;
import oracle.idm.mobile.auth.openID.OpenIDUserInfo;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOICMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.logging.OMLog;

/**
 * Authentication Service for OpenIDConnect10
 * As OpenIDConnect10 support for OAuth2.0 Authorization code/implicit OOB.
 * We will extend most of the authentication capabilities from existing AuthorizationCode flows apart from openID specific flows..
 *
 */
public class OpenIDConnect10AuthenticationService extends OAuthAuthorizationCodeService {

    private static final String TAG = OpenIDConnect10AuthenticationService.class.getSimpleName();
    private static final String BEARER = "Bearer";
    private static final String AUTHORIZATION = "Authorization";
    private OMOICMobileSecurityConfiguration idConfig;
    private OpenIDTokenService openIDTokenService;

    protected OpenIDConnect10AuthenticationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler loginHandler, OMLogoutCompletionHandler logoutHandler) {
        super(asm, loginHandler, logoutHandler);
        OMMobileSecurityConfiguration config = asm.getMSS().getMobileSecurityConfig();
        if (config instanceof OMOICMobileSecurityConfiguration) {
            idConfig = (OMOICMobileSecurityConfiguration) config;
            OMLog.info(TAG, "initialized!");
        }
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.info(TAG, "handleAuthentication");
        boolean error = false;
        OMMobileSecurityException mobileException = null;
        final HashMap<String, Object> inputParams = (HashMap<String, Object>) authContext
                .getInputParams();
        validateAndUpdateInputParams(inputParams);
        OAuthToken accessToken = null;
        authContext.setAuthenticationProvider(OMAuthenticationContext.AuthenticationProvider.OPENIDCONNECT10);
        if (inputParams.containsKey(OAuthConnectionsUtil.OAuthResponseParameters.CODE.getValue())) {
            // adding client id/client secret to params
            WeakHashMap<String, Object> paramMap = getEmptyParamHashMap();
            paramMap.put(OAuthConnectionsUtil.OAuthResponseParameters.CODE.getValue(),
                    inputParams.get(OAuthConnectionsUtil.OAuthResponseParameters.CODE
                            .getValue()));
            String identityDomain = (String) authContext.getInputParams().get(
                    OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY);
            String accessTokenResponse = onAuthZCode(authContext, paramMap,
                    identityDomain);
            if (!TextUtils.isEmpty(accessTokenResponse)) {
                try {
                    accessToken = onAccessToken(accessTokenResponse);
                    String idTokenString = accessToken.getIdToken();
                    if (!TextUtils.isEmpty(idTokenString)) {
                        OpenIDToken idToken = getOpenIDTokenService().generate(idTokenString, true);
                        URL url = idConfig.getSigningCertEndpoint();
                        OMLog.debug(TAG, "Getting Signing Cert details from URL: " + url);
                        String jwksResponse = "";
                        OMHTTPResponse response = getSigningCertForIDCS(url, accessToken);
                        boolean verify = false;
                        if (response != null) {
                            int responseCode = response.getResponseCode();
                            OMLog.debug(TAG, "Response Code: " + responseCode);
                            if (responseCode == HttpURLConnection.HTTP_OK) {
                                jwksResponse = response.getResponseStringOnSuccess();
                                verify = true;
                            } else {
                                jwksResponse = response.getResponseStringOnFailure();
                                verify = false;//no verifying required
                            }
                        }

                        //lets do local validation first
                        if (isTokenValid(idToken, true)) {
                            if (verify) {
                                boolean verificationStatus = getOpenIDTokenService().verifySignature(idToken, jwksResponse);
                                if (!verificationStatus) {
                                    error = true;
                                    mobileException = new OMMobileSecurityException(OMErrorCode.OPENID_TOKEN_SIGNATURE_INVALID);
                                } else {
                                    OMLog.debug(TAG, "ID token is Verified");
                                    onOpenIDSuccess(authContext, idToken, accessToken);
                                }
                            } else {
                                OMLog.debug(TAG, "Skipping the verifying of ID Token");
                                onOpenIDSuccess(authContext, idToken, accessToken);
                            }
                        } else {
                            OMLog.error(TAG, "ID Token Validation failed!");
                            error = true;
                            mobileException = new OMMobileSecurityException(OMErrorCode.OPENID_TOKEN_INVALID);
                        }
                    } else {
                        OMLog.error(TAG, "Unable to get the ID Token from the server!");
                        error = true;
                        mobileException = new OMMobileSecurityException(OMErrorCode.OPENID_AUTHENTICATION_FAILED);
                    }
                } catch (JSONException e) {
                    mobileException = new OMMobileSecurityException(OMErrorCode.OPENID_AUTHENTICATION_FAILED, e);
                } catch (ParseException e) {
                    mobileException = new OMMobileSecurityException(OMErrorCode.OPENID_TOKEN_PARSING_FAILED, e);
                }
            } else {
                OMLog.error(TAG, "access Token Response is null!");
                error = true;
                mobileException = new OMMobileSecurityException(OMErrorCode.OPENID_AUTHENTICATION_FAILED);
            }
        } else if (inputParams.containsKey(OAuthConnectionsUtil.OAuthResponseParameters.ERROR
                .getValue())) {
            // this may be because of some error either in front channel or back
            // channel
            // check in the input params for the same.
            mobileException = onError(inputParams);
            if (mobileException == null) {
                mobileException = new OMMobileSecurityException(
                        OMErrorCode.OAUTH_AUTHENTICATION_FAILED);
                return null;
            }
            error = true;
        }
        if (error) {
            authContext.setException(mobileException);
            authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
        }
        return null;
    }


    private void onOpenIDSuccess(OMAuthenticationContext authContext, OpenIDToken idToken, OAuthToken accessToken) throws OMMobileSecurityException {
        OMLog.debug(TAG, "onOpenIDSuccess");
        authContext.getTokens().put(OpenIDToken.OPENID_CONNECT_TOKEN, idToken);//set token in the authContext
        authContext.setOpenIdUserInfo(createUserInfo(idToken));
        onAuthSuccess(authContext, accessToken, OMAuthenticationContext.AuthenticationProvider.OPENIDCONNECT10);
    }

    private OpenIDUserInfo createUserInfo(OpenIDToken idToken) {
        return getOpenIDTokenService().generateUserInfo(idToken);
    }

    /**
     * Currently IDCS signing certs are OAuth protected
     *
     * @param url
     * @param accessToken
     * @return
     * @throws OMMobileSecurityException
     */
    private OMHTTPResponse getSigningCertForIDCS(URL url, OAuthToken accessToken) {
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION, BEARER + " " + accessToken.getValue());
        try {
            return mASM.getMSS().getConnectionHandler().httpGet(url, headers);
        } catch (OMMobileSecurityException e) {
            OMLog.error(TAG, e.getErrorMessage(), e);
        }
        return null;
    }

    public OpenIDTokenService getOpenIDTokenService() {
        if (openIDTokenService == null) {
            openIDTokenService = new OpenIDTokenService();
        }
        return openIDTokenService;
    }

    /**
     * returns true only when <b>all</b> of the following claims match
     * <p>validate issuer claim should match the one we from Open ID Discovery</p>
     * <p>validate the aud claim contains the client_id of the open ID client given during initialization.</p>
     * <p>validate if the azp claim is available, verify that it matches the client id</p>
     * <p>Since SDK sends the nonce, it expects the same to be part of ID token claims, and it should match the original nonce sent while making authentication request</p>
     *
     * @param token
     */
    private boolean validateClaims(OpenIDToken token) {
        OMLog.info(TAG, "ValidateClaims");
        if (token != null && idConfig != null) {
            boolean result = true;
            //create reference claims
            Map<String, String> referenceClaims = new HashMap<String, String>();
            //issuer
            referenceClaims.put(OpenIDToken.TokenClaims.ISSUER.getName(), idConfig.getIssuer());
            //audience
            referenceClaims.put(OpenIDToken.TokenClaims.AUDIENCE.getName(), idConfig.getOAuthClientID());

            result = getOpenIDTokenService().validateClaims(token, referenceClaims);
            if (result) {
                //proceed further
                //nonce
                result = getOpenIDTokenService().ifExistsThenValidate(token, OpenIDToken.TokenClaims.NONCE, mASM.getOAuthConnectionsUtil().getOpenIDNonce());
                if (result) {
                    //azp
                    result = getOpenIDTokenService().ifExistsThenValidate(token, OpenIDToken.TokenClaims.AUTHORIZATION_PARTY, idConfig.getOAuthClientID());
                }
            }
            return result;
        }
        return false;
    }

    private boolean isTokenValid(OpenIDToken token, boolean validateClaims) {
        boolean result = true;
        if (!token.isTokenExpired()) {
            OMLog.debug(TAG, "OpenId token not expired!");
            result = true;
            if (validateClaims) {
                result = validateClaims(token);
                OMLog.debug(TAG, "Validate claims result: " + result);
            }
            OMLog.debug(TAG, "validateOpenIDToken( validateClaims: " + true + ")" + " Result: " + result);
            return result;
        } else {
            OMLog.debug(TAG, "OpenID token is Expired");
            return false;
        }
    }

    private boolean isValidIdToken(OMAuthenticationContext authContext, boolean completeValidation) {
        OpenIDToken token = (OpenIDToken) authContext.getTokens().get(OpenIDToken.OPENID_CONNECT_TOKEN);
        if (token != null) {
            boolean result = isTokenValid(token, completeValidation);
            OMLog.debug(TAG, "isValid(IDToken) -> " + result);
            return result;
        }
        OMLog.debug(TAG, "No ID Token available");
        return true;
    }

    @Override
    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {

        if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.OPENIDCONNECT10) {
            boolean bAccessValid = isValidInternalAccessToken(authContext, validateOnline);//standard access token validation used in all OAuth services
            OMLog.debug(TAG, "Access token(s) valid : " + bAccessValid);
            boolean bIdValid = isValidIdToken(authContext, false);
            return bAccessValid && bIdValid;
        }
        OMLog.info(TAG, "isValid - Not an Open ID Use case!");
        return true;
    }

    @Override
    boolean isValid(OMAuthenticationContext authContext, Set<String> requiredScopes, boolean refreshExpiredToken) throws OMMobileSecurityException {
        if (super.isValid(authContext, requiredScopes, refreshExpiredToken)) {
            OMLog.debug(TAG, "Access token(s) valid : " + true);
            return isValidIdToken(authContext, false);//already the claims and signature is verified, we may change this behavior later, when its required.
        } else {
            OMLog.debug(TAG, "Access token(s) valid : " + false);
        }
        return false;
    }

    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd, boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
        if (authContext.getAuthenticationProvider() == OMAuthenticationContext.AuthenticationProvider.OPENIDCONNECT10) {
            OMLog.debug(TAG, "~logout~");
            URL logoutURL = mConfig.getLogoutUrl();
            if (isLogoutCall && logoutURL != null) {
                //invoke logout URL using logout handlers.
                handle3LeggedLogout(authContext, true);
                authContext.setOpenIdUserInfo(null);
            } else if (isDeleteTokens) {
                authContext.setOpenIdUserInfo(null);
                clearOAuthTokens(authContext, isLogoutCall);
                reportLogoutCompleted(mASM.getMSS(), isLogoutCall, (OMMobileSecurityException) null);
            }
        }
    }
}
