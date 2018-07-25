/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.provider.Settings;
import android.text.TextUtils;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import oracle.idm.mobile.OMAuthenticationRequest;
import oracle.idm.mobile.OMErrorCode;
import oracle.idm.mobile.OMMobileSecurityException;
import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.auth.logout.OMLogoutCompletionHandler;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMAuthenticationScheme;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMOICMobileSecurityConfiguration;
import oracle.idm.mobile.connection.OMHTTPRequest;
import oracle.idm.mobile.connection.OMHTTPResponse;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.crypto.CryptoScheme;
import oracle.idm.mobile.crypto.OMSecureStorageService;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.MOBILE_SECURITY_EXCEPTION;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY;

/**
 * This is the dynamic client registration service for the IDCS dynamic client.
 * This service can be used with any of the following:
 * OpenIDConnect
 * OAuth Authorization code
 * OAuth Resource owner flow
 * OAuth Client credentials.
 * <p>
 * The purpose of this service is :
 * </p>
 * Check if the client token is available for current config and passed login hint, If yes this service update the token params and update state to registration done.
 * <p>
 * If client assertion is not availble this is perform flows to obtain one and the update the tokens and update the state to registraion done.
 * </p>
 * Created by ajulka on 11/29/16.
 */

class IDCSClientRegistrationService extends OAuthAuthorizationCodeService {

    private static final String TAG = IDCSClientRegistrationService.class.getSimpleName();
    private static final String REGISTER_ENDPOINT = "oauth/v1/register";
    private static final String ANDROID_PACKAGE_NAME = "android_package_name";
    private static final String ANDROID_SIGNING_CERT_FINGERPRINT = "android_signing_cert_fingerprint";
    private static final String ANDROID_DEVICE_ID = "device_id";
    private OMOAuthMobileSecurityConfiguration mOAuthConfig;
    private OMSecureStorageService mSecureStorageService;

    IDCSClientRegistrationService(AuthenticationServiceManager asm, OMAuthenticationCompletionHandler loginHandler, OMLogoutCompletionHandler logoutHandler) {
        super(asm, loginHandler, logoutHandler);
        mOAuthConfig = (OMOAuthMobileSecurityConfiguration) asm.getMSS().getMobileSecurityConfig();
        isClientRegistration = true;
    }

    @Override
    public void collectLoginChallengeInput(Map<String, Object> inputParams, final ASMInputController inputController) {
        OMLog.info(TAG, "collectLoginChallengeInput");
        if (isChallengeInputRequired(inputParams)) {
            try {
                //FIXME Use oracle.idm.mobile.auth.webview.WebViewAuthServiceInputCallbackImpl instead of a new anonymous AuthServiceInputCallback
                mAuthCompletionHandler.createChallengeRequest(mASM.getMSS(), createLoginChallenge(), new AuthServiceInputCallback() {
                    @Override
                    public void onInput(Map<String, Object> inputs) {
                        inputController.onInputAvailable(inputs);
                    }

                    @Override
                    public void onError(OMErrorCode error) {
                        inputController.onInputError(error);
                    }

                    @Override
                    public void onCancel() {
                        inputController.onCancel();
                    }
                });
            } catch (OMMobileSecurityException e) {
                inputController.onInputError(OMErrorCode.INTERNAL_ERROR);
            }
        } else {
            inputController.onInputAvailable(inputParams);
        }
    }

    @Override
    public boolean isChallengeInputRequired(Map<String, Object> inputParams) {
        return /* we do not have client assertion */!isClientRegistrationTokenAvailable(inputParams) ||
                /* or we do not have a redirect response */!inputParams.containsKey(REDIRECT_RESPONSE_KEY) ||
                /* or we have a exception in the parmas */inputParams.containsKey(MOBILE_SECURITY_EXCEPTION);
    }

    private boolean isClientRegistrationTokenAvailable(Map<String, Object> inputParams) {

        boolean result = false;
        if (inputParams.containsKey(OMSecurityConstants.Param.IDCS_CLIENT_REGISTRATION_TOKEN)) {
            return true;
        }
        IDCSClientRegistrationToken token;
        try {
            token = getIDCSClientRegistrationToken(mOAuthConfig.getAuthenticationURL().toString(), mOAuthConfig.getLoginHint());
            if (token != null && !token.isTokenExpired()) {
                inputParams.put(OMSecurityConstants.Param.IDCS_CLIENT_REGISTRATION_TOKEN, token);
                result = true;
            }
        } catch (OMMobileSecurityException e) {
            OMLog.warn(TAG, "error while retrieving client token ", e);
        }
        return result;
    }

    private void onRegistrationSuccess(OMAuthenticationContext authenticationContext, IDCSClientRegistrationToken token) {
        //lets populate the params
        authenticationContext.getTokens().put(OMSecurityConstants.CLIENT_REGISTRATION_TOKEN, token);
        OMAuthenticationContext.Status status = (mOAuthConfig.getAuthenticationScheme() == OMAuthenticationScheme.OPENIDCONNECT10) ?
                OMAuthenticationContext.Status.OPENID_IDCS_CLIENT_REGISTRATION_DONE : OMAuthenticationContext.Status.OAUTH_IDCS_CLIENT_REGISTRATION_DONE;
        //lets remove code and redirect param if any
        authenticationContext.getInputParams().remove(OAuthConnectionsUtil.OAuthResponseParameters.CODE.getValue());
        authenticationContext.getInputParams().remove(OMSecurityConstants.Challenge.REDIRECT_RESPONSE_KEY);
        OMLog.debug(TAG, "~onClientRegistrationComplete~ setting status : " + status);
        authenticationContext.setStatus(status);
    }

    private void onRegistrationFailed(OMMobileSecurityException exception, OMAuthenticationContext authContext) {
        OMLog.error(TAG, "~onClientRegistrationFailed~ ");
        OMMobileSecurityException mobileException = new OMMobileSecurityException(
                OMErrorCode.IDCS_CLIENT_REGISTRATION_FAILED);
        authContext.setException(mobileException);
        authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
    }

    @Override
    public OMHTTPResponse handleAuthentication(OMAuthenticationRequest authRequest, OMAuthenticationContext authContext) throws OMMobileSecurityException {
        OMLog.debug(TAG, "~~handleAuthentication~~");
        OMOICMobileSecurityConfiguration oicConfig = (OMOICMobileSecurityConfiguration) mASM.getMSS().getMobileSecurityConfig();
        URL configEP = oicConfig.getConfigURL();
        String loginHint = oicConfig.getLoginHint();
        //lets first check if we have the client registration token ?
        IDCSClientRegistrationToken token = (IDCSClientRegistrationToken) authContext.getInputParams().get(OMSecurityConstants.Param.IDCS_CLIENT_REGISTRATION_TOKEN);
        if (token != null && !token.isTokenExpired()) {
            OMLog.debug(TAG, "Already have a valid client registration token for the user: " + loginHint);
            onRegistrationSuccess(authContext, token);
            return null;
        } else {
            OMLog.debug(TAG, "Do not have a valid client registration token for the user: " + loginHint + " Fetching a new one");
            //lets do the standard 3-legged flow to first get an access token for the register endpoint.
            super.handleAuthentication(authRequest, authContext);
            //lets check if we have the tokens
            OAuthToken atForReg = (OAuthToken) authContext.getInputParams().get(OMSecurityConstants.Param.IDCS_CLIENT_REGISTRATION_ACCESS_TOKEN);
            if (atForReg != null) {
                OMLog.debug(TAG, "Got the AT for the registration endpoint");

                //Make the request for registration

                try {
                    String registrationEP = oicConfig.getClientRegistrationEndpoint();
                    if (TextUtils.isEmpty(registrationEP)) {
                        OMLog.error(TAG, "Registration Endpoint not found in config. Please provide one.");
                        onRegistrationFailed(new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_INVALID_ENDPOINT), authContext);
                        return null;

                        //lets create one TODO

                        /*if (configEP != null) {

                            String url = null;
                            String configUrl = configEP.toString();
                            int len = configUrl.length();
                            if (configUrl.toLowerCase().contains(OMOICMobileSecurityConfiguration.WELL_KNOWN_CONFIGURATION)) {
                                url = configUrl.substring(0, (configUrl.indexOf('.') - 1)) + REGISTER_ENDPOINT;
                                registrationEP = new URL(url);
                            } else {
                                if (configUrl.toString().charAt(len - 1) == '/') {
                                    url = configUrl + REGISTER_ENDPOINT;
                                } else {
                                    url = configUrl + "/" + REGISTER_ENDPOINT;
                                }
                                registrationEP = new URL(url);
                            }
                            OMLog.debug(TAG, "Registration endpoint created : " + registrationEP);
                        } else {
                            OMLog.error(TAG, "Configuration Endpoint is not provided, so pass the registration EP in the configuration MAP");
                            //TODO error out
                            throw new OMMobileSecurityException(OMErrorCode.OPENID_AUTHENTICATION_FAILED);
                        }
                    }*/
                    }

                    //get client assertion

                    Map<String, String> headers = new HashMap<>();
                    headers.put("Authorization", "Bearer " + atForReg.getValue());
                    headers.put("Content-Type", OMSecurityConstants.ConnectionConstants.JSON_CONTENT_TYPE.getValue());
                    JSONObject payload = new JSONObject();
                    payload.put("client_id", oicConfig.getOAuthClientID());
                    Context appContext = mASM.getApplicationContext();
                    PackageManager pm = appContext.getPackageManager();
                    String packageName = appContext.getApplicationInfo().packageName;
                    payload.put(ANDROID_PACKAGE_NAME, packageName);

                    PackageInfo pInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                    Signature[] signatures = pInfo.signatures;
                    byte[] cert = signatures[0].toByteArray();
                    X509Certificate signingCert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(cert));
                    String fingerPrint = OMCertificateService.getFingerPrint(signingCert, CryptoScheme.SHA512);
                    payload.put(ANDROID_SIGNING_CERT_FINGERPRINT, fingerPrint);
                    payload.put(ANDROID_DEVICE_ID, Settings.Secure.getString(appContext.getContentResolver(),
                            Settings.Secure.ANDROID_ID));
                    if (enableReqResVerbose) {
                        OMLog.debug(TAG, "Payload for client registration : " + payload);
                    }
                    OMHTTPResponse regResponse = mASM.getMSS().getConnectionHandler().httpPost(new URL(registrationEP), headers, payload.toString(), OMSecurityConstants.ConnectionConstants.JSON_CONTENT_TYPE.getValue(),
                            (OMHTTPRequest.REQUIRE_RESPONSE_CODE | OMHTTPRequest.REQUIRE_RESPONSE_STRING));
                    if (regResponse != null && regResponse.isSuccess()) {
                        OMLog.debug(TAG, "Response Code from Registration EP: " + regResponse.getResponseCode());
                        String clientAssertion = regResponse.getResponseStringOnSuccess();
                        if (enableReqResVerbose) {
                            OMLog.debug(TAG, "Response: " + clientAssertion);
                        }
                        IDCSClientRegistrationToken newToken = new IDCSClientRegistrationToken(clientAssertion);
                        if (!newToken.isTokenExpired()) {
                            OMLog.info(TAG, "A valid client registration token is available now.");
                            onRegistrationSuccess(authContext, newToken);
                            return null;
                        } else {
                            OMLog.error(TAG, "Received invalid or null IDCS Client Registration Token");
                            onRegistrationFailed(new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_FAILED), authContext);
                            return null;
                        }

                    } else {
                        String reason = "Response from server is null or not OK";
                        if (regResponse != null) {
                            reason = regResponse.getResponseStringOnFailure();
                        }
                        OMLog.error(TAG, reason);
                        onRegistrationFailed(new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_FAILED), authContext);
                    }
                } catch (JSONException | MalformedURLException | PackageManager.NameNotFoundException e) {
                    OMLog.error(TAG, e.getMessage(), e);
                    OMMobileSecurityException mobileException = new OMMobileSecurityException(
                            OMErrorCode.OPENID_AUTHENTICATION_FAILED);
                    authContext.setException(mobileException);
                    authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
                } catch (CertificateException e) {
                    e.printStackTrace();
                }

            } else {
                OMLog.error(TAG, "Unable to obtain access token for the registration service");
                OMMobileSecurityException exception = new OMMobileSecurityException(OMErrorCode.IDCS_CLIENT_REGISTRATION_UNABLE_TO_OBTAIN_AT);
                authContext.setException(exception);
                authContext.setStatus(OMAuthenticationContext.Status.FAILURE);
            }
        }

        return null;
    }


    @Override
    public void logout(OMAuthenticationContext authContext, boolean isDeleteUnPwd,
                       boolean isDeleteCookies, boolean isDeleteTokens, boolean isLogoutCall) {
        OMAuthenticationContext.AuthenticationProvider authenticationProvider = authContext.getAuthenticationProvider();
        if (mOAuthConfig.isClientRegistrationRequired()) {
            OMLog.debug(TAG, "~.~logout~.~");
            boolean needLogoutHandler = false;
            if (isLogoutCall && mOAuthConfig.getOAuthzGrantType() != OAuthAuthorizationGrantType.AUTHORIZATION_CODE) {
                //Do logout URL invocation only it is any grant other than the AuthZ Code grant.
                //if it is authZ grant the OAuthAuthorizationCode service would already have invoked the external browser.
                final URL logoutURL = mConfig.getLogoutUrl();
                if (logoutURL != null) {
                    needLogoutHandler = true;
                    handle3LeggedLogout(authContext, false);
                }
            }
            if (isDeleteUnPwd) {
                removeIDCSClientRegistrationToken(mOAuthConfig.getAuthenticationURL().toString(), mOAuthConfig.getLoginHint());
            }
        }
    }

    void removeIDCSClientRegistrationToken(String configURL, String loginHint) {
        OMCredentialStore credService = mASM.getMSS().getCredentialStoreService();
        credService.remove(configURL + "_" + loginHint);
        OMLog.debug(TAG, "Removed IDCS ClientRegistration Token for user: " + loginHint + " from Store!");
    }

    void storeIDCSClientRegistrationToken(String configURL, String loginHint, IDCSClientRegistrationToken token) {

        OMCredentialStore credService = mASM.getMSS().getCredentialStoreService();
        credService.putString(configURL + "_" + loginHint, token.toString());
        OMLog.debug(TAG, "Stored IDCS ClientRegistration Token for user: " + loginHint + " to the Store!");
    }

    @Override
    public boolean isValid(OMAuthenticationContext authContext, boolean validateOnline) {
        if (mOAuthConfig.isClientRegistrationRequired()) {
            boolean result;
            IDCSClientRegistrationToken token = null;
            try {
                if (authContext.getTokens().containsKey(OMSecurityConstants.CLIENT_REGISTRATION_TOKEN)) {
                    token = (IDCSClientRegistrationToken) authContext.getTokens().get(OMSecurityConstants.CLIENT_REGISTRATION_TOKEN);
                } else {
                    //check if we have the token in the store?
                    token = getIDCSClientRegistrationToken(mOAuthConfig.getAuthenticationURL().toString(), mOAuthConfig.getLoginHint());
                }
                result = (token != null && !token.isTokenExpired());
            } catch (OMMobileSecurityException e) {
                OMLog.error(TAG, "Error retrieving client token from store ", e);
                result = false;
            }
            OMLog.debug(TAG, "~.~isValid~.~: " + result);
            return result;
        }
        return true;
    }

    IDCSClientRegistrationToken getIDCSClientRegistrationToken(String configURL, String loginHint) throws OMMobileSecurityException {
        OMCredentialStore credService = mASM.getMSS().getCredentialStoreService();
        String tokenString = credService.getString(configURL + "_" + loginHint);
        if (!TextUtils.isEmpty(tokenString)) {
            IDCSClientRegistrationToken token = new IDCSClientRegistrationToken(tokenString);
            OMLog.debug(TAG, "Retrieved IDCS client registration token for user: " + loginHint);
            return token;
        } else {
            OMLog.debug(TAG, "IDCS client registration token for user : " + loginHint + " not found in store.");
        }
        return null;
    }
}

