/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Build;
import android.util.Log;

import org.json.JSONException;

import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.auth.AuthServiceInputCallback;
import oracle.idm.mobile.auth.AuthenticationServiceManager;
import oracle.idm.mobile.auth.OAuthConnectionsUtil;
import oracle.idm.mobile.auth.OMAuthenticationChallenge;
import oracle.idm.mobile.auth.OMAuthenticationChallengeType;
import oracle.idm.mobile.auth.OMAuthenticationCompletionHandler;
import oracle.idm.mobile.auth.OMAuthenticationContext;
import oracle.idm.mobile.auth.RCUtility;
import oracle.idm.mobile.auth.TimeoutManager;
import oracle.idm.mobile.auth.local.OMAuthData;
import oracle.idm.mobile.auth.local.OMAuthenticationManagerException;
import oracle.idm.mobile.auth.local.OMAuthenticator;
import oracle.idm.mobile.auth.local.OMDefaultAuthenticator;
import oracle.idm.mobile.auth.openID.OpenIDTokenService;
import oracle.idm.mobile.callback.OMAuthenticationContextCallback;
import oracle.idm.mobile.callback.OMMobileSecurityServiceCallback;
import oracle.idm.mobile.certificate.ClientCertificatePreference;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.configuration.OAuthAuthorizationGrantType;
import oracle.idm.mobile.configuration.OMAuthenticationScheme;
import oracle.idm.mobile.configuration.OMConnectivityMode;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration.BrowserMode;
import oracle.idm.mobile.configuration.OMMobileSecurityConfiguration.HostnameVerification;
import oracle.idm.mobile.configuration.OMOAuthMobileSecurityConfiguration;
import oracle.idm.mobile.connection.CBAExceptionEvent;
import oracle.idm.mobile.connection.OMConnectionHandler;
import oracle.idm.mobile.connection.OMCookieManager;
import oracle.idm.mobile.connection.SSLExceptionEvent;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.crypto.OMCryptoService;
import oracle.idm.mobile.crypto.OMKeyManagerException;
import oracle.idm.mobile.crypto.OMKeyStore;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.util.DefaultAuthenticationUtils;

/**
 * OMMobileSecurityService class is the top-level class which provides Security
 * Service.
 * <p/>
 * <p>
 * This class can be instantiated through the various constructors supported.
 * </p>
 * <p>
 * The call to methods {@link #setup()} and {@link #authenticate()} are
 * asynchronous and response from this call will be sent back to the calling
 * application through the {@link OMMobileSecurityServiceCallback} instance that is
 * registered during instantiation.
 * </p>
 * <p/>
 * <p>
 * The call to {@link #authenticate()} api should be invoked only after the
 * {@link #setup()} response is received.
 * </p>
 *
 * @since 11.1.2.3.1
 */
public class OMMobileSecurityService {
    /**
     * This represents the type of the server. The value for this can be taken
     * from {@link AuthServerType} Enum.
     */
    public static final String OM_PROP_AUTHSERVER_TYPE = "AuthServerType";
    /**
     * This represents the name of the application. In case of authentication
     * using Mobile & Social server, this should be the name of the application
     * that is configured in the Mobile and Social server. The value should be
     * of type {@link String}.
     */
    public static final String OM_PROP_APPNAME = "ApplicationName";
    /**
     * This represents a {@link Boolean} value in which true represents that the
     * offline authentication is allowed for this application, false represents
     * that the offline authentication is not allowed.
     */
    public static final String OM_PROP_OFFLINE_AUTH_ALLOWED = "OfflineAuthAllowed";
    /**
     * This represents the authentication server {@link java.net.URL} instance which
     * should be used for performing HttpBasic/Federated authentication.
     */
    public static final String OM_PROP_LOGIN_URL = "LoginURL";
    /**
     * This represents the logout {@link java.net.URL} instance that will be invoked when
     * the application wants to logout from the server.
     */
    public static final String OM_PROP_LOGOUT_URL = "LogoutURL";
    /**
     * This represents the session timeout value of type {@link Integer}. The
     * unit for this is in seconds.
     */
    public static final String OM_PROP_SESSION_TIMEOUT_VALUE = "SessionTimeOutValue";
    /**
     * This represents the default protocols used by the client socket during a
     * SSL handshake. The value should of type {@link String[]}.
     * <p>
     * e.g: map.put(OMMobileSecurityService.OM_PROP_DEFAULT_PROTOCOL_FOR_CLIENT_SOCKET,
     * new String[]{"TLSv1.1", "TLSv1.2"});
     *
     * @hide
     */
    public static final String OM_PROP_DEFAULT_PROTOCOL_FOR_CLIENT_SOCKET = "DefaultProtocolsForClientSocket";
    /**
     * This represents the enabled cipher suites for SSL/TLS connections. The
     * value should of type {@link String[]}. Some cipher suites are disabled
     * by default. If you want enable them, provide the same along with the complete
     * list of cipher suites to be enabled.
     *
     * @hide
     * @see <a href="https://developer.android.com/reference/javax/net/ssl/SSLSocket.html">
     * SSL Socket</a>
     */
    public static final String OM_PROP_ENABLED_CIPHER_SUITES = "EnabledCipherSuites";
    /**
     * This represents the idle timeout value of type {@link Integer}. The unit
     * for this is in seconds.
     */
    public static final String OM_PROP_IDLE_TIMEOUT_VALUE = "IdleTimeOutValue";
    /**
     * This represents the percentage of idle timeout before which advance notification is sent.
     * the unit for is in percentage.
     */
    public static final String OM_PROP_PERCENTAGE_TO_IDLE_TIMEOUT = "PercentageToIdleTimeout";
    /**
     * This represents the logout timeout value of type {@link Integer}. The
     * unit for this is in seconds. If the logout is not completed with a server
     * within this time interval, the tokens will be cleared at the client side.
     */
    public static final String OM_PROP_LOGOUT_TIMEOUT_VALUE = "LogoutTimeOutValue";
    /**
     * This represents the maximum number of login failure attempts that is
     * allowed at any given time. The value should be of type {@link Integer}.
     */
    public static final String OM_PROP_MAX_LOGIN_ATTEMPTS = "MaxLoginAttempts";
    /**
     * This represents the {@link java.util.Set}&lt;{@link String}&gt; values that
     * contains names of the tokens that the application is expecting as a
     * result of authentication.
     */

    public static final String OM_PROP_REQUIRED_TOKENS = "RequiredTokens";
    /**
     * This represents the hashing/encryption algorithm that will be used for
     * hashing/encrypting the password that is stored in the credential store to
     * support offline authentication. The value should be of type
     * {@link oracle.idm.mobile.crypto.CryptoScheme}.
     */
    public static final String OM_PROP_CRYPTO_SCHEME = "CryptoScheme";
    /**
     * This represents whether identity domain is to be collected from the user
     * during HttpBasic authentication against a cloud setup. If it set, the
     * default view shown by SDK will contain an EditText to collect identity
     * domain. The value should be of type {@link Boolean}.
     */
    public static final String OM_PROP_COLLECT_IDENTITY_DOMAIN = "CollectIdentityDomain";
    /**
     * This represents the authentication key that should be used to store the
     * resultant of authentication in the credential store. The value should be
     * of type {@link String}.
     */
    public static final String OM_PROP_AUTH_KEY = "AuthKey";
    /**
     * This represents how authentication should happen, i.e. whether
     * authentication should be always done online/offline; or it should happen
     * online/offline depending on network connectivity. The value should of
     * type {@link OMConnectivityMode}.
     */
    public static final String OM_PROP_CONNECTIVITY_MODE = "ConnectivityMode";
    /**
     * This represents the identity domain name. Alternatively , you can use the
     * following methods :
     * {@link OMMobileSecurityConfiguration#setIdentityDomain(String)}
     * {@link OMAuthenticationRequest.Builder#setIdentityDomain(String)}. Please note
     * that these methods will take precedence over the values passed in the
     * MAP.
     */
    public static final String OM_PROP_IDENTITY_DOMAIN_NAME = "identityDomain";
    /**
     * This represents whether identity domain is sent as header value or its
     * simply prepended with the user name. The default behavior is to prepend
     * the user name with the given identity domain in the format
     * identity_domain_name.user_name. The value should be of type
     * {@link Boolean}.
     */
    public static final String OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER = "IdentityDomainNameInHeader";
    /**
     * This represents the header name used to send the identity domain. This
     * will be used only if the property
     * {@link OMMobileSecurityService#OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER} is
     * passed as true. Please note if no value is specified in this property the
     * default value X-USER-IDENTITY-DOMAIN-NAME will be used as header name.
     */
    public static final String OM_PROP_IDENTITY_DOMAIN_HEADER_NAME = "IdentityDomainHeaderName";
    /**
     * This represents whether external browser or embedded browser should be
     * used during authentication (e.g: {@link AuthServerType#OpenIDConnect10},
     * {@link AuthServerType#OAuth20}, {@link AuthServerType#FederatedAuth}).
     * The value should be of type {@link BrowserMode}.
     */
    public static final String OM_PROP_BROWSER_MODE = "BrowserMode";
    /**
     * This represents the url to which the server will be redirected to after
     * successful login in case of federated authentication. The value can be
     * either of type {@link java.net.URL} or {@link String}.
     */
    public static final String OM_PROP_LOGIN_SUCCESS_URL = "LoginSuccessURL";
    /**
     * This represents the url to which the server will be redirected to after
     * unsuccessful login in case of federated authentication. The value can be
     * either of type {@link java.net.URL} or {@link String}.
     */
    public static final String OM_PROP_LOGIN_FAILURE_URL = "LoginFailureURL";

    /**
     * This represents the possible set of names (HTML attribute: name) for the
     * input element corresponding to user name in Federated Authentication (
     * {@link AuthServerType#FederatedAuth}) login page. The value for this
     * configuration property should be given as a {@link Set}&lt;{@link String}
     * &gt;. Empty string or null is not accepted as one of the values.
     */
    public static final String OM_PROP_USERNAME_PARAM_NAME = "FedAuthUsernameParamName";

    /**
     * This represents the url to which the server redirects after logout is successful.
     * This is currently used only in case of {@link AuthServerType#FederatedAuth}.
     * The value can be either of type {@link java.net.URL} or {@link String}.
     */
    public static final String OM_PROP_LOGOUT_SUCCESS_URL = "LogoutSuccessURL";
    /**
     * This represents the url to which the server redirects when logout fails or
     * is cancelled by end-user. This is currently used only in case of
     * {@link AuthServerType#FederatedAuth}. The value can be either of type
     * {@link java.net.URL} or {@link String}.
     * <p><b>Note:</b> When this url is hit, all session cookies are cleared. </p>
     */
    public static final String OM_PROP_LOGOUT_FAILURE_URL = "LogoutFailureURL";
    /**
     * Logout consent screen can be enabled on some servers (e.g OAM). If it is enabled
     * on server, during logout in case of {@link AuthServerType#FederatedAuth}, SDK can
     * programmatically click on Confirm logout button if this boolean property is set to
     * true. The value should be of type {@link Boolean}.
     */
    public static final String OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY = "ConfirmLogoutAutomatically";
    /**
     * If {@link OMMobileSecurityService#OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY} is set to
     * true, then SDK assumes the id of the confirm logout button to be "Confirm".
     * If it is something else, the possible ids MUST be provided here. The value for this
     * configuration property should be given as a {@link Set}&lt;{@link String}
     * &gt;. Empty string or null is not accepted as one of the values.
     */
    public static final String OM_PROP_CONFIRM_LOGOUT_BUTTON_ID = "ConfirmLogoutButtonId";

    /**
     * This represents if all session cookies should be removed locally after
     * logout is done. Logout typically involves loading a logout url which will
     * clear session on server side as well as clear the corresponding cookies
     * on client side by virtue of server sending Set-Cookie response headers.
     * So, normally setting this property is not required. If there is some
     * issue with logout url clearing the cookies on client side, this property
     * can be set temporarily for working around the issue. The value should be
     * of type {@link Boolean}.
     * <p>
     * Note: This is not honoured in case authentication (e.g:
     * {@link AuthServerType#OpenIDConnect10}), {@link AuthServerType#OAuth20} is
     * done using {@link BrowserMode#EXTERNAL} as cookies are not present in the
     * app's cookie store.
     * <p>
     * If you maintain multiple {@link OMMobileSecurityService} instances for
     * maintaining multiple sessions with different servers, and if you have
     * issues with a logout url as mentioned above, then call
     * {@link OMCookieManager#removeSessionCookies(Context)} in
     * {@link OMMobileSecurityServiceCallback#onLogoutCompleted(OMMobileSecurityService, OMMobileSecurityException)}
     * after logging out of all instances. The above code snippet is the
     * recommended approach for apps which maintain multiple sessions because
     * with this property, logging out of one session maintained by one
     * {@link OMMobileSecurityService}, will lead to removal of cookies meant
     * for other instances as well.
     */
    public static final String OM_PROP_REMOVE_ALL_SESSION_COOKIES = "RemoveAllSessionCookies";

    // RC
    /**
     * This represents whether auto-login feature is allowed for the current
     * instance of {@link OMMobileSecurityService} . Having this property
     * enabled will show the auto login check box in the default login screen.
     * However in case of custom view the visibility is not controlled by the
     * SDK. If the user selects the auto login option from the UI , then in
     * subsequent calls to authenticate() will silently login the user with out
     * asking the credentials . The SDK will persist the auto login credentials
     * by encrypting it with 256 bit key using {@link oracle.idm.mobile.crypto.CryptoScheme#AES}
     * algorithm. Please note : the auto login credentials will be removed from
     * the device when a)Logout with forget device true is called
     * {@link OMMobileSecurityService#logout(boolean)}, b)session time out in
     * case of HTTP Basic authentication , c)If there is authentication failure
     * during authentication with auto login enabled .
     */
    public static final String OM_PROP_AUTO_LOGIN_ALLOWED = "AutoLoginAllowed";
    /**
     * This represents whether remember user name feature is allowed for the
     * current instance of {@link OMMobileSecurityService} . Having this
     * property enabled will show the remember user name check box in the
     * default login screen. However, in case of custom view the visibility is
     * not controlled by the SDK. If the user selects the remember username
     * option from the UI , then in subsequent calls to authenticate() , the
     * login screen will be pre-populated with the username saved during last
     * successful authentication. Please note : the username will be removed
     * from the device when a)Logout with forget device true is called
     * {@link OMMobileSecurityService#logout(boolean)} , b)session time out in
     * case of HTTP Basic authentication , c)If there is authentication failure
     * occurred .
     */
    public static final String OM_PROP_REMEMBER_USERNAME_ALLOWED = "RememberUsernameAllowed";
    /**
     * This represents whether remember credentials feature is allowed for the
     * current instance of {@link OMMobileSecurityService} . Having this
     * property enabled will show the remember credentials check box in the
     * default login screen. However in case of custom view the visibility is
     * not controlled by the SDK. If the user selects the remember credentials
     * option from the UI , then in subsequent calls to authenticate() , the
     * login screen will be pre-populated with the username and password saved
     * during last successful authentication. The SDK will persist the user
     * credentials by encrypting it with 256 bit key using
     * {@link oracle.idm.mobile.crypto.CryptoScheme#AES} algorithm. Please note : the user credentials
     * will be removed from the device when a)Logout with forget device true is
     * called{@link OMMobileSecurityService#logout(boolean)} , b)session time
     * out in case of HTTP Basic authentication , c)If there is authentication
     * failure occurred .
     */
    public static final String OM_PROP_REMEMBER_CREDENTIALS_ALLOWED = "RememberCredentialsAllowed";
    /**
     * If {@link OMMobileSecurityService#OM_PROP_AUTO_LOGIN_ALLOWED} property is
     * set then this flags represents the default value for the auto-login check
     * box . The state of the check box is controlled by the SDK. Please note:
     * If user checks/unchecks the auto login check box it will take precedence
     * over the default values set and subsequent authentication calls will
     * depend on whether the user has checked / unchecked the auto login check
     * box. The user preference for the check box state will be persisted by the
     * sdk internally .
     */
    public static final String OM_AUTO_LOGIN_DEFAULT = "AutoLoginDefault";
    /**
     * If {@link OMMobileSecurityService#OM_PROP_REMEMBER_USERNAME_ALLOWED}
     * property is set then this flags represents the default value for the
     * remember user name check box . The state of the check box is controlled
     * by the SDK. Please note: If user checks/unchecks the auto login check box
     * it will take precedence over the default values set and subsequent
     * authentication calls will depend on whether the user has checked /
     * unchecked the remember username check box. The user preference for the
     * check box state will be persisted by the sdk internally .
     */
    public static final String OM_REMEMBER_USERNAME_DEFAULT = "RememberUsernameDefault";
    /**
     * If {@link OMMobileSecurityService#OM_PROP_REMEMBER_CREDENTIALS_ALLOWED}
     * property is set then this flags represents the default value for the
     * remember credentials check box . The state of the check box is controlled
     * by the SDK. Please note: If user checks/unchecks the auto login check box
     * it will take precedence over the default values set and subsequent
     * authentication calls will depend on whether the user has checked /
     * unchecked the remember credentials check box. The user preference for the
     * check box state will be persisted by the sdk internally .
     */
    public static final String OM_REMEMBER_CREDENTIALS_DEFAULT = "RememberCredentialDefault";

    // RC

    // OAuth

    /**
     * This represents the Authorization end-point of the OAuth2.0 server
     * returned after the client/application registration. In general the
     * authorization end-point is used to interact with the resource owner and
     * obtain an authorization grant . The client SDK use this to obtain
     * authorization from the resource owner via user-agent redirection. The
     * value can be either of type {@link URL} or {@link String}.
     */
    public static final String OM_PROP_OAUTH_AUTHORIZATION_ENDPOINT = "OAuthAuthorizationEndpoint";

    /**
     * This represents the Token end-point of the OAuth2.0 server returned after
     * the client/application registration. The token end-point is used by the
     * client SDK to obtain an access token by presenting its authorization
     * grant or refresh token. The token end-point is used with every
     * authorization grant except for the implicit grant type (since an access
     * token is issued directly). The value can be either of type {@link URL} or
     * {@link String}.
     */
    public static final String OM_PROP_OAUTH_TOKEN_ENDPOINT = "OAuthTokenEndpoint";
    /**
     * This represent the Redirection end-point of the client application . The
     * SDK after completing its interaction with the resource owner, the
     * authorization server directs the resource owner's user-agent back to the
     * client application. The authorization server redirects the user-agent to
     * the client's redirection endpoint previously established with the
     * authorization server during the client registration process or when
     * making the authorization request.
     */
    public static final String OM_PROP_OAUTH_REDIRECT_ENDPOINT = "OAuthRedirectEndpoint";
    /**
     * This represents the the client-id generated by the OAuth2.0 authorization
     * server after client registration process. The Client ID is a unique
     * string generated by the Authorization server on behalf of client . The
     * Client ID can not be used as a client secret.This client ID is per
     * authorization server. The value can be of type {@link String}.
     */
    public static final String OM_PROP_OAUTH_CLIENT_ID = "OAuthClientID";

    /**
     * This represents the client secret for a confidential client. The value
     * can be of type {@link String} which can be found/generated after client
     * registration with the OAuth2.0 authorization server .
     */
    public static final String OM_PROP_OAUTH_CLIENT_SECRET = "OAuthClientSecret";
    /**
     * This represents the set of scopes that the application can get access to
     * . This field is mandatory for OAuth2.0
     * {@link OAuthAuthorizationGrantType#AUTHORIZATION_CODE} and
     * {@link OAuthAuthorizationGrantType#IMPLICIT} . Note the Authorization
     * server validates the scope at request level and compares the scopes asked
     * by client in the request with the scopes mentioned during client
     * registration, If the scope asked are greater than the defined scopes then
     * the Authorization server will throw an exception . The value can be of
     * type {@link Set} &lt;{@link String}&gt;.
     */
    public static final String OM_PROP_OAUTH_SCOPE = "OAuthScope";
    /**
     * The authorization is expressed in the form of an authorization grant,
     * which the client uses to request the access token. The value should be of
     * type {@link OAuthAuthorizationGrantType}.This is a mandatory field for
     * OAuth2.0 based authorization . Presently the SDK supports only
     * {@link OAuthAuthorizationGrantType#AUTHORIZATION_CODE} and
     * {@link OAuthAuthorizationGrantType#IMPLICIT} .
     */
    public static final String OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE = "OAuthAuthorizationGrantType";
    /**
     * /**
     * This property represents the value of the JWT client assertion to be used
     * in the OAuth flows.
     */
    public static final String OM_PROP_OAUTH_CLIENT_ASSERTION_SAML2 = "OAuthSAML2ClientAssertionValue";
    /**
     * This property represents the value of the SAML2 client assertion to be
     * used in the OAuth flows.
     */
    public static final String OM_PROP_OAUTH_CLIENT_ASSERTION_JWT = "OAuthJWTClientAssertionValue";
    /**
     * This property represents weather the client authorization header needs to
     * be sent in the request for access token. The default behavior is to
     * always send the client authorization header for confidential clients(
     * possessing client secret). However, the application can specify this
     * property to send the authorization header for other client types as well.
     * The value should be of type {@link Boolean}.
     */
    public static final String OM_PROP_OAUTH_INCLUDE_CLIENT_AUTH_HEADER = "OAuthIncludeClientAuthHeader";

    /**
     * This property represents if the application wants to enable PKCE(proof of key exchange) feature while doing the AUTHORIZATION_CODE grant flow.
     */
    public static final String OM_PROP_OAUTH_ENABLE_PKCE = "OAuthEnablePKCE";

    /**
     * This represents the custom HTTP headers which should be added to the HTTP
     * request being made to the server in case of HTTP Basic authentication.
     * (Key, value) pair should be like (HTTP header name, corresponding value).
     * The following HTTP headers are prohibited to be specified here:
     * Authorization, Cookie, Content-Length, Host.
     */
    public static final String OM_PROP_CUSTOM_AUTH_HEADERS = "CustomAuthHeaders";

    /**
     * This represents the custom user agent header to be sent during form-based
     * authentication. The value should be of type {@link String}.
     */
    public static final String OM_PROP_CUSTOM_USER_AGENT_HEADER = "CustomUserAgentHeader";
    /**
     * This represents the timeout for form-based authentication of type
     * {@link Integer}. The unit for this is in seconds.
     */
    public static final String OM_PROP_LOGIN_TIMEOUT_VALUE = "AuthTimeOutVal";

    /**
     * This property enables/disables the SDK's behavior to persist the
     * authentication context. By default SDK's behavior is not to persist the
     * authentication context, due to which the application/user is required to
     * authenticate again after application restart/crash.This is upto the
     * application developer to provide the value <code>true</code> if the app
     * wants to keep the session active/ persist the authentication context,
     * otherwise its <code>false</code> by default.
     */
    public static final String OM_PROP_SESSION_ACTIVE_ON_RESTART = "SessionActiveOnRestart";
    /**
     * This property enables/disables the support for Client Certificate based
     * Authentication. The default behavior is to ignore any client certificate
     * challenge during SSL handshake. The value <code>true</code> means that
     * the client certificate challenge by server during any network request
     * will be handled by the connection handler. The expected value should be
     * of type {@link Boolean} other wise neglected.
     */
    public static final String OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND = "PresentClientCertificate";

    /**
     * This property represents the custom headers to be used by mobile agent.
     * The valid value can be a {@link Map}. The keys should be of type
     * {@link String} representing the header names and the values should be of
     * type {@link String} representing header values.
     *
     * @hide
     */
    // MAF Internal
    public static final String OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT = "CustomHeadersForMobileAgent";

    /**
     * This property represents the MAF application's preference to send the
     * Identity domain along with other credentials.
     *
     * @hide
     */
    // MAF Internal
    public static final String OM_PROP_SEND_IDENTITY_DOMAIN_HEADER_TO_MOBILE_AGENT = "IdentityDomainHeaderToMobileAgent";

    /**
     * This property if enabled sends the headers supplied to SDK using property
     * {@link OMMobileSecurityService#OM_PROP_CUSTOM_AUTH_HEADERS} in the logout
     * operation. Note that if the identity domain is available and the property
     * {@link OMMobileSecurityService#OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER} is
     * enabled then the same will be included with other custom auth headers and
     * sent during logout operation.
     *
     * @hide
     */
    // MAF & MCS Internal
    public static final String OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT = "SendCustomAuthHeadersInLogout";

    /**
     * This property if enabled will send the authorization header in format:
     * Base64 encoded username:pwd in the logout request in Http Basic
     * Authentication. Note that this will work only if the application has
     * enabled Offline Authentication using property
     * {@link OMMobileSecurityService#OM_PROP_OFFLINE_AUTH_ALLOWED} and the
     * Crypto Scheme is provided as AES using property
     * {@link OMMobileSecurityService#OM_PROP_CRYPTO_SCHEME= CryptoScheme#AES}.
     * If any of the above is not provided then the authorization header will
     * not be sent during the logout request.
     *
     * @hide
     */
    // MAF and MCS Inernal
    public static final String OM_PROP_SEND_AUTHORIZATION_HEADER_IN_LOGOUT = "SendAuthorizationHeaderInLogout";

    /**
     * This property accepts {@link Boolean} value and is applicable only for
     * Web SSO. True indicates that the loginSuccessUrl content should be parsed
     * to obtain OAuth access token. False indicates that no parsing is
     * required.
     */
    public static final String OM_PROP_PARSE_TOKEN_RELAY_RESPONSE = "ParseTokenRelayResponse";

    /**
     * This property is used to provide openID discovery URL.
     */
    public static final String OM_PROP_OPENID_CONNECT_CONFIGURATION_URL = "OpenIDConnectDiscoveryURL";

    public static final String OM_PROP_OPENID_CONNECT_CONFIGURATION = "OpenIDConnectConfiguration";

    /**
     * If the application uses {@link AuthServerType#OpenIDConnect10} as its authentication server type then this property can be used to provide the login hint or the user name for which the authentication is required.
     * If the application is a single user application, then this property can be avoided.
     * <p>
     * If the application has already authenticated for a user once and have a multiple user support, then the application can send the user name for which the subsequent authentication is carried.
     * Logged in username can be obtained from {@link OMAuthenticationContext#getOpenIDUserInfo()} after successful authentication.
     */
    public static final String OM_PROP_LOGIN_HINT = "LoginHint";

    /**
     * This property can be used to specify if the client needs to be registered dynamically.
     * <p>
     * This property accepts {@link Boolean}.
     */
    public static final String OM_PROP_IDCS_REGISTER_CLIENT = "IDCSRegisterClient";

    /**
     * This property is used to specify the registration endpoint.
     */
    public static final String OM_PROP_IDCS_REGISTER_ENDPOINT = "IDCSRegisterEndpoint";


    /**
     * The local authenticator name which is used for app-level authentication (PIN, etc.)
     * must be passed here. This is used to store authentication related data securely.
     */
    public static final String OM_PROP_LOCAL_AUTHENTICATOR_NAME = "localAuthenticatorName";

    /**
     * The local authenticator instance id which is used for app-level authentication (PIN, etc.)
     * must be passed here. This is used to store authentication related data securely.
     */
    public static final String OM_PROP_LOCAL_AUTHENTICATOR_INSTANCE_ID = "localAuthenticatorInstanceId";
    /**
     * This property represents service profile download end-point for the OAuth
     * mobile clients configured with OAM OAuth Server.
     */
    public static final String OM_PROP_OAM_OAUTH_SERVICE_ENDPOINT = "OAMOAuthServiceEndpoint";
    /**
     * This represents whether location details have to collected from the
     * device for sending it to Mobile & Social server. The value should be of
     * type {@link Boolean}.
     */
    public static final String OM_PROP_LOCATION_UPDATE_ENABLED = "LocationUpdateEnabled";

    /**
     * This property accepts {@link HostnameVerification} value and is
     * applicable for all authentication flows. How hostname verification is to
     * be done is specified by this property. The default value for this
     * property is {@link HostnameVerification#ALLOW_ALL}.
     */
    public static final String OM_PROP_HOSTNAME_VERIFICATION = "HostnameVerification";

    /**
     * This lists down the authentication types supported by the SDK. This should be given as input against
     * OM_PROP_AUTHSERVER_TYPE in {@link OMMobileSecurityService} map-based constructor.
     */
    public enum AuthServerType {
        HTTPBasicAuth("HTTPBasicAuthentication"),
        /**
         * Federated authentication involving SP and IDP.
         * <p/>
         * Note: Client certificate authentication in embedded browser [Fed Auth, OAuth] is supported only from LOLLIPOP onwards.
         * So, any app which needs client certificate authentication MUST either
         * 1. Have minSdkVersion as 21 if CBA is the only authentication mechanism for the app
         * 2. Have runtime check NOT to use CBA [in Fed Auth, OAuth] for versions below Android 5.0.
         * This can be achieved by having a separate SDK configuration [Basic auth /Form based authentication during federation instead of CBA]
         * for versions below Android 5.0.
         * <p>
         * Note: {@link BrowserMode#EXTERNAL} is not supported currently.
         */
        FederatedAuth("FederatedAuthentication"),
        /**
         * OAuth2.0 as per RFC 6749
         * <p/>
         * Note: Client certificate authentication in embedded browser [Fed Auth, OAuth] is supported only from LOLLIPOP onwards.
         * So, any app which needs client certificate authentication MUST either
         * 1. Have minSdkVersion as 21 if CBA is the only authentication mechanism for the app
         * 2. Have runtime check NOT to use CBA [in Fed Auth, OAuth] for versions below Android 5.0.
         * This can be achieved by having a separate SDK configuration [[Basic auth /Form based authentication during federation instead of CBA]]
         * for versions below Android 5.0.
         */
        OAuth20("OAuthAuthentication"),
        CBA("CertificateBasedAuthentication"),
        OpenIDConnect10("OpenIDConnect10");

        private String value;

        AuthServerType(String value) {
            this.value = value;
        }

        public static AuthServerType valueOfAuthServerType(String authServerType) {
            for (AuthServerType authServerTypeEnum : values()) {
                if (authServerTypeEnum.value.equalsIgnoreCase(authServerType)) {
                    return authServerTypeEnum;
                }
            }
            return null;
        }

        public String getValue() {
            return value;
        }

    }

    private static final String TAG = OMMobileSecurityService.class.getSimpleName();
    private static boolean authenticateCalledForFirstTime = false;

    private final Context mContext;
    private final OMMobileSecurityConfiguration mMobileSecurityConfig;
    private OMMobileSecurityServiceCallback mCallback;
    private AuthenticationServiceManager mASM;
    private OMCryptoService cryptoService;
    private OMCredentialStore credentialStoreService = null;
    private boolean logoutInProgress = false;
    private OMAuthenticationContextCallback mAuthContextCallback;
    private OMConnectionHandler mConnectionHandler;
    private Object mASMLock = new Object();
    private OpenIDTokenService openIDTokenService;

    /**
     * This returns {@link OMDefaultAuthenticator} used by SDK to store sensitive information
     * securely, when another authentication mechanism like PIN, Fingerprint, etc. is not set.
     * <p>
     * If app level PIN, Fingerprint is used, then keys in {@link OMDefaultAuthenticator#getKeyStore()} should
     * be migrated. For this, call {@link oracle.idm.mobile.auth.local.OMAuthenticator#copyKeysFrom(OMKeyStore)},
     * by passing {@link OMDefaultAuthenticator#getKeyStore()} obtained from the returned {@link OMDefaultAuthenticator}.
     * <p>
     * NOTE: {@link OMDefaultAuthenticator#deleteAuthData()} MUST be called to delete keys after
     * {@link OMAuthenticator#setAuthData(OMAuthData)} is called for new local authentication. This
     * will ensure better security.
     * <p>
     * This API can also be called during app startup if the app does not have any local authentication (PIN, etc.)
     * set. This will ensure that additional time taken for storing the credentials securely for the first time
     * is reduced.
     *
     * @param context
     * @return
     * @throws OMAuthenticationManagerException
     * @throws OMKeyManagerException
     */
    public static OMDefaultAuthenticator getDefaultAuthenticator(Context context) throws OMAuthenticationManagerException, OMKeyManagerException {
        OMDefaultAuthenticator defaultAuthenticator = DefaultAuthenticationUtils.getDefaultAuthenticator(context);
        DefaultAuthenticationUtils.initializeDefaultAuthenticator(context, defaultAuthenticator);
        return defaultAuthenticator;
    }

    /**
     * Constructs a OMMobileSecurityService instance with the details passed in
     * the map. The map can contain information which will be used to construct
     * the appropriate {@link OMMobileSecurityConfiguration} instances.
     *
     * @param context          context of the calling application. Always pass
     *                         {@link Context#getApplicationContext()}. Activity context
     *                         should not be passed as it may lead to memory leak.
     * @param configProperties {@link Map} of properties used for constructing
     *                         {@link OMMobileSecurityConfiguration} instance
     * @param callback         instance of {@link OMMobileSecurityServiceCallback} to return the
     *                         control back to the calling application.
     * @throws IllegalArgumentException if the required arguments are null
     */
    public OMMobileSecurityService(Context context, Map<String, Object> configProperties,
                                   OMMobileSecurityServiceCallback callback) throws OMMobileSecurityException {
        mContext = context;
        mMobileSecurityConfig = OMMobileSecurityConfiguration.createMobileSecurityConfiguration(configProperties);
        mCallback = callback;
    }

    /**
     * Constructs OMMobileSecurityService object based on the configuration
     * properties stored in SharedPreferences against the default key. If the
     * configuration properties are not available against the default key,
     * {@link OMMobileSecurityException} will be thrown.
     * {@link OMMobileSecurityConfiguration#parseConfigurationURI(Context, Intent, boolean, String)}
     * should be called before using this constructor to make sure that
     * configuration properties are stored in SharedPrefereces.
     *
     * @param context  context of the calling application. Always pass
     *                 {@link Context#getApplicationContext()}. Activity context
     *                 should not be passed as it may lead to memory leak.
     * @param callback instance of {@link OMMobileSecurityServiceCallback} to return the
     *                 control back to the calling application
     * @throws JSONException             If the JSON string retrieved from SharedPreferences cannot be
     *                                   parsed
     * @throws OMMobileSecurityException if the configuration properties cannot be retrieved from
     *                                   SharedPreferences
     */
    public OMMobileSecurityService(Context context,
                                   OMMobileSecurityServiceCallback callback) throws JSONException,
            OMMobileSecurityException {
        this(context, OMMobileSecurityConfiguration.getInitializationConfiguration(context,
                OMMobileSecurityConfiguration.DEFAULT_CONFIGURATION_PROPERTIES_KEY), callback);
    }

    /**
     * Constructs OMMobileSecurityService object based on the configuration
     * properties stored in SharedPreferences against the key passed as a
     * parameter. If the configuration properties are not available against the
     * specified key, {@link OMMobileSecurityException} will be thrown.
     * {@link OMMobileSecurityConfiguration#parseConfigurationURI(Context, Intent, boolean, String)}
     * should be called before using this constructor to make sure that
     * configuration properties are stored in SharedPrefereces.
     *
     * @param context                    context of the calling application. Always pass
     *                                   {@link Context#getApplicationContext()}. Activity context
     *                                   should not be passed as it may lead to memory leak.
     * @param configurationPropertiesKey the key against which the configuration properties are stored
     *                                   in SharedPreferences
     * @param callback                   instance of {@link OMMobileSecurityServiceCallback} to return the
     *                                   control back to the calling application
     * @throws JSONException             If the JSON string retrieved from SharedPreferences cannot be
     *                                   parsed
     * @throws OMMobileSecurityException if the configuration properties cannot be retrieved from
     *                                   SharedPreferences
     */
    public OMMobileSecurityService(Context context,
                                   String configurationPropertiesKey, OMMobileSecurityServiceCallback callback)
            throws JSONException, OMMobileSecurityException {
        this(context, OMMobileSecurityConfiguration.getInitializationConfiguration(context,
                configurationPropertiesKey), callback);
    }

    /**
     * This is to be called before calling {@link #authenticate()} in case of OpenID Connect.
     * This fetches the endpoint details from OpenID Connect Discovery endpoint.
     */
    public void setup() {
        OMLog.debug(TAG, "setup");
        if (mMobileSecurityConfig.isInitialized()) {
            //do nothing
            invokeSetupCompleteCallback(null);
            isSetupDone = true;
        } else {
            new SetupTask(this).execute();
        }
    }

    public void authenticate(final OMAuthenticationRequest omAuthRequest)
            throws OMMobileSecurityException {
        removeSessionCookies();
        checkValidityBeforeAuthentication();
        OMAuthenticationScheme scheme = mMobileSecurityConfig.getAuthenticationScheme();
        OMAuthenticationRequest.Builder builder = new OMAuthenticationRequest.Builder();
        builder.setAuthScheme(scheme).
                setLogoutTimeout(mMobileSecurityConfig.getLogoutTimeOutValue());
        OMAuthenticationRequest authRequest = null;
        if (scheme == OMAuthenticationScheme.BASIC) {
            builder = builder.setBasicAuthEndpoint(mMobileSecurityConfig.getAuthenticationURL()).
                    setCollectIdentityDomain(mMobileSecurityConfig.isCollectIdentityDomain());
        } else if (scheme == OMAuthenticationScheme.OAUTH20) {
            OAuthConnectionsUtil oauthConnectionUtil = new OAuthConnectionsUtil(
                    getApplicationContext(),
                    (OMOAuthMobileSecurityConfiguration) mMobileSecurityConfig,
                    null);
            getASM().setOAuthConnUtil(oauthConnectionUtil);
            OMOAuthMobileSecurityConfiguration oauthConfig = (OMOAuthMobileSecurityConfiguration) mMobileSecurityConfig;
            builder = builder.setAuthScheme(scheme).setOAuthTokenEndpoint(oauthConfig.getOAuthTokenEndpoint()).
                    setOAuthAuthorizationEndpoint(oauthConfig.getOAuthAuthorizationEndpoint()).
                    setOAuthGrantType(oauthConfig.getOAuthzGrantType()).
                    setOAuthScopes(oauthConfig.getOAuthScopes()).
                    setCollectIdentityDomain(mMobileSecurityConfig.isCollectIdentityDomain()).
                    setLogoutTimeout(mMobileSecurityConfig.getLogoutTimeOutValue());
        } else if (scheme == OMAuthenticationScheme.OPENIDCONNECT10) {
            if (!isSetupDone) {
                throw new OMMobileSecurityException(OMErrorCode.SETUP_NOT_INVOKED);
            }
            OAuthConnectionsUtil oauthConnectionUtil = new OAuthConnectionsUtil(
                    getApplicationContext(),
                    (OMOAuthMobileSecurityConfiguration) mMobileSecurityConfig,
                    null);
            getASM().setOAuthConnUtil(oauthConnectionUtil);
        }
        if (omAuthRequest != null) {
            String identityDomainNameFromRequest = omAuthRequest
                    .getIdentityDomain();
            OMConnectivityMode connectivityMode = omAuthRequest
                    .getConnectivityMode();
            int logoutTimeOutValue = omAuthRequest.getLogoutTimeout();
            Set<String> oAuthScopesFromRequest = omAuthRequest.getOAuthScopes();
            if (identityDomainNameFromRequest != null) {
                builder.setIdentityDomain(identityDomainNameFromRequest);
            }
            if (connectivityMode != null) {
                builder.setConnMode(connectivityMode);
            }
            if (logoutTimeOutValue > 0) {
                builder.setLogoutTimeout(logoutTimeOutValue);
            }
            builder.setForceAuthentication(omAuthRequest
                    .isForceAuthentication());
            if (omAuthRequest.isForceAuthentication()) {
                resetConnectionHandler();
            }
            if (mMobileSecurityConfig instanceof OMOAuthMobileSecurityConfiguration && oAuthScopesFromRequest != null) {
                builder.setOAuthScopes(oAuthScopesFromRequest);
            }
        }
        authRequest = builder.buildComplete();
        if (authRequest != null)
            getASM().startAuthenticationProcess(authRequest);
    }

    public void authenticate() throws OMMobileSecurityException {
        authenticate(null);
    }

    private boolean isSetupDone;

    private class SetupTask extends
            AsyncTask<Void, Void, OMMobileSecurityException> {
        private OMMobileSecurityService sMSS;

        SetupTask(OMMobileSecurityService mss) {
            sMSS = mss;

        }

        @Override
        protected OMMobileSecurityException doInBackground(Void... params) {
            try {
                sMSS.getMobileSecurityConfig().initialize(sMSS.getApplicationContext(), sMSS.getConnectionHandler());
            } catch (OMMobileSecurityException e) {
                return e;
            }
            return null;
        }

        @Override
        protected void onPostExecute(OMMobileSecurityException e) {
            if (e != null && e.getExceptionEvent() != null) {


                OMExceptionEvent event = e.getExceptionEvent();

                //lets check for SSL events
                if (event instanceof SSLExceptionEvent) {

                    SSLExceptionEvent sslEvent = (SSLExceptionEvent) event;

                    OMAuthenticationChallenge sslChallenge = new OMAuthenticationChallenge(OMAuthenticationChallengeType.UNTRUSTED_SERVER_CERTIFICATE);
                    sslChallenge.addChallengeField(OMSecurityConstants.Challenge
                            .UNTRUSTED_SERVER_CERTIFICATE_AUTH_TYPE_KEY, sslEvent.getAuthType());
                    sslChallenge.addChallengeField(OMSecurityConstants.Challenge
                            .UNTRUSTED_SERVER_CERTIFICATE_CHAIN_KEY, sslEvent.getCertificateChain());
                    new Setup1WaySSLCompletionHandler(sMSS.getMobileSecurityConfig(), sMSS.getCallback()).createChallengeRequest(sMSS, sslChallenge, null);
                    //handle 1-way SSL
                    return;
                } else if (event instanceof CBAExceptionEvent) {
                    //handle CBA
                }
            }
            sMSS.invokeSetupCompleteCallback(e);
        }
    }


    private void invokeSetupCompleteCallback(OMMobileSecurityException e) {
        if (e != null) {
            getCallback().onSetupCompleted(this, null, e);
        } else {
            setSetupCompleted(true);
            getCallback().onSetupCompleted(this, getMobileSecurityConfig(), null);
        }
    }

    /**
     * 1-way SSL Completion Handler for Setup Task
     */
    private static class Setup1WaySSLCompletionHandler extends OMAuthenticationCompletionHandler {
        private OMMobileSecurityService mMSS;
        private OMAuthenticationChallenge mSSLChallenge;

        protected Setup1WaySSLCompletionHandler(OMMobileSecurityConfiguration config, OMMobileSecurityServiceCallback appCallback) {
            super(config, appCallback);
        }

        @Override
        protected void createChallengeRequest(OMMobileSecurityService mas, OMAuthenticationChallenge challenge, AuthServiceInputCallback authServiceCallback) {
            mMSS = mas;
            mSSLChallenge = challenge;
            mAppCallback.onAuthenticationChallenge(mas, challenge, this);//invoke application callback.

        }

        @Override
        public void proceed(Map<String, Object> responseFields) {
            //we do not want any response fields from the app.
            //as they have called proceed, it means they want to trust the certificate.
            OMLog.info(TAG, "proceed");
            OMLog.info(TAG, "Installing untrusted certificate");
            try {
                OMCertificateService certificateService = new OMCertificateService(mMSS.getApplicationContext());
                X509Certificate[] chain = (X509Certificate[]) mSSLChallenge.getChallengeFields().get(OMSecurityConstants.Challenge.UNTRUSTED_SERVER_CERTIFICATE_CHAIN_KEY);
                //Root certificate is imported
                certificateService.importServerCertificate(chain[0]);
                mMSS.refreshConnectionHandler(OMSecurityConstants.Flags.CONNECTION_ALLOW_UNTRUSTED_SERVER_CERTIFICATE, true);
                mMSS.setup();
            } catch (CertificateException e) {
                OMLog.error(TAG, e.getMessage(), e);
                mAppCallback.onSetupCompleted(mMSS, null, new OMMobileSecurityException(OMErrorCode.SETUP_FAILED));
                return;
            }
        }

        @Override
        public void validateResponseFields(Map<String, Object> responseFields) throws OMMobileSecurityException {
            //nothing
        }

        @Override
        public void cancel() {
            mAppCallback.onSetupCompleted(mMSS, null, new OMMobileSecurityException(OMErrorCode.USER_REJECTED_SERVER_CERTIFICATE));
            return;
            //validate
        }
    }

    void setSetupCompleted(boolean completed) {
        isSetupDone = completed;
    }


    /**
     * This will cancel the current authentication attempt by SDK.
     */
    public void cancel() {
        OMLog.trace(TAG, "cancel");
        getASM().cancel();
    }

    /**
     * This method can be used to register an instance of
     * {@link OMMobileSecurityServiceCallback} with the mobile security service.
     *
     * @param callback an instance of {@link OMMobileSecurityServiceCallback}
     * @throws IllegalArgumentException if callback is null
     */
    public void registerCallback(OMMobileSecurityServiceCallback callback) {
        if (callback == null) {
            throw new IllegalArgumentException();
        }

        this.mCallback = callback;
    }

    /**
     * Gets an instance of {@link OMMobileSecurityConfiguration} to retrieve
     * all configuration attributes
     *
     * @return an instance of {@link OMMobileSecurityConfiguration}
     */
    public OMMobileSecurityConfiguration getMobileSecurityConfig() {
        return mMobileSecurityConfig;
    }

    public OMMobileSecurityServiceCallback getCallback() {
        return mCallback;
    }

    AuthenticationServiceManager getASM() {
        final Object lock = mASMLock;
        synchronized (lock) {
            if (mASM == null) {
                mASM = new AuthenticationServiceManager(this);
            }
        }
        return mASM;
    }

    /**
     * Returns the calling application {@link Context} instance.
     *
     * @return {@link Context} instance.
     * @hide
     */
    public Context getApplicationContext() {
        return mContext;
    }

    /**
     * This method removes all session cookies when authenticate is called for
     * first time after app launch. This is done, because android sometimes
     * retains some session cookies even after app restart. E.g: User is logged
     * in using Federated Authentication, and then the app is force stopped. The
     * next time app is launched, if the session cookies are not removed, the
     * federated authentication flow will fail.
     */
    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private void removeSessionCookies() {
        if (!authenticateCalledForFirstTime) {
            authenticateCalledForFirstTime = true;
            if (!getMobileSecurityConfig().isAuthContextPersistenceAllowed()) {
                OMLog.debug(TAG,
                        "Authenticate API called for first time after app launch -> Removing session cookies");
                OMCookieManager.getInstance().removeSessionCookies(getApplicationContext());
            }
        }
    }

    private void removeSessionCookiesOnLogout() {
        if (mMobileSecurityConfig != null
                && mMobileSecurityConfig.isRemoveAllSessionCookies()) {
            boolean removeAllSessionCookies = true;
            if (mMobileSecurityConfig instanceof OMOAuthMobileSecurityConfiguration
                    && ((OMOAuthMobileSecurityConfiguration) mMobileSecurityConfig).getOAuthBrowserMode()
                    == BrowserMode.EXTERNAL) {
                /* In case authentication was done using External browser, there is
                 no need to clear cookies used by WebView.
                  */
                removeAllSessionCookies = false;
            }
            if (removeAllSessionCookies) {
                OMCookieManager.getInstance().removeSessionCookies(getApplicationContext());
            }
        }
    }

    public void logout(boolean isForgetDevice) {
        if (isLogoutInProgress()) {
            if (mCallback != null) {
                mCallback.onLogoutCompleted(this,
                        new OMMobileSecurityException(
                                OMErrorCode.LOGOUT_IN_PROGRESS));
            }
            return;
        }

        refreshConnectionHandler(OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTP_TO_HTTPS_REDIRECT, false);
        refreshConnectionHandler(OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTPS_TO_HTTP_REDIRECT, false);
        OMAuthenticationContext authContext = getASM()
                .getAuthenticationContext();

        if (authContext == null) {
            authContext = mASM
                    .retrieveAuthenticationContext();
        }

        if (authContext != null) {
            // Try to invoke delete user token from the server.
            authContext.logout(isForgetDevice);
            /*
             * Commenting this so that we call these from the respective logout
             * services after the logout is done.
             */
            // resetAuthServiceManager();
            // resetConnectionHandler();
        } else {
            /* If logout(true)is called without logging in, it is expected that persisted
             * credentials are removed.*/
            if (isForgetDevice) {
                removeCredentials();
            }
            // no need to set logout in progress in this case.
            if (mCallback != null) {
                mCallback.onLogoutCompleted(this, null);
            }
        }
    }

    private void removeCredentials() {
        Map<String, Object> configProperties = new HashMap<>();
        configProperties.put(OM_PROP_LOGIN_URL, getMobileSecurityConfig().getAuthenticationURL());
        configProperties.put(OM_PROP_AUTH_KEY, getMobileSecurityConfig().getAuthenticationKey());
        configProperties.put(OM_PROP_APPNAME, getMobileSecurityConfig().getApplicationId());
        int deletedCredentialsCount = getCredentialStoreService().deleteCredentialForProperties(configProperties);
        Log.d(TAG, "deletedCredentialsCount = " + deletedCredentialsCount);
        RCUtility rcUtility = new RCUtility(getApplicationContext(), getMobileSecurityConfig(),
                getCredentialStoreService());
        rcUtility.removeAll();
    }

    /**
     * Gets an instance of {@link OMConnectionHandler} to handle server
     * connections.
     *
     * @return an instance of {@link OMConnectionHandler}
     */
    public OMConnectionHandler getConnectionHandler() {
        return getConnectionHandler(getMobileSecurityConfig().getConnectionTimeout());
    }

    /**
     * Gets an instance of {@link OMConnectionHandler} to handle server
     * connections with the connection timeout specified.
     *
     * @param connectionTimeout connection timeout in seconds.
     * @return an instance of {@link OMConnectionHandler}
     */
    public OMConnectionHandler getConnectionHandler(int connectionTimeout) {
        if (mConnectionHandler == null) {
            boolean handleClientCert = mMobileSecurityConfig.isClientCertificateEnabled();
            mConnectionHandler = new OMConnectionHandler(
                    getApplicationContext(), connectionTimeout, handleClientCert, mMobileSecurityConfig);
            if (mMobileSecurityConfig.getDefaultProtocols() != null) {
                mConnectionHandler.setDefaultSSLProtocols(mMobileSecurityConfig.getDefaultProtocols());
            }
            if (mMobileSecurityConfig.getEnabledCipherSuites() != null) {
                mConnectionHandler.setEnabledCipherSuites(mMobileSecurityConfig
                        .getEnabledCipherSuites());
            }
        } else {
            if (mConnectionHandler.getConnectionTimeout() != connectionTimeout) {
                mConnectionHandler.setConnectionTimeout(connectionTimeout);
            }
        }
        return mConnectionHandler;
    }

    public OMCryptoService getCryptoService() {
        if (cryptoService == null) {
            cryptoService = new OMCryptoService(getCredentialStoreService());
        }
        return cryptoService;
    }

    public OMCredentialStore getCredentialStoreService() {
        if (credentialStoreService == null) {
            credentialStoreService = new OMCredentialStore(getApplicationContext(),
                    getMobileSecurityConfig().getAuthenticatorName(),
                    getMobileSecurityConfig().getAuthenticatorInstanceId());
        }

        return credentialStoreService;
    }

    /**
     * @return
     * @hide
     */
    public boolean isLogoutInProgress() {
        // TODO make if required make this per thread.
        // First of all avoid call from a different thread in the start of the
        // API.
        return logoutInProgress;
    }

    public void setLogoutInProgress(boolean logoutInProgress) {
        OMLog.debug(TAG, "Logout In Progress : " + logoutInProgress + " From "
                + Thread.currentThread().getName());
        this.logoutInProgress = logoutInProgress;
    }

    public void setAuthenticationContextCallback(OMAuthenticationContextCallback authContextCallback) {
        mAuthContextCallback = authContextCallback;
    }

    public OMAuthenticationContextCallback getAuthenticationContextCallback() {
        return mAuthContextCallback;
    }

    private void resetAuthServiceManager() {
        final Object lock = mASMLock;
        synchronized (lock) {
            this.mASM = null;
        }
        OMLog.info(TAG, "Resetting ASM");
    }

    private void resetConnectionHandler() {
        this.mConnectionHandler = null;
    }

    /**
     * Can be called by the client application to find out whether there is a
     * valid authentication context already available in the credential store
     * before invoking the {@link OMMobileSecurityService#authenticate()}
     * method.
     *
     * @return {@link OMAuthenticationContext} instance
     * @throws OMMobileSecurityException if {@link OMMobileSecurityService#setup()} has not been
     *                                   invoked or if it has failed
     */
    public OMAuthenticationContext retrieveAuthenticationContext()
            throws OMMobileSecurityException {
        if (mMobileSecurityConfig == null) {
            throw new OMMobileSecurityException(OMErrorCode.INTERNAL_ERROR);
        }

        return getASM().retrieveAuthenticationContext();
    }

    public void refreshConnectionHandler(int flags, boolean set) {

        switch (flags) {
            case OMSecurityConstants.Flags.CONNECTION_ALLOW_UNTRUSTED_SERVER_CERTIFICATE:
            case OMSecurityConstants.Flags.CONNECTION_FORCE_RESET:
                if (mConnectionHandler != null) {
                    OMLog.info(TAG, "Resetting connection handler");
                    resetConnectionHandler();
                }
                break;
            case OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTPS_TO_HTTP_REDIRECT:
                if (mConnectionHandler != null) {
                    mConnectionHandler.setAllowHttpsToHttpRedirect(set);
                }
                break;
            case OMSecurityConstants.Flags.CONNECTION_ALLOW_HTTP_TO_HTTPS_REDIRECT:
                if (mConnectionHandler != null) {
                    mConnectionHandler.setAllowHttpToHttpsRedirect(set);
                }
                break;
            default:

        }
    }

    /**
     * @hide
     */
    public void setClientCertificatePreference(ClientCertificatePreference preference) {
        if (preference != null) {
            getConnectionHandler().setClientCertificatePreference(preference);
        }
    }

    /**
     * @hide
     */
    public void onLogoutCompleted() {
        /*try
        {
            OMAuthenticationContext authContext = retrieveAuthenticationContext();
              //TODO remove owsm_ma cookies
        }
        catch (OMMobileSecurityException e)
        {
            OMLog.error(TAG,
                    "Deletion of cookies set by OWSM MA failed. So, will delete all session cookies." +
                    e.getMessage());
            OMCookieManager.getInstance().removeSessionCookies(getApplicationContext());
        }*/
        OMLog.debug(TAG, "onLogoutComplete!");
        OMAuthenticationContext authenticationContext = mASM.retrieveAuthenticationContext();
        if (authenticationContext != null) {
            TimeoutManager timeoutManager = authenticationContext.getTimeoutManager();
            if (timeoutManager != null) {
                timeoutManager.stopTimers();
            }
            authenticationContext.deleteCookies();
        }
        removeSessionCookiesOnLogout();
        resetAuthServiceManager();
        resetConnectionHandler();
        setLogoutInProgress(false);
    }

    private void checkValidityBeforeAuthentication()
            throws OMMobileSecurityException {
        /*Throw OMMobileSecurityException(OMErrorCode.SETUP_NOT_INVOKED)
        for authentication mechanisms which require app profile download here.*/

        if (isLogoutInProgress()) {
            throw new OMMobileSecurityException(OMErrorCode.LOGOUT_IN_PROGRESS);
        }
    }
}
