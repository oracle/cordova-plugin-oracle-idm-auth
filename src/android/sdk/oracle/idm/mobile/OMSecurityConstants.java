/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile;

/**
 * Class that contains all the constants.
 */
public class OMSecurityConstants {

    public static final char COLON = ':';
    public static final char EQUAL = '=';
    public static final char AMPERSAND = '&';
    public static final char SEMI_COLON = ';';
    public static final String TAG = "IDMMobileSDK";
    public static final String OPEN_BRACKET = "[";
    public static final String CLOSE_BRACKET = "] ";
    public static final String EMPTY_STRING = "";
    public static final String AUTHORIZATION_BASIC = "Basic ";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final int DEFAULT_SALT_LENGTH = 8; // In bytes

    // M&S OAuth constants
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";
    public static final String IDENTITY_DOMAIN = "identityDomain";
    public static final String OAUTH_MS_VALID_CLIENT_ASSERTION_PRESENT = "OAuthValidClientAssertionPresent";
    public static final String OAUTH_MS_CLIENT_ASSERTION_SUFFIX = "OAuthClientAssertionKey";
    public static final String OM_OAUTH_USER_ASSERTION_TOKEN = "user_assertion";// used by the apps
    public static final String OM_OAUTH_CLIENT_ASSERTION_TOKEN = "client_assertion";

    //IDCS Client Registration
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_NAME = "client_name";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_SECRET_EXPIRES_AT = "client_secret_expires_at";
    public static final String REDIRECT_URIS = "redirect_uris";
    public static final String GRANT_TYPES = "grant_types";
    public static final String SCOPE = "scope";
    public static final String DEVICE_ID = "device_id";
    public static final String ANDROID_PACKAGE_NAME = "android_package_name";
    public static final String ANDROID_SIGNING_CERT_FINGERPRINT = "android_signing_cert_fingerprint";
    public static final String CLIENT_REGISTRATION_TOKEN = "client_registration_token";


    /*TODO Documentation*/
//    public static final String USERNAME = "username";
//    public static final String PASSWORD = "password";
//    public static final String IDENTITY_DOMAIN = "identityDomain";


    //TODO Add javadoc for every constant following the format specified for CLIENT_CERTIFICATE_HOST
    /**
     * Holds constants specific to OMAuthenticationChallenge
     */
    public static class Challenge {
        public static final String USERNAME_KEY = "username_key";
        public static final String PASSWORD_KEY = "password_key";
        public static final String IDENTITY_DOMAIN_KEY = "iddomain_key";
        public static final String OFFLINE_CREDENTIAL_KEY = "offline_credential_key";
        public static final String IS_FORCE_AUTHENTICATION ="isForceAuthentication";
        /**
         * The key against the following is present:
         * Exception thrown in the authentication attempt
         * <p/>
         * The value is of type {@link OMMobileSecurityException}.
         * <p/>
         */
        public static final String MOBILE_SECURITY_EXCEPTION = "mobileSecurityException";

        /**
         * The key against the following is present:
         * the host name of the server requesting the certificate
         * <p/>
         * The value is of type {@link String}.
         * <p/>
         * <b>Note:</b> Client certificate authentication in embedded browser [Fed Auth, OAuth] is supported only from LOLLIPOP onwards.
         * Refer {@link oracle.idm.mobile.OMMobileSecurityService.AuthServerType} for more details.
         */
        public static final String CLIENT_CERTIFICATE_HOST = "client_certificate_host_key";

        /**
         * The key against the following is present:
         * the port number of the server requesting the certificate
         * <p/>
         * The value is of type {@link Integer}.
         * <p/>
         * <b>Note:</b> Client certificate authentication in embedded browser [Fed Auth, OAuth] is supported only from LOLLIPOP onwards.
         * Refer {@link oracle.idm.mobile.OMMobileSecurityService.AuthServerType} for more details.
         */
        public static final String CLIENT_CERTIFICATE_PORT = "client_certificate_port_key";

        /**
         * The key against the following is present:
         * the acceptable certificate issuers for the certificate matching the private key (can be null)
         * null implies any issuer will do.
         * <p/>
         * The value is of type {@link java.security.Principal}[].
         * <p/>
         * <b>Note:</b> Client certificate authentication in embedded browser [Fed Auth, OAuth] is supported only from LOLLIPOP onwards.
         * Refer {@link oracle.idm.mobile.OMMobileSecurityService.AuthServerType} for more details.
         */
        public static final String CLIENT_CERTIFICATE_ISSUERS_KEY = "client_certificate_issuer_names_key";

        /**
         * The key against the following is present:
         * the acceptable types of asymmetric keys (can be null) or in other words: the list of public key algorithm names
         *
         * The value is of type {@link String}[].
         *
         * <b>Note:</b> Client certificate authentication in embedded browser [Fed Auth, OAuth] is supported only from LOLLIPOP onwards.
         * Refer {@link oracle.idm.mobile.OMMobileSecurityService.AuthServerType} for more details.
         */
        public static final String CLIENT_CERTIFICATE_KEYTYPES_KEY = "client_certificate_keytypes_key";

        /**
         * The key against the following MUST BE provided by the developer:
         * the alias for the client side of an SSL connection to authenticate it with the specified public key type and certificate issuers
         *
         * The value MUST be of type {@link String}
         *
         * <b>Note:</b> Client certificate authentication in embedded browser [Fed Auth, OAuth] is supported only from LOLLIPOP onwards.
         * Refer {@link oracle.idm.mobile.OMMobileSecurityService.AuthServerType} for more details.
         */
        public static final String CLIENT_CERTIFICATE_ALIAS_KEY = "client_certificate_alias_key";

        //TODO Javadoc
        public static final String HTTP_AUTH_HOST = "http_auth_host_key";
        //TODO Javadoc
        public static final String HTTP_AUTH_REALM = "http_auth_realm_key";

        public static final String AUTO_LOGIN_UI_PREFERENCE_KEY = "autoLogin_ui_preference_key";
        public static final String REMEMBER_USER_NAME_UI_PREFERENCE_KEY = "remember_username_ui_preference_key";
        public static final String REMEMBER_CREDENTIALS_UI_PREFERENCE_KEY = "remember_credentials_ui_preference_key";
        public static final String CLIENT_CERTIFICATE_STORAGE_PREFERENCE_KEY = "client_certificate_storage_pref_key";
        public static final String UNTRUSTED_SERVER_CERTIFICATE_AUTH_TYPE_KEY = "untrusted_certificate_authtype_key";
        public static final String UNTRUSTED_SERVER_CERTIFICATE_CHAIN_KEY = "untrusted_server_certificate_chain_key";
        public static final String INVALID_REDIRECT_TYPE_KEY = "invalid_redirect_type_key";


        /**
         * Key indicating that webview MUST be passed by app to SDK to proceed with authentication.
         */
        public static final String WEBVIEW_KEY = "webview_key";
        public static final String WEBVIEW_CLIENT_KEY = "webview_client_key";
        /**
         * key used to pass the redirect response from the external application/browser back to the SDK.
         * Used for OAuth Authorization Code grant type.
         */
        public static final String REDIRECT_RESPONSE_KEY = "redirect_response_key";
        public static final String EXTERNAL_BROWSER_LOAD_URL = "external_browser_load_url_key";
    }

    //Cookie related constants
    public static final String COOKIE_EXPIRY_DATE_PATTERN = "EEE',' dd MMM yyyy HH:mm:ss zzz";
    public static final String DOMAIN = "domain";
    public static final String PATH = "path";
    public static final String SECURE = "secure";
    public static final String HTTP_ONLY = "httponly";
    public static final String IS_HTTP_ONLY = "ishttponly";
    public static final String EXPIRY_DATE = "expiresdate";
    public static final String EXPIRES_IN = "expires_in";
    public static final String IS_SECURE = "issecure";
    /**
     * Constants to represent parameter keys used internally in SDK.
     *
     * @hide
     */
    public static class Param {
        public static final String OAUTH_REFRESH_TOKEN_VALUE = "ParamOAuthRefreshTokenValue";
        public static final String OAUTH_FRONT_CHANNEL_RESPONSE_JSON = "ParamFrontChannelResponseJSON";
        public static final String COLLECT_OFFLINE_CREDENTIAL = "collectOfflineCredential";
        //Begin: Fed Auth
        public static final String LOGIN_FAILURE_URL_HIT = "login_failure_url_hit";
        public static final String VISITED_URLS = "visited_urls";
        public static final String TOKEN_RELAY_RESPONSE = "tokenRelayResponse";
        public static final String AUTHENTICATION_MECHANISM = "authenticationMechanism";
        //End: Fed Auth

        //IDCS Client registration

        public static final String IDCS_CLIENT_REGISTRATION_TOKEN = "IDCSClientRegistrationToken";
        public static final String IDCS_CLIENT_REGISTRATION_ACCESS_TOKEN = "IDCSClientRegistrationAccessToken";

        //Client Assertion OAuth

        public static final String OAUTH_CLIENT_ASSERTION = "OAuthClientAssertion";
    }

    //OAuth
    public static final String TOKEN = "TOKEN";
    public static final String TOKEN_NAME = "name";
    public static final String TOKEN_VALUE = "value";
    public static final String EXPIRES = "expires";
    public static final String EXPIRY_SECS = "expirationTSInSec";
    public static final String OAUTH_TOKEN_REFRESH_VALUE = "OAuthRefreshValue";
    public static final String OAUTH_TOKEN_SCOPE = "OAuthTokenScopes";
    public static final String OAUTH_AUTHORIZATION_HEADER = "Authorization";
    public static final String OAUTH_ACCESS_TOKEN = "oauth_access_token";

    public static final String CLIENT_CERTIFICATE_PREFERENCE = "ClientCertificatePreference";

    public enum ConnectionConstants {
        AUTHORIZATION("Authorization"), ELEMENTS("elements"), CONTENT_TYPE(
                "Content-Type"), JSON_CONTENT_TYPE("application/json"), TOKEN(
                "TOKEN"), OAUTH20_CONTENT_TYPE(
                "application/x-www-form-urlencoded"), BASIC("Basic");

        private String value;

        ConnectionConstants(String value) {
            this.value = value;
        }

        public String getValue() {
            return this.value;
        }
    }

    /**
     * Flags used internally
     *
     * @hide
     */
    public class Flags {

        public static final int CONNECTION_ALLOW_UNTRUSTED_SERVER_CERTIFICATE = 100;
        public static final int CONNECTION_CLIENT_IDENTITY_CERTIFICATE_PROVIDED = 101;
        public static final int CONNECTION_FORCE_RESET = 102;
        public static final int CONNECTION_ALLOW_HTTPS_TO_HTTP_REDIRECT = 103;
        public static final int CONNECTION_ALLOW_HTTP_TO_HTTPS_REDIRECT = 104;
    }
}
