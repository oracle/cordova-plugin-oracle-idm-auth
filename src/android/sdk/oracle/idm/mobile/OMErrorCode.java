/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile;


/**
 * OMErrorCode represents various error codes supported.
 *
 * @since 11.1.2.3.1
 */
public enum OMErrorCode {

    CONNECTION_TIMEOUT("0001", "CONNECTION TIMEOUT"),
    SOCKET_TIMEOUT("0002", "SOCKET_TIMEOUT"),
    SERVER_CERTIFICATE_NOT_ALLOWED("0003", "SERVER CERTIFICATE NOT ALLOWED"),
    SETUP_NOT_INVOKED("0004", "Setup not invoked"),
    SETUP_FAILED("0005", "Setup Failed"),
    UNABLE_TO_CONNECT_TO_SERVER("10001", "UNABLE TO CONNECT TO SERVER"),
    SSL_EXCEPTION("10002", "SSL Exception occurred."),
    UNEXPECTED_SSL_FAILURE("10004", "Unexpected SSL error occurred. Please contact administrator for help."),

    AUTHENTICATION_FAILED("10408", "Authentication failed"),
    USER_NOT_AUTHENTICATED("10023", "User not yet authenticated"),
    USER_CANCELED_AUTHENTICATION("10029","User canceled authentication"),
    LOGOUT_TIMED_OUT("10034", "Logout operation failed as connection timed out."),
    LOGOUT_FAILED("10035", "Logout failed"),
    USERNAME_REQUIRED("10036", "Username required"),
    IDENTITY_DOMAIN_REQUIRED("10037", "Identity domain required"),
    PASSWORD_REQUIRED("10039", "Password required"),
    LOGOUT_IN_PROGRESS("10043", "Logout in progress"),
    UNABLE_OPEN_SECURE_CONNECTION("0007", "UNABLE TO OPEN SECURE CONNECTION"),
    UNABLE_OPEN_CONNECTION("0008", "UNABLE TO OPEN CONNECTION"),
    INTERNAL_ERROR("0009", "INTERNAL ERROR"),

    INVALID_CHALLENGE_INPUT_RESPONSE("10045", "INVALID CHALLENGE INPUT RESPONSE PROVIDED"),
    INVALID_AUTHENTICATION_SCHEME("0014", "INVALID AUTHENTICATION SCHEME"),
    UN_PWD_TENANT_INVALID("10011", "Invalid username or password or identity domain"),
    UN_PWD_INVALID("10003", "Invalid username or password."),
    LOGOUT_URL_NOT_LOADED("0021", "LOGOUT URL IS NOT LOADED IN WEBVIEW. BUT, ALL SESSION COOKIES ARE CLEARED LOCALLY"),

    INVALID_APP_NAME("10100","Invalid Application name"),
    INVALID_AUTH_SERVER_TYPE("10115", "Invalid authentication server type"),
    MAX_RETRIES_REACHED("10418", "Authentication has been retried max allowed times"),

    USERNAME_AND_IDENTITY_DOMAIN_REQUIRED("10040", "USERNAME AND IDENTITY DOMAIN REQUIRED"),

    //SSL related exception
    USER_REJECTED_SERVER_CERTIFICATE("10422", "User rejected to import un-trusted server certificate"),
    INVALID_CLIENT_CERTIFICATE("0051", "INVALID CLIENT CERTIFICATE"),
    //Initialization exceptions
    //TODO Change error from string to int. Ref:http://stackoverflow.com/a/14939831/1756069
    //<string name="oamms_invalid_server_type">Authentication server type is invalid.</string>
    OUT_OF_RANGE("10403", "Parameter or value is out of range"),

    //basic
    INVALID_BASIC_AUTHENTICATION_URL("20001", "Invalid basic auth url"),

    //Network related
    INVALID_REDIRECTION_PROTOCOL_MISMATCH("300", "INVALID REDIRECTION (CHANGE IN PROTOCOL NOT SUPPORTED)"),
    USER_CANCELED_INVALID_REDIRECT_OPERATION("301", "User canceled invalid redirect operation"),
    NOT_FOUND("404", "HTTP NOT FOUND"),
    //Fed Auth specific error codes
    RFC_NON_COMPLIANT_URI("400", "URL(s) LOADED IN WEBVIEW DURING AUTHENTICATION ARE NOT RFC COMPLIANT URI(s)"),

    //CBA related errors
    ANDROID_KEYSTORE_NOT_AVAILABLE("30000", "AndroidKeyStore is available only in Android 4.3 and above."),

    OAUTH_AUTHENTICATION_FAILED("40200", "OAuth authentication failed", "OAuth Authentication failed due to some internal error"),
    OAUTH_CONTEXT_INVALID("40201", "No valid access token is present for the given request. Authenticate with the appropriate scope."),
    OAUTH_AUTHORIZATION_METHOD_NOT_SUPPORTED("40202", "Method not supported for OAuth Authorization"),
    OAUTH_UNSUPPORTED_RESPONSE_TYPE("40001", "unsupported_response_type", "The authorization server does not support obtaining an authorization code using this method."),
    OAUTH_UNAUTHORIZED_CLIENT("40002", "unauthorized_client", "The authenticated client is not authorized to use this authorization grant type."),
    OAUTH_STATE_INVALID("40220", "OAuth state is invalid", "The state value obtained from server did not match the one sent by the client."),
    OAUTH_INVALID_REQUEST("40230", "invalid_request", "The request is missing a required parameter, includes an unsupported parameter value,repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed."),
    OAUTH_ACCESS_DENIED("40231", "access_denied", "The resource owner or authorization server denied the request."),
    OAUTH_INVALID_SCOPE("40232", "invalid_scope", "The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner."),
    OAUTH_SERVER_ERROR("40233", "server_error", "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."),
    OAUTH_TEMPORARILY_UNAVAILABLE("40234", "temporarily_unavailable", "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."),
    OAUTH_UNSUPPORTED_GRANT_TYPE("40238", "unsupported_grant_type", "The authorization grant type is not supported by the authorization server"),
    OAUTH_INVALID_CLIENT("40239", "invalid_client", "Client authentication failed"),
    OAUTH_INVALID_GRANT("40240", "invalid_grant", "The provided authorization grant or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client"),
    OAUTH_CLIENT_SECRET_INVALID("40241", "Client secret can not be null or empty for this grant type."),
    OAUTH_SETUP_FAILED("40242", "OAuth client profile cannot be downloaded."),
    OAUH_MS_PRE_AUHZ_CODE_INVALID("40215", "Pre AuthZ code for client registration is invalid."),
    OAUTH_MS_CLIENT_ASSERTION_INVALID("40213", "Invalid client assertion. Restart the authentication process."),

    //OpenIDConnect
    OPENID_CONFIGURATION_FAILED("50200", "Open ID Configuration failed"),
    OPENID_FETCH_CONFIGURATION_FAILED("50201", "Failed fetching OpenID well known configuration"),
    OPENID_AUTHENTICATION_FAILED("50202", "Open ID Authentication Failed"),
    OPENID_TOKEN_PARSING_FAILED("50203", "Open ID token parsing failed"),
    OPENID_TOKEN_INVALID("50204", "Open ID token invalid"),
    OPENID_TOKEN_SIGNATURE_INVALID("50205", "Open ID token has an invalid signature"),

    //IDCS Dynamic Client Registration
    IDCS_CLIENT_REGISTRATION_FAILED("50300", "IDCS dynamic client registration failed"),
    IDCS_CLIENT_REGISTRATION_UNABLE_TO_OBTAIN_AT("50301", "Unable to obtain access token for IDCS registration service."),
    IDCS_CLIENT_REGISTRATION_PARSING_FAILED("50302", "Unable to parse the IDCS Client registration token."),
    IDCS_CLIENT_REGISTRATION_INVALID_ENDPOINT("50303", "Invalid Registration endpoint"),
    IDCS_CLIENT_REGISTRATION_TOKEN_NOT_AVAILABLE("50304", "IDCS Client registration token is not available. Try to authenticate again."),
    IDCS_CLIENT_REGISTRATION_TOKEN_EMPTY("50305", "IDCS Client registration String null or empty"),

    //Error Codes as per https://stbeehive.oracle.com/teamcollab/wiki/Mobile+Development:IDM+Mobile+SDK+Headless+error+codes
    INVALID_IDLE_SESSION_TIMEOUT_TIME("10104", "Invalid idle session timeout time"),
    WEB_VIEW_REQUIRED("10417", "This flow requires a web-view"),

    COULD_NOT_STORE_CONFIGURATION("10006", "Could not store configuration properties in SharedPreferences"),
    COULD_NOT_RETRIEVE_CONFIGURATION("10007", "Could not retrieve configuration properties from SharedPreferences"),

    // new key manager and secure storage related constants...
    VALUE_CANNOT_BE_NULL("10406", "Value or parameter cannot be null."),
    INVALID_STATE("10427", "Invalid state"),
    KEY_IS_NULL("10501", "key is null when it must be non-null"),
    INVALID_INPUT("10502", "Input is not proper ,invalid input or missing input"),
    UNKNOWN_OR_UNSUPPORTED_ALGORITHM("10507", "unsupported encrypt algorithm"),
    KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM("10508", "key size not supported"),
    IV_LENGTH_MUST_MATCH_ALGORITHM_BLOCK_SIZE("10509", "IV length not matching to block size"),
    TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN("10521", "Tag require to identify key in key-chain error"),
    KEYCHAIN_SYSTEM_ERROR("10522", "key-chain system error"),
    KEYCHAIN_ITEM_NOT_FOUND("10523", "key-chain item missing"),
    KEYCHAIN_ITEM_ALREADY_EXISTS("10528", "key-chain item already exists"),
    RESOURCE_FILE_PATH_NOT_FOUND("10533", "file not found at resource path error"),
    LOCAL_AUTHENTICATION_NOT_DONE("10534", "Local authentication is not done. It is required for secure storage."),
    KEY_UNWRAP_FAILED("10535", "Unwrapping of secret key failed. This is mostly due to an android bug related to android keystore when device lock screen is changed."),
    /**
     * This happens every time when emulator is restarted. Though a fingerprint is registered, the stacktrace indicates:
     * Caused by: java.security.InvalidAlgorithmParameterException: java.lang.IllegalStateException: At least one fingerprint must be enrolled to create keys requiring user authentication for every use
     * This seems to be a bug in emulator. This should not arise in a device.
     */
    NO_FINGERPRINT_ENROLLED("10536", "At least one fingerprint must be enrolled to create keys requiring user authentication for every use");


    String mErrorCode;
    String mErrorMessage;
    String mErrorDescription;
    static OMErrorCode[] mOAuthErrorCodes;
    static OMErrorCode[] mRecoverableCodes;

    OMErrorCode(String errorCode, String errorMessage) {
        mErrorCode = errorCode;
        mErrorMessage = errorMessage;
    }

    OMErrorCode(String errorCode, String errorMessage, String errorDescription) {
        this(errorCode, errorMessage);
        mErrorDescription = errorDescription;
    }

    public String getErrorCode() {
        return mErrorCode;
    }

    public String getErrorString() {
        return mErrorMessage;
    }

    public String getErrorDescription() {
        return mErrorDescription;
    }

    public static OMErrorCode[] getOAuthKnownErrorCodes() {
        if (mOAuthErrorCodes == null) {
            mOAuthErrorCodes = new OMErrorCode[]{OMErrorCode.OAUTH_INVALID_REQUEST, OMErrorCode.OAUTH_UNAUTHORIZED_CLIENT,
                    OMErrorCode.OAUTH_ACCESS_DENIED, OMErrorCode.OAUTH_UNSUPPORTED_RESPONSE_TYPE, OMErrorCode.OAUTH_SERVER_ERROR,
                    OMErrorCode.OAUTH_TEMPORARILY_UNAVAILABLE, OMErrorCode.OAUTH_INVALID_SCOPE, OMErrorCode.OAUTH_UNSUPPORTED_GRANT_TYPE,
                    OMErrorCode.OAUTH_INVALID_CLIENT, OMErrorCode.OAUTH_INVALID_GRANT};
        }
        return mOAuthErrorCodes;
    }

    public static OMErrorCode[] getRecoverableErrorCodes() {
        if (mRecoverableCodes == null) {
            mRecoverableCodes = new OMErrorCode[]{OMErrorCode.USERNAME_REQUIRED, OMErrorCode.PASSWORD_REQUIRED,
                    OMErrorCode.IDENTITY_DOMAIN_REQUIRED, OMErrorCode.USERNAME_AND_IDENTITY_DOMAIN_REQUIRED,
                    OMErrorCode.UN_PWD_INVALID, OMErrorCode.UNABLE_TO_CONNECT_TO_SERVER};
        }
        return mRecoverableCodes;
    }

    public static boolean isOAuthResponseError(OMErrorCode errorCode) {
        for (OMErrorCode code : getOAuthKnownErrorCodes()) {
            if (code == errorCode) {
                return true;
            }
        }
        return false;
    }

}
