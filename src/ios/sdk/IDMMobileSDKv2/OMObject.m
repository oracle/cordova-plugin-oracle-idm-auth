/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMObject.h"
#import "OMReachability.h"
#import "OMVersion.h"


NSString *const OM_PROP_KEYCHAIN_DATA_PROTECTION = @"KeychainDataProtection";
NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED           = @"KeychainDataAccessibleWhenUnlocked";
NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_AFTER_FIRST_UNLOCK      = @"KeychainDataAccessibleAfterFirstUnlock";
NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_ALWAYS                  = @"KeychainDataAccessibleAlways";
NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY      = @"KeychainDataAccessibleWhenUnlockedThisDeviceOnly";
NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY = @"KeychainDataAccessibleAfterFirstUnlockThisDeviceOnly";
NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY = @"KeychainDataAccessibleAlwaysThisDeviceOnly";

NSString *const OM_NOTIFICATION_CERT_PROMPT       = @"CertPrompt";
NSString *const OM_NOTIFICATION_CERT_PERMISSION   = @"CertPermission";
NSString *const OM_KEYPAIR_TAG_PRIVATE       = @".private";
NSString *const OM_KEYPAIR_TAG_PUBLIC        = @".public";
NSString *const OM_CRYPTO_DES                = @"DES";
NSString *const OM_CRYPTO_3DES               = @"3DES";
NSString *const OM_CRYPTO_MD5                = @"MD5";
NSString *const OM_CRYPTO_SMD5               = @"SaltedMD5";


NSString *const OM_PROP_CREDENTIALS          = @"Credentials";
NSString *const OM_PROP_CRYPTO_PLAINTEXT     = @"PlainText";
NSString *const OM_PROP_CRYPTO_SHA1          = @"SHA-1";
NSString *const OM_PROP_CRYPTO_SHA224        = @"SHA-224";
NSString *const OM_PROP_CRYPTO_SHA256        = @"SHA-256";
NSString *const OM_PROP_CRYPTO_SHA384        = @"SHA-384";
NSString *const OM_PROP_CRYPTO_SHA512        = @"SHA-512";
NSString *const OM_PROP_CRYPTO_SSHA1         = @"SaltedSHA-1";
NSString *const OM_PROP_CRYPTO_SSHA224       = @"SaltedSHA-224";
NSString *const OM_PROP_CRYPTO_SSHA256       = @"SaltedSHA-256";
NSString *const OM_PROP_CRYPTO_SSHA384       = @"SaltedSHA-384";
NSString *const OM_PROP_CRYPTO_SSHA512       = @"SaltedSHA-512";
NSString *const OM_PROP_CRYPTO_AES           = @"AES";

NSString *const OM_ERROR_DOMAIN_NAME         = @"ORAIDMMOBILE";
NSString *const OM_IDENTITY_DOMAIN           = @"iddomain_key";
NSString *const OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER = @"IdentityDomainNameInHeader";
NSString *const OM_PROP_IDENTITY_DOMAIN_HEADER_NAME = @"IdentityDomainHeaderName";

NSString *const OM_PROP_NSUSERDEFAULTS_KEY   = @"OracleIDMMobileSDKConfigurationKey";
NSString *const OM_PROP_REQUIRED_TOKENS      = @"RequiredTokens";
NSString *const OM_PROP_LOGIN_URL            = @"LoginURL";
NSString *const OM_PROP_LOGOUT_URL           = @"LogoutURL";
NSString *const OM_PROP_LOGIN_SUCCESS_URL   = @"LoginSuccessURL";
NSString *const OM_PROP_LOGIN_FAILURE_URL    = @"LoginFailureURL";
NSString *const OM_PROP_LOGOUT_SUCCESS_URL   = @"LogoutSuccessURL";
NSString *const OM_PROP_LOGOUT_FAILURE_URL    = @"LogoutFailureURL";
NSString *const OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY = @"ConfirmLogoutAutomatically";
NSString *const OM_PROP_CONFIRM_LOGOUT_BUTTON_ID = @"ConfirmLogoutButtonId";

NSString *const OM_PROP_AUTHSERVER_TYPE      = @"AuthServerType";
NSString *const OM_PROP_AUTHSERVER_HTTPBASIC = @"HTTPBasicAuthentication";
NSString *const OM_PROP_APPNAME              = @"ApplicationName";
NSString *const OM_USERNAME                  = @"username_key";
NSString *const OM_PASSWORD                  = @"password_key";
NSString *const OM_PROP_SESSION_TIMEOUT_VALUE= @"SessionTimeOutValue";
NSString *const OM_PROP_PERCENTAGE_TO_IDLE_TIMEOUT= @"PercentageToIdleTimeout";
NSString *const OM_PROP_IDLE_TIMEOUT_VALUE   = @"IdleTimeOutValue";
NSString *const OM_PROP_MAX_LOGIN_ATTEMPTS   = @"MaxLoginAttempts";
NSString *const OM_PROP_CONNECTIVITY_MODE = @"ConnectivityMode";
NSString *const OM_CONNECTIVITY_AUTO = @"Auto";
NSString *const OM_CONNECTIVITY_OFFLINE = @"Offline";
NSString *const OM_CONNECTIVITY_ONLINE = @"Online";
NSString *const OM_PROP_OFFLINE_AUTH_ALLOWED = @"OfflineAuthAllowed";

NSString *const OM_CLIENTCERTS               = @"ClientCertArray";
NSString *const OM_SELECTED_CERT             = @"SelectedCert";
NSString *const OM_CERT_DESC                 = @"CertDesc";
NSString *const OM_TRUST_SERVER_CHALLANGE    = @"TrustServerChallange";
NSString *const OM_SERVER_TRUST_INFO         = @"serverTrustInfo";

///////////////////////////////////////////////////////////////////////////////
// Remember Credentials
///////////////////////////////////////////////////////////////////////////////
NSString *const OM_PROP_AUTO_LOGIN_ALLOWED   = @"AutoLoginAllowed";
NSString *const OM_PROP_REMEMBER_CREDENTIALS_ALLOWED = @"RememberCredentialsAllowed";
NSString *const OM_PROP_REMEMBER_USERNAME_ALLOWED = @"RememberUsernameAllowed";
NSString *const OM_AUTO_LOGIN_DEFAULT        = @"AutoLoginDefault";
NSString *const OM_REMEMBER_CREDENTIALS_DEFAULT = @"RememberCredentialDefault";
NSString *const OM_REMEMBER_USERNAME_DEFAULT = @"RememberUsernameDefault";
NSString *const OM_REMEMBER_CRED_PREF_SET    = @"RememberCredPreferenceSet";
NSString *const OM_AUTO_LOGIN_PREF           = @"autoLogin_ui_preference_key";
NSString *const OM_REMEMBER_CREDENTIALS_PREF = @"remember_credentials_ui_preference_key";
NSString *const OM_REMEMBER_USERNAME_PREF     = @"remember_username_ui_preference_key";
NSString *const OM_AUTH_SUCCESS              = @"AuthenticationSuccess";
NSString *const OM_PROP_COLLECT_IDENTITY_DOMAIN  = @"CollectIdentityDomain";
NSString *const OM_PROP_IDENTITY_DOMAIN_NAME = @"identityDomain";
NSString *const OM_PROP_LOGIN_TIMEOUT_VALUE  = @"AuthTimeOutVal";
NSString *const OM_FED_AUTH_QUERY_PARAMS     = @"FedAuthQueryParams";
NSString *const OM_FED_AUTH_USER_COOKIE_NAME = @"FedAuthUserCookieName";
NSString *const OM_PROP_AUTH_KEY             = @"AuthKey";

NSString *const OM_CHALLENGE_FINISHED = @"ChallengeFinished";

NSString *const OM_CLIENT_CERT = @"ClientCertificate";
NSString *const OM_PROP_AUTHSERVER_CLIENT_CERT = @"CertificateBasedAuthentication";
NSString *const OM_CLIENT_CERT_AUTH_SCHEME = @"ClientCertAuthentication";
NSString *const OM_CLIENT_CERT_PROMPT = @"ClientCertificatePrompt";
NSString *const OM_CLIENT_CERT_SELECTED = @"ClientCertificateSelected";
NSString *const OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND = @"PresentClientCertificate";
NSString *const OM_CERT_VALID_FROM = @"Valid From";
NSString *const OM_CERT_VALID_TILL = @"Valid Till";
NSString *const OM_CERT_IMPORT_RETRY = @"OMCertificateImportRetryCount";
NSString *const OM_DEFAULT_IDENTITY_DOMAIN_HEADER
= @"X-USER-IDENTITY-DOMAIN-NAME";
NSString *const OM_PROP_OAUTH_OAUTH20_SERVER = @"OAuthAuthentication";
NSString *const OM_PROP_OAUTH_CLIENT_ID      = @"OAuthClientID";
NSString *const OM_PROP_OAUTH_CLIENT_SECRET  = @"OAuthClientSecret";
NSString *const OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE = @"OAuthAuthorizationGrantType";
NSString *const OM_OAUTH_RESOURCE_OWNER      = @"OAuthResourceOwner";
NSString *const OM_OAUTH_AUTHORIZATION_CODE  = @"OAuthAuthorizationCode";
NSString *const OM_OAUTH_IMPLICIT            = @"OAuthImplicit";
NSString *const OM_OAUTH_CLIENT_CREDENTIALS  = @"OAuthClientCredentials";
NSString *const OM_OAUTH_ASSERTION           = @"OAuthAssertion";
NSString *const OM_OAUTH_OAM_CREDENTIAL      = @"OAuthOAMCredential";
NSString *const OM_PROP_OAUTH_SCOPE          = @"OAuthScope";
NSString *const OM_PROP_OAUTH_TOKEN_ENDPOINT = @"OAuthTokenEndpoint";
NSString *const OM_OAUTH_BACK_CHANNEL        = @"OAuthBackChannelRequest";
NSString *const OM_OAUTH_BACK_CHANNEL_REQUEST_URL = @"OAuthBackChannelURL";
NSString *const OM_OAUTH_BACK_CHANNEL_PAYLOAD = @"OAuthBackChannelPayload";
NSString *const OM_OAUTH_BACK_CHANNEL_HEADERS = @"OAuthBackChannelHeaders";
NSString *const OM_OAUTH_BACK_CHANNEL_REQUEST_TYPE  =
@"OAuthBackChannelRequestType";
NSString *const OM_AUTHORIZATION             = @"Authorization";
NSString *const OM_OAUTH_ERROR_INAVLID_REQUEST = @"invalid_request";
NSString *const OM_OAUTH_ERROR_UNAUTHORIZED_CLIENT = @"unauthorized_client";
NSString *const OM_OAUTH_ERROR_ACCESS_DENIED = @"access_denied";
NSString *const OM_OAUTH_ERROR_UNSUPPORTED_RESPONSE =
@"unsupported_response_type";
NSString *const OM_OAUTH_ERROR_SERVER_ERROR = @"server_error";
NSString *const OM_OAUTH_ERROR_TEMPORARILY_UNAVAILABLE =
@"temporarily_unavailable";
NSString *const OM_OAUTH_ERROR_TIMEOUT = @"TIMEOUT";
NSString *const OM_OAUTH_CLIENT_ASSERTION_REFRESH_TOKEN =
@"CilentAssertionRefreshToken";
NSString *const OM_OAUTH_INVALID_SCOPE       = @"invalid_scope";
NSString *const OM_STATUS_DENIED             = @"DENIED";
NSString *const OM_PROP_AUTHSERVER_FED_AUTH = @"FederatedAuthentication";
NSString *const OM_PROP_AUTH_WEBVIEW = @"webview_key";
NSString *const OM_FED_AUTH_HEADERS          = @"FedAuthHeaders";
NSString *const OM_ERROR                     = @"Error";
NSString *const OM_VISITED_HOST_URLS         = @"visitedURLs";
NSString *const OM_PROP_COOKIES              = @"cookies";
NSString *const OM_CUSTOM_HEADERS_MOBILE_AGENT = @"headers";
NSString *const OM_PROP_CREDENTIALS_USERNAME =
@"javax.xml.ws.security.auth.username";
NSString *const OM_PROP_CREDENTIALS_PASSWORD =
@"javax.xml.ws.security.auth.password";
NSString *const OM_PROP_TOKENS               = @"oauth_access_token";
NSString *const OM_PROP_CREDENTIALS_ERROR    = @"Error";
NSString *const OM_OAUTH_ACCESS_TOKEN        = @"oauth_access_token";
NSString *const OM_PROP_OAUTH_AUTHORIZATION_ENDPOINT
= @"OAuthAuthorizationEndpoint";
NSString *const OM_PROP_OAUTH_REDIRECT_ENDPOINT
= @"OAuthRedirectEndpoint";
NSString *const OM_PROP_BROWSERMODE          = @"BrowserMode";
NSString *const OM_PROP_BROWSERMODE_EMBEDDED = @"Embedded";
NSString *const OM_PROP_BROWSERMODE_EMBEDDED_SAFARI = @"EmbeddedSafari";
NSString *const OM_PROP_BROWSERMODE_EXTERNAL = @"External";
NSString *const OM_MAX_RETRY = @"MaxRetryKey";
NSString *const OM_PROP_PARSE_TOKEN_RELAY_RESPONSE = @"ParseTokenRelayResponse";
NSString *const OM_TOKENS                    = @"Tokens";
NSString *const OM_ACCESS_TOKEN              = @"access_token";
NSString *const OM_INVALID_REDIRECT = @"invalid_redirect_type";
NSString *const OM_PROP_CRYPTO_SCHEME        = @"CryptoScheme";
NSString *const OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT
= @"SendCustomAuthHeadersInLogout";
NSString *const OM_PROP_SEND_AUTHORIZATION_HEADER_DURING_LOGOUT
= @"SendAuthorizationHeaderDuringLogout";
NSString *const OM_MOBILESECURITY_EXCEPTION = @"mobileSecurityException";
NSString *const OM_RETRY_COUNT = @"retryCount";
NSString *const OM_PROP_CUSTOM_AUTH_HEADERS = @"CustomAuthHeaders";
NSString *const OM_PRINCIPAL = @"principal";
NSString *const OM_PROP_USERNAME_PARAM_NAME  = @"FedAuthUsernameParamName";
NSString *const OM_PROP_CUSTOM_HEADERS_FOR_MOBILE_AGENT
= @"CustomHeadersForMobileAgent";
//secure storage
NSString *const OM_DEFAULT_KEY               = @"defaultKey";
NSString *const OM_PIN_AUTHENTICATOR         = @"pinAuthenticator";
NSString *const OM_DEFAULT_AUTHENTICATOR     = @"defaultAuthenticator";
NSString *const OM_PBKDF2_SALT_ID = @"pbkdf2saltid";
NSString *const OM_PIN_VALIDATION_DATA_ID = @"pinvalidationid";
NSString *const OM_Pin_Auth_Keychain = @"omapinAuthKeyChain";
NSString *const OM_Touch_VALIDATION_DATA_ID = @"touchvalidationid";
NSString *const OM_KEK_ID = @"keykeychainkey";
NSString *const OM_PROP_LOCAL_AUTHENTICATOR_INSTANCE_ID = @"localauthenticatorinstanceid";
NSString *const OM_PROP_ENABLE_WKWEBVIEW = @"enablewkwebview";
NSString *const OM_CRED_FILE_LIST = @"credentialFileList";
NSString *const OM_PIN_LENGTH_KEY = @"pinLength";

///////////////////////////////////////////////////////////////////////////////
// OpenID Connect Constants
///////////////////////////////////////////////////////////////////////////////

NSString *const OM_PROP_OPENID_CONNECT_CONFIGURATION = @"OpenIDConnectConfiguration";
NSString *const OM_PROP_OPENID_CONNECT_CONFIGURATION_URL = @"OpenIDConnectDiscoveryURL";
NSString *const OM_PROP_OPENID_CONNECT_SERVER = @"OpenIDConnect10";
NSString *const OM_PROP_OPENID_CONNECT_REVOCATION_ENDPOINT = @"OpenIDConnect10RevocationEndPoint";
NSString *const OM_PROP_OPENID_CONNECT_USERINFO_ENDPOINT = @"OpenIDConnect10UserInfoEndPoint";
NSString *const OM_PROP_OPENID_CONNECT_CLAIMS = @"OpenIDConnect10Claims";
NSString *const OM_PROP_OPENID_CONNECT_ISSUER = @"OpenIDConnect10Issuer";
NSString *const OM_PROP_LOGOUT_REDIRECT_ENDPOINT = @"OpenIDConnect10LogoutRedirectEndpoint";

NSString *const OM_PROP_OPENID_CONNECT_SCOPE_OPENID  = @"openid";
NSString *const OM_PROP_OPENID_CONNECT_SCOPE_PROFILE  = @"profile";

NSString *const OM_PROP_ISSUER = @"issuer";
NSString *const OM_PROP_USERINFO_ENDPOINT = @"userinfo_endpoint";
NSString *const OM_PROP_REVOCATION_ENDPOINT = @"revocation_endpoint";
NSString *const OM_PROP_INTROSPECT_ENDPOINT = @"introspect_endpoint";
NSString *const OM_PROP_END_SESSION_ENDPOINT = @"end_session_endpoint";
NSString *const OM_PROP_JWKS_URI = @"jwks_uri";
NSString *const OM_PROP_SCOPES_SUPPORTED = @"scopes_supported";
NSString *const OM_PROP_RESPONSE_TYPES_SUPPORTED = @"response_types_supported";
NSString *const OM_PROP_SUBJECT_TYPES_SUPPORTED = @"subject_types_supported";
NSString *const OM_PROP_TOKEN_SIGN_ALGO_SUPPORTED = @"id_token_signing_alg_values_supported";
NSString *const OM_PROP_CLAIMS_SUPPORTED = @"claims_supported";
NSString *const OM_PROP_GRANT_TYPES_SUPPORTED = @"grant_types_supported";
NSString *const OM_PROP_TOKEN_ENDPOINT_AUTH_SUPPORTED = @"token_endpoint_auth_methods_supported";
NSString *const OM_PROP_TOKEN_ENDPOINT_AUTH_SIGNING_SUPPORTED = @"token_endpoint_auth_signing_alg_values_supported";
NSString *const OM_PROP_USERINFO_SIGNING_ALGO_SUPPORTED = @"userinfo_signing_alg_values_supported";
NSString *const OM_PROP_LOCALES_SUPPORTED = @"ui_locales_supported";
NSString *const OM_PROP_CLAIMS_PARAM_SUPPORTED = @"claims_parameter_supported";
NSString *const OM_PROP_HTTP_LOGOUT_SUPPORTED = @"http_logout_supported";
NSString *const OM_PROP_LOGOUT_SESSION_SUPPORTED = @"logout_session_supported";
NSString *const OM_PROP_REQUEST_PARAM_SUPPORTED = @"request_parameter_supported";
NSString *const OM_PROP_REQUEST_URI_SUPPORTED = @"request_uri_parameter_supported";
NSString *const OM_PROP_REQUIRE_REQ_URI_REG = @"require_request_uri_registration";
NSString *const OM_PROP_OAUTH_ENABLE_PKCE = @"OAuthEnablePKCE";
NSString *const OM_PROP_OAUTH_OAM_SERVICE_ENDPOINT = @"OAMOAuthServiceEndpoint";
NSString *const OM_OAM_OAUTH_TWO_LEGGED_REGISTRATION
= @"OAMOAuth2LeggedRegistration";
NSString *const OM_OAM_OAUTH_THREE_LEGGED_REGISTRATION
= @"OAMOAuth3LeggedRegistration";
NSString *const OM_LOGOUT_RESPONSE = @"logoutResponse";
NSString *const OM_PROP_AUTHORIZATION_ENDPOINT = @"authorization_endpoint";
NSString *const OM_PROP_TOKEN_ENDPOINT = @"token_endpoint";
NSString *const OM_PROP_REGISTRATION_ENDPOINT = @"registration_endpoint";
NSString *const OM_PROP_OPENID_CONFIGURATION = @"openid-configuration";


//Device Properties
NSString *const OM_HARDWAREIDS                    = @"hardwareIds";
NSString *const OM_DEVICE_UNIQUE_ID               = @"oracle:idm:claims:client:udid";
NSString *const OM_LOCALE                         = @"oracle:idm:claims:client:locale";
NSString *const OM_MACADDR                        = @"oracle:idm:claims:client:macaddress";
NSString *const OM_GEOLOCATION                    = @"oracle:idm:claims:client:geolocation";
NSString *const OM_OS_TYPE                        = @"oracle:idm:claims:client:ostype";
NSString *const OM_OS_VERSION                     = @"oracle:idm:claims:client:osversion";
NSString *const OM_CLIENT_SDK_VERSION             = @"oracle:idm:claims:client:sdkversion";
NSString *const OM_IMEI                           = @"oracle:idm:claims:client:imei";
NSString *const OM_PHONENUM                       = @"oracle:idm:claims:client:phonenumber";
NSString *const OM_ISJAILBROKEN                   = @"oracle:idm:claims:client:jailbroken";
NSString *const OM_NETWORKTYPE                    = @"oracle:idm:claims:client:networktype";
NSString *const OM_PHONECARRIER_NAME              = @"oracle:idm:claims:client:phonecarriername";
NSString *const OM_ISVPNENABLED                   = @"oracle:idm:claims:client:vpnenabled";
NSString *const OM_FINGERPRINT                    = @"oracle:idm:claims:client:fingerprint";
NSString *const OM_VENDOR_ID                      = @"oracle:idm:claims:client:iosidforvendor";
NSString *const OM_ADVERTISMENT_ID                = @"oracle:idm:claims:client:iosidforad";
NSString *const OM_APP_PROFILE                    = @"/oic_rest/rest/AppProfiles/";
NSString *const OM_DETECTION_LOCATION             = @"detectionLocation";
NSString *const OM_FILE_PATH                      = @"filePath";
NSString *const OM_CLIENT                         = @"client";
NSString *const OM_CLIENT_SDK_NAME                = @"clientSDKName";
NSString *const OM_CLIENT_SDK_NAME_VALUE          = @"Oracle Identity Management Mobile SDK";
NSString *const OM_CLIENT_SDK_VERSION_VALUE       = @"11.1.2.3.0";
NSString *const OM_FORCE_AUTH                     = @"isForceAuth";

// Hardware Properties
NSString *const OM_HARDWARE                       = @"hardware";
NSString *const OM_HARDWARE_PAGE_SIZE             = @"hardwarePageSize";
NSString *const OM_HARDWARE_PHYSICAL_MEMORY       = @"hardwarePhysicalMemory";
NSString *const OM_HARDWARE_CPU_FREQ              = @"hardwareCPUFrequency";
NSString *const OM_HARDWARE_BUS_FREQ              = @"hardwareBusFrequency";
NSString *const OM_HARDWARE_SYSTEM                = @"hardwareSystemName";
NSString *const OM_HARDWARE_NODE                  = @"hardwareNodeName";
NSString *const OM_HARDWARE_RELEASE               = @"hardwareRelease";
NSString *const OM_HARDWARE_VERSION               = @"hardwareVersion";
NSString *const OM_HARDWARE_MACHINE               = @"hardwareMachine";

// DYCR
NSString *const OM_PROP_IDCS_REGISTER_CLIENT = @"IDCSRegisterClient";
NSString *const OM_PROP_LOGIN_HINT = @"LoginHint";
NSString *const OM_PROP_IDCS_CLIENT_REGISTRATION_TOKEN = @"IDCSClientRegistrationToken";
NSString *const OM_PROP_IDCS_REGISTER_ENDPOINT = @"IDCSRegisterEndpoint";
NSString *const OM_PROP_OAUTH_DISCOVERY_URL = @"oauth_discoveryURL";

NSString *const OM_FACEBOOK_HOST = @".facebook.com";
NSString *const OM_PROP_SESSION_ACTIVE_ON_RESTART = @"SessionActiveOnRestart";

@implementation OMObject

- (instancetype)init
{
    self = [super init];
    if (self) {
        stringObj = nil;
        
    }
    return self;
}
///////////////////////////////////////////////////////////////////////////////
// messageForCode
///////////////////////////////////////////////////////////////////////////////
+ (NSString *)messageForCode: (NSUInteger)code, ...
{
    va_list args;
    va_start(args, code);
    NSString *msgKey           = [NSString stringWithFormat:@"%05lu",
                                  (unsigned long)code];
    NSString *localizedMessage = NSLocalizedStringFromTable(msgKey,
                                                            @"OMLocalizable",
                                                            nil);
    NSString *errorMessage     = nil;
    
    if( localizedMessage != nil )
    {
        errorMessage = [[NSString alloc] initWithFormat:localizedMessage
                                              arguments:args];
    }
    else
    {
        errorMessage = [[NSString alloc]
                        initWithFormat:@"Message for key %@ is not found.",
                        msgKey];
    }
    return errorMessage;
}

///////////////////////////////////////////////////////////////////////////////
// createErrorWithCode
///////////////////////////////////////////////////////////////////////////////
+ (NSError *)createErrorWithCode:(NSInteger)code, ...
{
    va_list args;
    va_start(args, code);
    NSString *msgKey             = [NSString stringWithFormat:@"%05lu",
                                    (long)code];
    NSString *localizedMessage   = NSLocalizedStringFromTable(msgKey,
                                                              @"OMLocalizable",
                                                              nil);
    NSMutableDictionary *details = [[NSMutableDictionary alloc] initWithCapacity:1];
    NSString *errorMessage       = nil;
    
    if( localizedMessage != nil )
    {
        errorMessage = [[NSString alloc] initWithFormat:localizedMessage
                                              arguments:args];
    }
    else
    {
        errorMessage = [[NSString alloc]
                        initWithFormat:@"Message for key %@ is not found.",
                        msgKey];
    }
    [details setValue:errorMessage forKey:NSLocalizedDescriptionKey];
    
    NSError  *error       = [[NSError alloc] initWithDomain:OM_ERROR_DOMAIN_NAME
                                                       code:code
                                                   userInfo:details];
    return error;
}

///////////////////////////////////////////////////////////////////////////////
// createErrorWithCodeandMessage
///////////////////////////////////////////////////////////////////////////////
+ (NSError *)createErrorWithCode:(NSInteger)code andMessage:(NSString *)errorMessage
{
    NSMutableDictionary *details = [[NSMutableDictionary alloc] initWithCapacity:1];
    [details setValue:errorMessage forKey:NSLocalizedDescriptionKey];
    NSError  *error       = [[NSError alloc] initWithDomain:OM_ERROR_DOMAIN_NAME
                                                       code:code
                                                   userInfo:details];
    return error;
}

+ (BOOL)checkConnectivityToHost:(NSURL*)hostUrl
{
    __block BOOL isHostReachable = NO;
    
    if ([self isNetworkReachable])
    {
        dispatch_semaphore_t    sem;
        sem = dispatch_semaphore_create(0);
        
        NSMutableURLRequest *request =
        [NSMutableURLRequest requestWithURL:hostUrl
                             cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                            timeoutInterval:10.0];
        
        [request setHTTPMethod:@"HEAD"];

        [[[NSURLSession sharedSession] dataTaskWithRequest:request
                                         completionHandler:^
          (NSData *data,NSURLResponse *response,NSError *error)
          {
              if (!error)
              {
                  isHostReachable = YES;
              }
              dispatch_semaphore_signal(sem);
          }] resume];
        
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    }
   
    return isHostReachable;
}

+ (BOOL)isHostReachable:(NSString *)host
{
    OMReachability *reachability = [OMReachability reachabilityWithHostName:host];
    NetworkStatus status = [reachability currentReachabilityStatus];
    return !(status == NotReachable);
}

+ (BOOL)isNetworkReachable
{
    OMReachability *reachability = [OMReachability reachabilityForInternetConnection];
    NetworkStatus status = [reachability currentReachabilityStatus];
    return !(status == NotReachable);
}

///////////////////////////////////////////////////////////////////////////////
// isURL: EqualTo:
// Compares two given URLs. NSURL's isEqual does not work well in our case
// as SSO server can append additional query parameters to success URL or
// failure URL
///////////////////////////////////////////////////////////////////////////////
+ (BOOL) isCurrentURL:(NSURL *)currentURL EqualTo:(NSURL *)expectedURL
{
    if ([currentURL isEqual:expectedURL])
        return TRUE;
    
    if (NSOrderedSame != [[currentURL scheme]
                          caseInsensitiveCompare:[expectedURL scheme]])
        return FALSE;
    
    if (NSOrderedSame != [[currentURL host]
                          caseInsensitiveCompare:[expectedURL host]])
        return FALSE;
    
    if (NSOrderedSame != [[currentURL port] compare:[expectedURL port]])
        return FALSE;
    
    NSString *currentURLPath = [currentURL path];
    NSString *expectedURLPath = [expectedURL path];
    
    //If current URL and expected URL are same except that there is "/" at the
    //end, comparison returns FALSE. But it shall return TRUE. Hence
    //the following check
    if (NSOrderedSame != [currentURLPath compare:expectedURLPath])
    {
        if (((NSOrderedSame == [currentURLPath compare:@"/"]) &&
             (0 == [expectedURLPath length])) ||
            ((0 == [currentURLPath length]) &&
             (NSOrderedSame == [expectedURLPath compare:@"/"])))
        {
            //Do Nothing
        }
        else
            return FALSE;
    }
    
    NSString *expectedURLQuery = [expectedURL query];
    NSString *currentURLQuery = [currentURL query];
    
    if (expectedURLQuery != nil && currentURLQuery == nil)
        return FALSE;
   
    if ((expectedURLQuery != nil && currentURLQuery != nil) &&
        NSOrderedSame ==[expectedURLQuery caseInsensitiveCompare:currentURLQuery])
    {
        return TRUE;
    }

    //Support wildcard characters in query component to support apex
    //applications using corporate SSO. In case of APEX application, sessionid
    //is appended to login success URL. Since login URL and login success URL
    //are same and differentiated only with sessionid in query parameter, Also login URL gets loaded and java script
    //triggers SSO authentication. Hence current
    NSRange range = [expectedURLQuery rangeOfString:@"*"];
    if (range.location != NSNotFound && range.length != 0)
    {
        NSString *expression = [expectedURLQuery stringByReplacingOccurrencesOfString:@"*" withString:@".*"];
        NSError *error = nil;
        NSRegularExpression *regex = [[NSRegularExpression alloc]
                                      initWithPattern:expression
                                      options:NSRegularExpressionCaseInsensitive
                                      error:&error];
        if (error == nil)
        {
            NSRange rangeOfFirstMatch = [regex rangeOfFirstMatchInString:currentURLQuery
                                                                 options:0
                                                                   range:NSMakeRange(0, [currentURLQuery length])];
            if (NSNotFound == rangeOfFirstMatch.location &&
                0 == rangeOfFirstMatch.length)
                return FALSE;
            else
                return TRUE;
        }
    }
    
    //currentURL's query can have more query components than what expected
    //URL has. But current URL's query component shall begin with expected
    //URL's query. This is because SSO server will add return URL to success
    //or failure URL
    if (expectedURLQuery != nil)
    {
        NSString *expectedQuery = [expectedURLQuery stringByAppendingString:@"&"];
        if (NO == [currentURLQuery hasPrefix:expectedQuery])
            return FALSE;
    }
    
    return TRUE;
}

+(NSString *)version
{
    return OM_VERSION;
}


@end
