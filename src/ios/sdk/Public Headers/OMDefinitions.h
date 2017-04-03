/* Copyright (c) 2011, 2015, Oracle and/or its affiliates. 
All rights reserved.*/

/*
 NAME
   OMDefinitions.h - Oracle Mobile constant Definitions
 
 DESCRIPTION
   This header file is just for definitions.
 
 RELATED DOCUMENTS
   None
 
 PROTOCOLS
   None
 
 EXAMPLES
   None
 
 NOTES
   None
 
 MODIFIED   (MM/DD/YY)
 asashiss    06/23/16 - OMSS-29864
 asashiss    06/23/16 - OMSS-29780
 asashiss    04/13/16 - OAuth browser modes
 asashiss    04/11/16 - MCS parse token relay changes
 shivap      04/28/16 - OMSS 28260
 shivap      03/15/16 - Added varibles related to Fed auth implementation
 shivap      03/10/16 - Added varibles to fix OMSS-28206
 shivap      02/10/16 - Added remember password constants
 SHIVAP    04/02/16 - Creation
 */


#import <Foundation/Foundation.h>


/**
 * Macro for logging error message only in debug mode and not in release
 * mode
 */
#ifdef DEBUG
#   define OMDebugLogF(fmt, ...) NSLog((@"%s:%s[Line #:%d]: " fmt), __FILE__, \
                                       __PRETTY_FUNCTION__, __LINE__, \
                                       ##__VA_ARGS__);
#   define OMDebugLogNF(fmt, ...) NSLog((@"%s[Line #:%d]: " fmt), \
                                        __PRETTY_FUNCTION__, __LINE__, \
                                        ##__VA_ARGS__);
#   define OMDebugLog  OMDebugLogNF
#   define OMDebugLogError(err)  NSLog(@"%s:%s[Line #:%d]: Error %@-%05ld:%@", \
                                       __FILE__, __PRETTY_FUNCTION__, \
                                       __LINE__,  [(err) domain], \
                                      (long)[(err) code], \
                                      [(err) localizedDescription] );
#else
#   define OMDebugLogF(...)
#   define OMDebugLogNF(...)
#   define OMDebugLog(...)
#   define OMDebugLogError(...)
#endif

/**
 * Macro for logging error message with file name, function name, line #,
 * error domain, error code, and error message. File name will not be used
 * if logged using this macro.
 */
#define OMLogWithOutF(fmt, ...)  NSLog((@"%s[Line #:%d]: " fmt), \
                                       __PRETTY_FUNCTION__, __LINE__, \
                                       ##__VA_ARGS__);

/**
 * Macro for logging error message with file name, function name, line #,
 * error domain, error code, and error message.
 */
#define OMLogWithF(fmt, ...) NSLog((@"%s:%s[Line #:%d]: " fmt), __FILE__, \
                                   __PRETTY_FUNCTION__, __LINE__, \
                                   ##__VA_ARGS__);

/**
 * All functions will be using OMLog to log message. OMLog is defined to use
 * OMLogWithF - Log with file name, function name, line #, and message.
 */
#define OMLog   OMLogWithOutF


/**
 * Macro for logging error message with file name, function name, line #,
 * error domain, error code, and error message
 */
#define OMLogError(err)  NSLog(@"%s:%s[Line #:%d]: Error %@-%05ld:%@",__FILE__,\
                                          __PRETTY_FUNCTION__, __LINE__,  \
                                         [(err) domain], (long)[(err) code], \
                                         [(err) localizedDescription] );

/**
 * Macro for logging version of SDK
 */
#define OMLogVersion  NSLog(@"%@", OM_VERSION);

#define SYSTEM_VERSION_EQUAL_TO(v)              \
    ([[[UIDevice currentDevice] systemVersion]  \
    compare:(v) options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v)          \
    ([[[UIDevice currentDevice] systemVersion]  \
    compare:(v) options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  \
    ([[[UIDevice currentDevice] systemVersion]  \
    compare:(v) options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v)             \
    ([[[UIDevice currentDevice] systemVersion]  \
    compare:(v) options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v) \
    ([[[UIDevice currentDevice] systemVersion]  \
    compare:(v) options:NSNumericSearch] != NSOrderedDescending)

///////////////////////////////////////////////////////////////////////////////
// DEVICE HEIGHT AND WIDTH
///////////////////////////////////////////////////////////////////////////////
#define omScreenWidth  [[UIScreen mainScreen] bounds].size.width
#define omScreenHeight [[UIScreen mainScreen] bounds].size.height
///////////////////////////////////////////////////////////////////////////////
// DEVICE FINGERPRINTING OR IDENTITY CONTEXT RELATED DEFINITIONS
///////////////////////////////////////////////////////////////////////////////
#define OM_NEXT_AUTH_STEP_NONE                       0
#define OM_NEXT_AUTH_STEP_AUTH_FAILED                1
#define OM_NEXT_AUTH_STEP_DEVICE_REGISTRATION        2
#define OM_NEXT_AUTH_STEP_REST                       3
#define OM_NEXT_AUTH_STEP_KBAAUTH                    4
#define OM_NEXT_AUTH_STEP_AUTHSCHEME                 5
#define OM_NEXT_REG_STEP_NONE                        6
#define OM_NEXT_AUTH_STEP_CLIENTAPP_REG              7
#define OM_NEXT_AUTH_STEP_RP_AUTH                    8
#define OM_NEXT_POSTAUTH_STEP_KBAAUTH                9
#define OM_NEXT_EXCHANGE_AUTHZ_CODE                 10
#define OM_NEXT_OAUTH_AUTHORIZATION                 11
#define OM_NEXT_OAUTH_CLIENT_ASSERTION              12
#define OM_NEXT_OAUTH_CLIENT_REGISTER_AUTHZ         13
#define OM_NEXT_OAUTH_USER_ASSERTION                14
#define OM_NEXT_OAUTH_KBAAUTH                       15
#define OM_NEXT_OFFLINE_AUTH                        16
#define OM_NEXT_ONLINE_AUTH                         17
#define OM_NEXT_AUTH_STEP_CHALLENGE                 18

#define OM_CRYPTO_SCHEME_PLAIN_TEXT                  0
#define OM_CRYPTO_SCHEME_SHA1                        1
#define OM_CRYPTO_SCHEME_SHA224                      2
#define OM_CRYPTO_SCHEME_SHA256                      3
#define OM_CRYPTO_SCHEME_SHA384                      4
#define OM_CRYPTO_SCHEME_SHA512                      5
#define OM_CRYPTO_SCHEME_SSHA1                       6
#define OM_CRYPTO_SCHEME_SSHA224                     7
#define OM_CRYPTO_SCHEME_SSHA256                     8
#define OM_CRYPTO_SCHEME_SSHA384                     9
#define OM_CRYPTO_SCHEME_SSHA512                    10
#define OM_CRYPTO_SCHEME_AES                        11

#define OM_HTTP_STATUS_OK                          200
#define OM_HTTP_STATUS_CREATED                     201
#define OM_HTTP_STATUS_REDIRECTION                 300
#define OM_HTTP_STATUS_BAD_REQUEST                 400
#define OM_HTTP_STATUS_AUTH_DENIED                 401
#define OM_HTTP_STATUS_UNAUTHORIZED                403
#define OM_HTTP_STATUS_NOT_FOUND                   404

#define DERIVED_KEY_LEN                            32 
#define PBKDF2_SALT_LENGTH                          16
#define PBKDF2_ITERATION_COUNT                     1000
#define PBKDF2_KEY_LENGTH                           32
#define PIN_VALIDATION_DATA_LENGTH                  128

enum
{
    PlainText = 0,
    SHA1 = 1,
    SHA224 = 2,
    SHA256 = 3,
    SHA384 = 4,
    SHA512 = 5,
    SSHA1 = 6,
    SSHA224 = 7,
    SSHA256 = 8,
    SSHA384 = 9,
    SSHA512 = 10,
    AES = 11
};
typedef NSUInteger OMCryptoScheme;
extern NSString *const OM_KEYPAIR_TAG_PRIVATE;
extern NSString *const OM_KEYPAIR_TAG_PUBLIC;
extern NSString *const OM_CRYPTO_DES;
extern NSString *const OM_CRYPTO_3DES;
extern NSString *const OM_CRYPTO_MD5;
extern NSString *const OM_CRYPTO_SMD5;
extern NSString *const OM_NOTIFICATION_CERT_PROMPT;
extern NSString *const OM_NOTIFICATION_CERT_PERMISSION;

extern NSString *const OM_PROP_CRYPTO_SCHEME;
extern NSString *const OM_PROP_CRYPTO_PLAINTEXT;
extern NSString *const OM_PROP_CRYPTO_SHA1;
extern NSString *const OM_PROP_CRYPTO_SHA224;
extern NSString *const OM_PROP_CRYPTO_SHA256;
extern NSString *const OM_PROP_CRYPTO_SHA384;
extern NSString *const OM_PROP_CRYPTO_SHA512;
extern NSString *const OM_PROP_CRYPTO_SSHA1;
extern NSString *const OM_PROP_CRYPTO_SSHA224;
extern NSString *const OM_PROP_CRYPTO_SSHA256;
extern NSString *const OM_PROP_CRYPTO_SSHA384;
extern NSString *const OM_PROP_CRYPTO_SSHA512;
extern NSString *const OM_PROP_CRYPTO_AES;

///////////////////////////////////////////////////////////////////////////////
// KEYCHAIN DATA PROTECTION LEVELS
///////////////////////////////////////////////////////////////////////////////
extern NSString *const OM_PROP_KEYCHAIN_DATA_PROTECTION;
extern NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED;
extern NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_AFTER_FIRST_UNLOCK;
extern NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_ALWAYS;
extern NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY;
extern NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY;
extern NSString *const OM_KEYCHAIN_DATA_ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY;

extern NSString *const OM_PROP_NSUSERDEFAULTS_KEY;
extern NSString *const OM_PROP_REQUIRED_TOKENS;
extern NSString *const OM_PROP_LOGIN_URL;
extern NSString *const OM_PROP_LOGOUT_URL;
extern NSString *const OM_PROP_LOGIN_SUCCESS_URL;
extern NSString *const OM_PROP_LOGIN_FAILURE_URL;
extern NSString *const OM_PROP_AUTHSERVER_TYPE;
extern NSString *const OM_PROP_AUTHSERVER_HTTPBASIC;
extern NSString *const OM_PROP_APPNAME;
extern NSString *const OM_USERNAME;
extern NSString *const OM_PASSWORD;
extern NSString *const OM_IDENTITY_DOMAIN;
extern NSString *const OM_PROP_SESSION_TIMEOUT_VALUE;
extern NSString *const OM_PROP_IDLE_TIMEOUT_VALUE;
extern NSString *const OM_PROP_PERCENTAGE_TO_IDLE_TIMEOUT;
extern NSString *const OM_PROP_MAX_LOGIN_ATTEMPTS;
extern NSString *const OM_PROP_CONNECTIVITY_MODE;
extern NSString *const OM_CONNECTIVITY_AUTO;
extern NSString *const OM_CONNECTIVITY_OFFLINE;
extern NSString *const OM_CONNECTIVITY_ONLINE;
extern NSString *const OM_PROP_OFFLINE_AUTH_ALLOWED;

extern NSString *const OM_CHALLENGE_FINISHED;
extern NSString *const OM_CLIENT_CERT_PROMPT;
extern NSString *const OM_CLIENT_CERT_SELECTED;
extern NSString *const OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND;
extern NSString *const OM_CERT_VALID_FROM;
extern NSString *const OM_CERT_VALID_TILL;
extern NSString *const OM_CERT_IMPORT_RETRY;
extern NSString *const OM_CLIENTCERTS;
extern NSString *const OM_SELECTED_CERT;
extern NSString *const OM_CERT_DESC;
extern NSString *const OM_TRUST_SERVER_CHALLANGE;
///////////////////////////////////////////////////////////////////////////////
// Remember Credentials
///////////////////////////////////////////////////////////////////////////////
extern NSString *const OM_PROP_AUTO_LOGIN_ALLOWED;
extern NSString *const OM_PROP_REMEMBER_CREDENTIALS_ALLOWED;
extern NSString *const OM_PROP_REMEMBER_USERNAME_ALLOWED;
extern NSString *const OM_AUTO_LOGIN_DEFAULT;
extern NSString *const OM_REMEMBER_CREDENTIALS_DEFAULT;
extern NSString *const OM_REMEMBER_USERNAME_DEFAULT;
extern NSString *const OM_REMEMBER_CRED_PREF_SET;
extern NSString *const OM_AUTO_LOGIN_PREF;
extern NSString *const OM_REMEMBER_CREDENTIALS_PREF;
extern NSString *const OM_REMEMBER_USERNAME_PREF;
extern NSString *const OM_AUTH_SUCCESS;
extern NSString *const OM_PROP_COLLECT_IDENTITY_DOMAIN;
extern NSString *const OM_PROP_IDENTITY_DOMAIN_NAME;
extern NSString *const OM_PROP_LOGIN_TIMEOUT_VALUE;
extern NSString *const OM_PROP_AUTH_KEY;
extern NSString *const OM_PROP_SESSION_TIMEOUT_VALUE;
extern NSString *const OM_PROP_IDLE_TIMEOUT_VALUE;
extern NSString *const OM_PROP_MAX_LOGIN_ATTEMPTS;
extern NSString *const OM_PROP_REQUIRED_TOKENS;

extern NSString *const OM_PROP_AUTHSERVER_CLIENT_CERT;
extern NSString *const OM_PROP_OAUTH_OAUTH20_SERVER;
extern NSString *const OM_PROP_OAUTH_CLIENT_ID;
extern NSString *const OM_PROP_OAUTH_CLIENT_SECRET;
extern NSString *const OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE ;
extern NSString *const OM_OAUTH_RESOURCE_OWNER;
extern NSString *const OM_OAUTH_AUTHORIZATION_CODE;
extern NSString *const OM_OAUTH_IMPLICIT;
extern NSString *const OM_OAUTH_CLIENT_CREDENTIALS;
extern NSString *const OM_OAUTH_ASSERTION;
extern NSString *const OM_OAUTH_OAM_CREDENTIAL;
extern NSString *const OM_PROP_OAUTH_SCOPE;
extern NSString *const OM_PROP_OAUTH_TOKEN_ENDPOINT;
extern NSString *const OM_OAUTH_BACK_CHANNEL;
extern NSString *const OM_OAUTH_BACK_CHANNEL_REQUEST_URL;
extern NSString *const OM_OAUTH_BACK_CHANNEL_PAYLOAD;
extern NSString *const OM_OAUTH_BACK_CHANNEL_HEADERS;
extern NSString *const OM_OAUTH_BACK_CHANNEL_REQUEST_TYPE;
extern NSString *const OM_AUTHORIZATION;
extern NSString *const OM_DEFAULT_IDENTITY_DOMAIN_HEADER;
extern NSString *const OM_OAUTH_ERROR_INAVLID_REQUEST;
extern NSString *const OM_OAUTH_ERROR_UNAUTHORIZED_CLIENT;
extern NSString *const OM_OAUTH_ERROR_ACCESS_DENIED;
extern NSString *const OM_OAUTH_ERROR_UNSUPPORTED_RESPONSE;
extern NSString *const OM_OAUTH_ERROR_SERVER_ERROR;
extern NSString *const OM_OAUTH_ERROR_TEMPORARILY_UNAVAILABLE;
extern NSString *const OM_OAUTH_ERROR_TIMEOUT;
extern NSString *const OM_OAUTH_CLIENT_ASSERTION_REFRESH_TOKEN;
extern NSString *const OM_STATUS_DENIED;
extern NSString *const OM_PROP_AUTHSERVER_FED_AUTH;
extern NSString *const OM_PROP_AUTH_WEBVIEW;
extern NSString *const OM_FED_AUTH_QUERY_PARAMS;
extern NSString *const OM_FED_AUTH_HEADERS;
extern NSString *const OM_ERROR;
extern NSString *const OM_VISITED_HOST_URLS;
extern NSString *const OM_PROP_COOKIES;
extern NSString *const OM_CUSTOM_HEADERS_MOBILE_AGENT;
extern NSString *const OM_PROP_CREDENTIALS;
extern NSString *const OM_PROP_CREDENTIALS_USERNAME;
extern NSString *const OM_PROP_CREDENTIALS_PASSWORD;
extern NSString *const OM_PROP_TOKENS;
extern NSString *const OM_PROP_CREDENTIALS_ERROR;
extern NSString *const OM_OAUTH_ACCESS_TOKEN;
extern NSString *const OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER;
extern NSString *const OM_PROP_IDENTITY_DOMAIN_HEADER_NAME;
extern NSString *const OM_DEFAULT_IDENTITY_DOMAIN_HEADER;
extern NSString *const OM_PROP_OAUTH_AUTHORIZATION_ENDPOINT;
extern NSString *const OM_PROP_OAUTH_REDIRECT_ENDPOINT;
extern NSString *const OM_PROP_BROWSERMODE;
extern NSString *const OM_PROP_BROWSERMODE_EMBEDDED;
extern NSString *const OM_PROP_BROWSERMODE_EXTERNAL;
extern NSString *const OM_MAX_RETRY;
extern NSString *const OM_PROP_PARSE_TOKEN_RELAY_RESPONSE;
extern NSString *const OM_TOKENS;
extern NSString *const OM_ACCESS_TOKEN;

extern NSString *const OM_INVALID_REDIRECT;
extern NSString *const OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT;
extern NSString *const OM_PROP_SEND_AUTHORIZATION_HEADER_DURING_LOGOUT;
extern NSString *const OM_MOBILESECURITY_EXCEPTION;
extern NSString *const OM_RETRY_COUNT;
extern NSString *const OM_PROP_CUSTOM_AUTH_HEADERS;
extern NSString *const OM_PROP_TOKENS;

//Webkit

extern NSString *const OM_PROP_ENABLE_WKWEBVIEW;

///////////////////////////////////////////////////////////////////////////////
// End of OMDefinitions.h
///////////////////////////////////////////////////////////////////////////////
