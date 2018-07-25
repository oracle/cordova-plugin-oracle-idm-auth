/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


///////////////////////////////////////////////////////////////////////////////
// Define all error codes here. It shall be of the format given below. Assign
// the error codes in sequence. Do not jump or start assign error codes in new
// series. Number of digits shall not exceed five digits. For each error code,
// make corresponding error message entry in resource bundle 
// OMLocalizable.strings file. Error look up key shall also be the same number
// but in string format. When you add string look up key in
// OMLocalizable.strings file, ensure that it is added in 5 digit format. For
// example, if you are error code is 7, resource bundle look-up key is "00007".
//
//      OMERR_ERROR_CODE_NAME                                          ERROR
//                                                                      CODE
//----- -------------------------------------------------------------- ----- --
///////////////////////////////////////////////////////////////////////////////

//#define OMERR_NOT_FOUND                                                  132
//#define OMERR_UNSUPPORTED_URL                                            133
//#define OMERR_SERVER_UNREACHABLE                                         135
//#define OMERR_SERVER_ERROR                                               136
//#define OMERR_INVALID_LOGOUT_URL                                         137
//#define OMERR_USER_CANCELLED_IMPORT                                      140
//#define OMERR_OAUTH_GRANT_NOT_ALLOWED                                    141
//#define OMERR_OAUTH_SERVER_SSO_NOT_SUPPORTED                             142
//#define OMERR_ACTION_NOT_ALLOWED                                         144
//#define OMERR_MAXIMUM_LOGIN_ATTEMPTS_EXCEEDED                            145


#define OMERR_NETWORK_UNAVAILABLE                                         00134


#define OMERR_SUCCESS                                                     10000
#define OMERR_COULD_NOT_CONNECT_TO_SERVER                                 10001
#define OMERR_INVALID_USERNAME_PASSWORD                                   10003
#define OMERR_OIC_SERVER_RETURNED_ERROR                                   10005
#define OMERR_INITIALIZATION_FAILED                                       10025
#define OMERR_LOGOUT_FAILED                                               10035
#define OMERR_USER_AUTHENTICATION_FAILED                                  10408
#define OMERR_INVALID_USERNAME_PASSWORD_IDENTITY                          10011
#define OMERR_USER_CANCELED_AUTHENTICATION                                10029
#define OMERR_DENIED_ACTION                                               10030
#define OMERR_NO_IDENTITY                                                 10037
#define OMERR_INVALID_PASSWORD                                            10038
#define OMERR_AUTHENTICATION_TIMED_OUT                                    10042
#define OMERR_OUT_OF_RANGE                                                10403
#define OMERR_WEBVIEW_REQUIRED                                            10017
#define OMERR_INVALID_SEND_CUSTOM_HEADERS_LOGOUT                          10018
#define OMERR_INVALID_SEND_AUTH_HEADER_LOGOUT                             10019
#define OMERR_WKWEBVIEW_REQUIRED                                          10020
#define OMERR_INVALID_CUSTOM_HEADERS                                      10021

#define OMERR_KEY_IS_NIL                                                  10501
#define OMERR_INVALID_INPUT                                               10502
#define OMERR_INVALID_CRYPTO_SCHEME                                       10503
///////////////////////////////////////////////////////////////////////////////
// OMCryptoService Messages
///////////////////////////////////////////////////////////////////////////////
#define OMERR_MEMORY_ALLOCATION_FAILURE                                   10503
#define OMERR_RANDOM_GENERATOR_SYSTEM_ERROR                               10504
#define OMERR_REQUESTED_LENGTH_TOO_SHORT                                  10505
#define OMERR_INPUT_TEXT_CANNOT_BE_EMPTY                                  10406
#define OMERR_MAX_RETRIES_REACHED                                         10418
#define OMERR_UNKNOWN_OR_UNSUPPORTED_ALGORITHM                            10506
#define OMERR_KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM                         10507
#define OMERR_IV_LENGTH_MUST_MATCH_ALGORITHM_BLOCK_SIZE                   10508
#define OMERR_PADDING_REQUIRED                                            10509
#define OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING                              10510
#define OMERR_ENCRYPTION_SYSTEM_ERROR                                     10511
#define OMERR_REQUESTED_LENGTH_NOT_A_MULTIPLE_OF_4                        10512
#define OMERR_SALT_REQUIRED_FOR_CHOSEN_ALGORITHM                          10513
#define OMERR_SALT_NOT_SUPPORTED_FOR_CHOSEN_ALGORITHM                     10514
#define OMERR_CANNOT_PREFIX_SALT_IN_NON_SALTED_ALGORITHM                  10515
#define OMERR_INPUT_NOT_PREFIXED_WITH_ALGORITHM_NAME                      10516
#define OMERR_INPUT_MUST_BE_NSSTRING_WHEN_BASE64_IS_ENABLED               10517
#define OMERR_UNKNOWN_INPUT_TYPE                                          10518
#define OMERR_INPUT_LENGTH_MUST_BE_LESS_THAN_OR_EQUAL_TO                  10519
#define OMERR_KEYPAIR_GENERATION_SYSTEM_ERROR                             10520
#define OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN                    10521
#define OMERR_KEYCHAIN_SYSTEM_ERROR                                       10522
#define OMERR_KEYCHAIN_ITEM_NOT_FOUND                                     10523
#define OMERR_SIGNING_SYSTEM_ERROR                                        10524
#define OMERR_INPUT_SIGN_CANNOT_BE_EMPTY                                  10525
#define OMERR_VERIFICATION_SYSTEM_ERROR                                   10526
#define OMERR_DECRYPTION_SYSTEM_ERROR                                     10527
#define OMERR_KEYCHAIN_ITEM_ALREADY_FOUND                                 10528
#define OMERR_UNKNOWN_OR_UNSUPPORTED_KEY_TYPE                             10529
#define OMERR_INVALID_KEYCHAIN_DATA_PROTECTION_LEVEL                      10530
#define OMERR_PBKDF2_KEY_GENERATION_ERROR                                 10531
#define OMERR_DELEGATE_NOT_SET                                            10532
#define OMERR_RESOURCE_FILE_PATH                                          10533
#define OMERR_LOGIN_IS_IN_PROGRESS                                        10534

#define OMERR_INVALID_APP_NAME                                            10100
#define OMERR_LOGIN_URL_IS_INVALID                                        10101
#define OMERR_LOGOUT_URL_IS_INVALID                                       10102
#define OMERR_INVALID_SESSION_TIMEOUT_TIME                                10103
#define OMERR_INVALID_IDLE_TIMEOUT_TIME                                   10104
#define OMERR_INVALID_IDLE_DELTA                                          10105
#define OMERR_INVALID_RETRY_COUNTS                                        10106
#define OMERR_INVALID_REQUIRED_TOKENS                                     10107
#define OMERR_INVALID_IDENTITY_DOMAIN                                     10108
#define OMERR_INVALID_COLLECT_IDENTITY_DOMAIN                             10109
#define OMERR_INVALID_REMEMBER_CREDENTAILS_ENABLED                        10110
#define OMERR_INVALID_REMEMBER_USERNAME_DEFAULT                           10111
#define OMERR_INVALID_AUTOLOGIN                                           10112
#define OMERR_INVALID_REMEMBER_CREDENTIALS                                10113
#define OMERR_INVALID_REMEMBER_USERNAME                                   10114
#define OMERR_INVALID_AUTH_SERVER_TYPE                                    10115
#define OMERR_INVALID_OFFLINE_AUTH_ALLOWED                                10116
#define OMERR_INVALID_CONNECTIVITY_MODE                                   10117
#define OMERR_INVALID_PRESENT_IDENTITY_ON_DEMAND                          10118
#define OMERR_INVALID_BROWSERMODE                                         10119

#define OMERR_INVALID_CLIENT_CERTIFICATE                                  30004

#define OMERR_FEDAUTH_LOGIN_SUCCESS_URL_IS_INVALID                        50001
#define OMERR_FEDAUTH_LOGIN_FAILURE_URL_IS_INVALID                        50002
#define OMERR_PARSE_TOKEN_RELAY_RESPONSE_INVALID                          50003

#define OMERR_IDCS_CLIENT_REGISTRATION_FAILED                             50300
#define OMERR_IDCS_CLIENT_REGISTRATION_UNABLE_TO_OBTAIN_AT                50301
#define OMERR_IDCS_CLIENT_REGISTRATION_PARSING_FAILED                     50302
#define OMERR_IDCS_CLIENT_REGISTRATION_INVALID_ENDPOINT                   50303
#define OMERR_IDCS_CLIENT_REGISTRATION_TOKEN_EMPTY                        50400

#define OMERR_OAUTH_UNSUPPORTED_RESPONSE_TYPE                             40211
#define OMERR_OAUTH_UNAUTHORIZED_CLIENT                                   40214
#define OMERR_OAUTH_STATE_INVALID                                         40220
#define OMERR_OAUTH_INVALID_REQUEST                                       40230
#define OMERR_OAUTH_ACCESS_DENIED                                         40231
#define OMERR_OAUTH_INVALID_SCOPE                                         40232
#define OMERR_OAUTH_SERVER_ERROR                                          40233
#define OMERR_OAUTH_TEMPORARILY_UNAVAILABLE                               40234
#define OMERR_OAUTH_OTHER_ERROR                                           40235
#define OMERR_OAUTH_BAD_REQUEST                                           40236
#define OMERR_OAUTH_CLIENT_ASSERTION_REVOKED                              40237
#define OMERR_OAUTH_INVALID_CLIENT                                        40239
#define OMERR_OAUTH_INVALID_GRANT                                         40240
#define OMERR_OAUTH_CLIENT_SECRET_INVALID                                 40241
#define OMERR_OAUTH_CLIENT_ID_INVALID                                     40242
#define OMERR_OAUTH_TOKEN_ENDPOINT_INVALID                                40243
#define OMERR_OAUTH_AUTHZ_ENDPOINT_INVALID                                40244
#define OMERR_OAUTH_REDIRECT_ENDPOINT_INVALID                             40245
#define OMERR_INVALID_APP_RESPONSE                                        40246

///////////////////////////////////////////////////////////////////////////////
// Open ID Error Codes
///////////////////////////////////////////////////////////////////////////////

#define OMERR_OIDC10_UNAUTHORIZED_ISSUER                                  60001
#define OMERR_OIDC10_USERINFO_ENDPOINT_INVALID                            60002
#define OMERR_OIDC10_REVOCATION_ENDPOINT_INVALID                          60003
#define OMERR_OIDC10_INVALID_CLAIMS                                       60004
#define OMERR_OIDC10_UNKNOWN                                              60005
#define OMERR_OIDC10_INVALID_JSON                                         60007
#define OMERR_OIDC10_DISCOVERY_ENDPOINT_INVALID                           60008

    //secure
#define OMERR_AUTHDATA_ALREADY_SET                                        70007
#define OMERR_AUTHDATA_NOT_SET                                            70008
#define OMERR_INCORRECT_CURRENT_AUTHDATA                                  70009
#define OMERR_FILE_NOT_FOUND                                              75001
#define OMERR_AUTHENTICATOR_NOT_REGISTERED                                70001
#define OMERR_KEY_NOT_FOUND                                               75002
#define OM_KEYSTORE_EXIST                                                 71000
#define OMERR_AUTHENTICATOR_ALREADY_REGISTERED                            70012
#define OMERR_KEYSTORE_FILE_CREATION_FAILED                               70013
#define OMERR_KEY_ALREADY_FOUND                                           70014
#define OMERR_PIN_CHANGE_FAILED                                           70015
#define OMERR_LOCAL_AUTH_NOT_AUTHENTICATED                                70016
#define OMERR_KEYCHAIN_CANNOT_BE_NIL                                      70017

///////////////////////////////////////////////////////////////////////////////
// End of OMErrorCodes.h
///////////////////////////////////////////////////////////////////////////////
