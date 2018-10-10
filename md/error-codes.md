# Error codes and its meanings.

Error Code | Short description
---------- | -----------------
10001 | Could not connect to server
10003 | username or password invalid
10005 | Could not parse response from server
10011 | username, password or tenant invalid
10015 | setup failed default
10021 | Setup is not invoked
10023 | Not yet authenticated
10025 | Initialization failed
10029 | User cancelled authentication
10030 | user denied
10034 | Logout timed out
10035 | Logout failed
10036 | Username required
10037 | Identity domain required
10039 | Password required
10040 | Username and Identity domain are required
10041 | Application not available
10042 | Authentication timed out
10043 | Logout is in progress
10044 | Network not available
10045 | Challenge input response is invalid
10100 | Invalid app name
10101 | invalid login URL
10102 | invalid logout URL
10103 | invalid session timeout time
10104 | Invalid idle session timeout time
10105 | invalid idle session timeout delta
10106 | Invalid retry counts
10107 | Invalid required tokens format
10108 | Invalid identity domain format
10109 | Invalid collect identity domain format
10110 | Invalid remember credentials enabled parm
10111 | Invalid remember username default   parm
10112 | Invalid autologin parm
10113 | invalid remember credentails parm
10114 | invalid remember username parm
10115 | Invalid auth server type
10116 | INVALID_OFFLINE_AUTH_ALLOWED_PARM
10117 | Invalid connectivity mode
10119 | Invalid browser modes
10401 | Could not filter tokens
10403 | Parameter or value is out of range
10404 | Invalid property value
10406 | Value or parameter cannot be null.
10407 | The URI did not contain query parameters
10408 | Authentication failed
10409 | Invalid authentication URL
10414 | The server responded with more number of redirect responses than maximum allowed.
10415 | Invalid HTML. One or more required fields missing
10416 | The loaded web page contains an unresponsive or long-running script
10417 | This flow requires a web-view
10418 | Authentication has been retried max allowed times.
10419 | HTML view error.
10421 | Client certificate is not specified.
10422 | Untrusted server certificate import was canceled.
10423 | Unknown error
10424 | Client certificate based authentication is not enabled.
10425 | A handler is required for authentication challenge events
10426 | A handler is required for logout events
10501 | key for credential or for map nil
10502 | Input is not proper,invalid input or missing input
10503 | out of memory in keychain
10504 | Random generation failure
10505 | salt length less then min length
10506 | Input text empty
10507 | unsupported encrypt algorithm
10508 | key size not supported
10509 | length not matching to block size
10510 | padding missing error
10511 | ENCRYPTION SYSTEM ERROR
10512 | key length not multiple of 4
10513 | salt required error
10514 | salt not supported for algorithm
10515 | cannot prefix salt in not supported salt algorithm
10516 | Algorithm name missing
10517 | input has to be NSString type
10518 | unknown input type
10519 | input length error
10520 | key-pair generation system error
10521 | tag require to identify key in key-chain error
10522 | key-chain system error
10523 | key-chain item missing
10524 | signing missing error
10525 | sign cannot be empty
10526 | system verification failed
10527 | Decryption system error
10528 | key-chain item already there
10529 | Unsupported key type
10530 | invalid key chain protection level
10531 | PBKDF2 key generation error
10532 | delegate missing error
10533 | file not found at resource path error
12412 | Value or parameter type mismatch occurred
12413 | Message length is not a multiple of block length
20001 | Invalid basic auth url
30001 | The server did not request for a client certificate
30002 | Access to the certificate was denied or an error occurred while attempting to use the client certificate.
30003 | No client certificates installed/found.
40001 | Unsupported response
40002 | Unauthorized client
40017 | Tokens not available
40200 | OAuth setup failed
40210 | OAuth authentication failed
40211 | OAuth context invalid
40213 | OAuth client assertion invalid
40214 | OAuth client secret invalid
40215 | OAuth MSpre authz code invalid
40219 | OAuth redirect URI is invalid
40220 | OAuth state is invalid
40230 | Invalid request
40231 | access denied
40232 | Invalid scope
40233 | Internal server error
40234 | Oauth temporarily not available
40235 | Unknown error
40236 | Bad request
40237 | Client assertion
40238 | unsupported_grant_type
40239 | invalid_client
40240 | invalid_grant
40241 | Client secret can not be null or empty for this grant type
40242 | Client id can not be null or empty for this grant type
40243 | Invalid auth token endpoint
40244 | Invalid authorization endpoint
40245 | Error while parsing OAuth token
40410 | Assertion cannot be NULL
50001 | Fedauth invalid login successes url
50002 | Fedauth invalid login failure url
50003 | Invalid value for parse token relay
50306 | Cannot  Connect
50400 | Bad Request
50405 | External browser mode is unsupported
50406 | Parse token relay enabled, but no token was found.
50407 | Error while parsing token relay response.
70009 | Authentication error during PIN change.
P1001 | Invalid redirect encountered while authenticating. Check the auth setup being used by the app.
P1002 | Untrusted server error encountered while authenticating. Check the auth setup being used by the app.
P1003 | Unsupported challenge encountered while authenticating.
P1004 | Idle timeout reset failed.
P1005 | Init expects a map of properties to be passed.
P1006 | Challenge fields are not passed.
P1007 | Invalid arguments passed. AuthFlowKey is expected to be passed.
P1008 | Null or empty AuthFlowKey passed.
P1009 | Invalid AuthFlowKey passed.
P1010 | No auth context available to fetch headers.
P1011 | This error code is deprecated and no longer in use.
P1012 | Error while launching external browser.
P1013 | No local authenticator enabled.
P1014 | Unidentified local authenticator type.
P1015 | Ongoing enable or disable task. Try after the current one is completed.
P1016 | Attempt to enable fingerprint when PIN is not enabled.
P1017 | Attempt to disable PIN when fingerprint is enabled.
P1018 | Error while enabling local authenticator.
P1019 | Either the device does not support it or fingerprint is not enrolled.
P1020 | Attempt to change PIN when PIN is not enabled.
P1021 | Error while getting enabled local authentications.
P1022 | Unable to find the local authenticator required for the operation.
