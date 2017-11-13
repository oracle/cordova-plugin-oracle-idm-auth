# `cordova.plugings.IdmAuthFlows` API

The top level `IdmAuthFlows` module is a JavaScript Object containing all authentication related objects and methods.

The `IdmAuthFlows` module is exposed within the `window.cordova.plugins` namespace. Example usage:

```js
cordova.plugins.IdmAuthFlows.init(authProps).then(...).catch(...);
```

## cordova.plugins.IdmAuthFlows.ConnectivityModes
Enum values for HttpBasicAuthPropertiesBuilder's connectivityMode. Valid values are:
* `Online`
* `Offline`
* `Auto`

Setting ConnectivityMode has an effect only when offlineAuthMode is set to `true`. 
offlineAuthMode `false` will result in an `ONLINE` login always.

## cordova.plugins.IdmAuthFlows.Error
`onReject` callback returns an error object with fields in this enum. 
* `ErrorCode` Value as a {String}, contains the error code.
* `ErrorSource` Value as a {String}, one of `IdmAuthFlows.ErrorSources` enum.
* `TranslatedErrorMessage` Value as a {String}, set only when ErrorSources is `IdmAuthFlows.ErrorSources.System` for iOS. 

## cordova.plugins.IdmAuthFlows.ErrorSources
Enum values for `IdmAuthFlows.Error.ErrorSource`
* `Plugin` Indicates that the error is a plugin error. Use [error codes documentation](error-codes.md) to translate.
* `System` Indicates that the error is a system generated error. Currently, used only for iOS system errors. 
App can either use the `IdmAuthFlows.Error.TranslatedErrorMessage` or have their own translated messages based on the iOS system error codes.

## cordova.plugins.IdmAuthFlows.OAuthAuthorizationGrantTypes
Enum values for OAuthPropertiesBuilder's OAuthAuthorizationGrantTypes. Valid values are:

* `OAuthImplicit`
* `OAuthAuthorizationCode`
* `OAuthResourceOwner`
* `OAuthClientCredentials`

## cordova.plugins.IdmAuthFlows.AuthChallenge
Some authentication types such as HTTP Basic authentication and 2-legged OAUTH need user input such as username, password.
For such scenarios this enum keys can be used to access the relevant items from the `fields` object available in the challenge callback.
* `UserName` Set a {String} value for this in the challenge callback.
* `Password` Set a {String} value for this in the challenge callback.
* `ErrorCode` Error codes if any is available as a {String} from `fields` in challenge callback.
* `IdentityDomain` Set a {String} value for this in the challenge callback.
* `RememberUserPreference` Set a {boolean} value for this in the challenge callback.
* `RememberCredentialsPreference` Set a {boolean} value for this in the challenge callback.
* `AutoLoginPreference` Set a {boolean} value for this in the challenge callback.

## cordova.plugins.IdmAuthFlows.BrowserMode
Enum value for OAuthPropertiesBuilder's browserMode. This enum states whether the app should use an external browser or a webview to load the authentication server's login page.
Valid values are:
* `External`
* `Embedded`

For using `External` BrowserMode, the app has to be [setup to handle the redirects from the external browser](faq.md#externalBrowser). 
Refer FAQ item about [setting up URL scheme](faq.md#urlScheme) on how to set it up.

## cordova.plugins.IdmAuthFlows.TimeoutType
Enum value representing various timeout types possible in a timeout callback.
* `SessionTimeout`
* `IdleTimeout`

## cordova.plugins.IdmAuthFlows.TimeoutResponse
This enum represents the keys present in response object when timeout callback is invoked.
Timeout callback is passed to `cordova.plugins.IdmAuthFlows.init`
* `TimeoutType` one of `cordova.plugins.IdmAuthFlows.TimeoutType`
* `TimeLeftToTimeout` number of seconds left before the said timeout will occur.

## cordova.plugins.IdmAuthFlows.newHttpBasicAuthPropertiesBuilder
The object returned is a builder which can be used to create the authentication props for HTTPBasicAuthentication.
Builder exposes methods to add properties relevant to HTTP basic authentication.
The builder expects mandatory parameters in the constructor. Further optional properties can be set using the methods provided.
The builder does basic validation of the properties being set. It also populates the default properties needed for HTTP basic authentication.
If there is any properties to be set that is not supported by the builder, use put(k, v) on the builder.

```js
var authProps = IdmAuthFlows.newHttpBasicAuthPropertiesBuilder('appName',
           'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
           'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
    .idleTimeOutInSeconds(300)
    .sessionTimeOutInSeconds(6000)
    .percentageToIdleTimeout(80)
    .maxLoginAttempts(2)
    .connectivityMode(IdmAuthFlows.ConnectivityModes.Offline)
    .offlineAuthAllowed(true)
    .customAuthHeaders({'a':'b'})
    .rememberUsernameAllowed(true)
    .rememberCredentialsAllowed(false)
    .rememberUsernameDefault(true)
    .rememberCredentialDefault(true)
    .autoLoginDefault(false)
    .autoLoginAllowed(false)
    .put('customKey1', 'customValue1')
    .put('customKey2', true)
    .build();
```

All parameters of this method are mandatory:

* `applicationName` {String} Name of the application.
* `loginUrl` {String} Valid login URL.
* `logoutUrl` {String} Valid logout URL.

The methods on the builder are:

* `idleTimeOutInSeconds` {Number} of seconds before idle timeout should kick in.
* `sessionTimeOutInSeconds` {Number} of seconds - Avoid setting this if you need infinite timeout.
* `percentageToIdleTimeout`  {Number} between 0 and 100. Percentage of idle timeout before which the timeout callback should be invoked.
If this number is very low, the timeout callback is not guaranteed to be invoked.
* `logoutTimeOutInSeconds`  {Number} of seconds to wait for logout operation, before timing out.
* `customAuthHeaders` {Object} Key value pairs of custom headers
* `maxLoginAttempts` {Number} number of retry allowed for a user to login.
* `connectivityMode` {cordova.plugins.IdmAuthFlows.ConnectivityModes} enum values.
* `offlineAuthAllowed` {Boolean} if offline authentication is allowed or not. 
This should be set to `true` if app wants to enable offline login and for getHeaders() API to return the `Authorization` header.
* `rememberUsernameAllowed` {Boolean} If remember username feature should be enabled or not. Default to false.
* `rememberUsernameDefault` {Boolean} Default value for remember username, if enabled. Default to false.
* `rememberCredentialsAllowed` {Boolean} If remember credentials feature should be enabled or not. Default to false.
* `rememberCredentialDefault` {Boolean} Default value for credentials, if enabled. Default to false.
* `autoLoginAllowed` {Boolean} If auto login feature should be enabled or not. Default to false.
This enables user to login without challenge, after first successful login, until session times out or user logs out.
* `autoLoginDefault` {Boolean} Default value for credentials, if enabled. Default to false.
* `put` {String}, {Object} Additional key value pairs for setting authentication properties not supported by the builder.

### ConnectivityMode and offlineAuthAllowed
offlineAuthAllowed `true` results in offline credentials being stored in secured storage. 
App will be authenticated against this, when `OFFLINE` login applies. getHeader() API depends on this to be able to retrieve the `Authorization` headers.

No matter what ConnectivityMode is set, first time login will always be `ONLINE`.
Offline credentials will be cleared if user exceeds the `maxLoginAttempts` while logging in.

* offlineAuthAllowed set to `false` results in `ONLINE` login always, no matter what ConnectivityMode is set.
* offlineAuthAllowed set to `true` and ConnectivityMode is set to `ONLINE`. This results in an `ONLINE` login always.
* offlineAuthAllowed set to `true` and ConnectivityMode is set to `OFFLINE`. 
This results in `OFFLINE` login for subsequent attempts. 
In the case of wrong credentials, an `ONLINE` login will be attempted after `maxLoginAttempts` is exceeded.
* offlineAuthAllowed set to `true` and ConnectivityMode is set to `AUTO`. 
Cookie validity determines the type if subsequent login performed. If cookies are valid, it will be an `OFFLINE` login, otherwise it will be `ONLINE` login.

## cordova.plugins.IdmAuthFlows.newFedAuthPropertiesBuilder
The object returned is a builder which can be used to create the authentication props for federated authentication.
Builder exposes methods to add properties relevant to federated authentication.
The builder expects mandatory parameters in the constructor. Further optional properties can be set using the methods provided.
The builder does basic validation of the properties being set. It also populates the default properties needed for federated authentication.
If there is any properties to be set that is not supported by the builder, use put(k, v) on the builder.

```js
var authProps = IdmAuthFlows.newFedAuthPropertiesBuilder('appName',
                                                         'http://login/url',
                                                         'http://logout/url',
                                                         'http://login/success',
                                                         'http://logout/failed')
    .logoutSuccessURL('http://logout/success')
    .logoutFailureUrl('http://logout/failed')
    .confirmLogoutAutomatically(true)
    .confirmLogoutButtonId('buttonId')
    .idleTimeOutInSeconds(300)
    .sessionTimeOutInSeconds(6000)
    .percentageToIdleTimeout(80)
    .logoutTimeOutInSeconds(60)
    .parseTokenRelayResponse(true)
    .enableWkWebView(true)
    .customAuthHeaders({'header':'value'})
    .put('customKey1', 'customValue1')
    .put('customKey2', true)
    .build();
```

All parameters of this method are mandatory:

* `applicationName` {String} Name of the application.
* `loginUrl` {String} Valid login URL.
* `logoutUrl` {String} Valid logout URL.
* `loginSuccessUrl` {String} Valid URL to redirect after successful login.
* `loginFailureUrl` {String} Valid URL to redirect after failed login.

The methods on the builder are:

* `logoutSuccessURL` {String} Valid logout success URL. Url to which the server redirects after logout is successful.
* `logoutFailureUrl` {String} Valid logout failure URL. Url to which the server redirects when logout fails or is cancelled by end-user.
* `confirmLogoutAutomatically` {Boolean} Set to `true` for automatically dismissing the logout confirmation page by clicking on DOM with id set by `confirmLogoutButtonId`.
* `confirmLogoutButtonId` {String} DOM id of the confirmation button on the logout confirmation HTML page. Defaults to `Confirm`.
* `idleTimeOutInSeconds` {Number} of seconds before idle timeout should kick in.
* `sessionTimeOutInSeconds` {Number} of seconds - Avoid setting this if you need infinite timeout.
* `percentageToIdleTimeout`  {Number} between 0 and 100. Percentage of idle timeout before which the timeout callback should be invoked.
If this number is very low, the timeout callback is not guaranteed to be invoked.
* `logoutTimeOutInSeconds`  {Number} of seconds to wait for logout operation, before timing out.
* `parseTokenRelayResponse` {Boolean} Used for SAML federated login. When set to `true`, ensure that the login URL returns the token response in JSON format.
* `enableWkWebView` {Boolean} Used for indicating that the cordova app wants to use WkWebView. This works only for iOS 10+.
* `customAuthHeaders` {Object} Key value pairs of custom headers
* `put` {String}, {Object} Additional key value pairs for setting authentication properties not supported by the builder.

Some federated authentication servers provide a logout confirmation screen where the user is expected to provide his consent for logout.
There are two ways to handle this situation. First by having the confirmation screen dismissed automatically, without user interaction.
This can be achieved by setting `confirmLogoutAutomatically` to `true` and providing`confirmLogoutButtonId` if needed.
The other way is to wait for user to provide his consent. This can be done by specifying `logoutSuccessURL` and `logoutFailureUrl`.
*Note:Irrespective of whether user cancels the logout or accepts the logout in the confirmation screen, the user is logged out.*

Also see relevant FAQ on [SAML configuration](#faq.md/saml), [logout confirmation](#faq.md/logoutConfirm) and [WKWebView support](#faq.md/WKWebView).

## cordova.plugins.IdmAuthFlows.newOAuthPropertiesBuilder
The object returned is a builder which can be used to create the authentication props for OAuth authentication.
Builder exposes methods to add properties relevant to OAuth authentication. The builder expects mandatory  parameters in the constructor.
Further optional properties can be set using the methods provided. The builder does basic validation of the properties being set.
It also populates the default properties needed for OAuth authentication. If there is any properties to be set that is not supported by
the builder, use put(k, v) on the builder.

```js
var authProps = IdmAuthFlows.newOAuthPropertiesBuilder('appName',
                                                       IdmAuthFlows.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
                                                       'http://token/endpoint',
                                                       'clientId')
    .idleTimeOutInSeconds(300)
    .sessionTimeOutInSeconds(6000)
    .percentageToIdleTimeout(80)
    .logoutTimeOutInSeconds(60)
    .customAuthHeaders({'header':'value'})
    .oAuthAuthorizationEndpoint('http://auth/endpoint')
    .oAuthRedirectEndpoint('http://redirect/endpoint')
    .oAuthScope(['scope1', 'scope2'])
    .oAuthClientSecret('clientSecret')
    .enableWkWebView(true)
    .browserMode(IdmAuthFlows.BrowserMode.External)
    .put('customKey1', 'customValue1')
    .put('customKey2', true)
    .build();
```

All parameters of this method are mandatory:

* `applicationName` {String} Name of the application.
* `grantType` {cordova.plugins.IdmAuthFlows.OAuthAuthorizationGrantTypes} enum value.
* `tokenEndpoint` {String} Valid token end point URL.
* `clientId` {String}

The methods on the builder are:

* `idleTimeOutInSeconds` {Number} of seconds before idle timeout should kick in.
* `sessionTimeOutInSeconds` {Number} of seconds - Avoid setting this if you need infinite timeout.
* `percentageToIdleTimeout`  {Number} between 0 and 100. Percentage of idle timeout before which the timeout callback should be invoked.
If this number is very low, the timeout callback is not guaranteed to be invoked.
* `logoutTimeOutInSeconds`  {Number} of seconds to wait for logout operation, before timing out.
* `customAuthHeaders` {Object} Key value pairs of custom headers
* `oAuthAuthorizationEndpoint` {String} Valid authorization end point URL.
* `oAuthRedirectEndpoint` {String} Valid redirect end point URL.
* `oAuthScope` {Array} Set of scopes.
* `oAuthClientSecret` {String}
* `enableWkWebView` {Boolean} Used for indicating that the cordova app wants to use WkWebView. This works only for iOS 10+.
* `browserMode` {cordova.plugins.IdmAuthFlows.BrowserMode} enum value. 
`External` will open up the browser on the device to authenticate. 
`Embedded` will open a webview inside the app to authenticate.
* `put` {String}, {Object} Additional key value pairs for setting authentication properties not supported by the builder.

Also see relevant FAQ on [Google OAUTH](#faq.md/google), [Google logout](#faq.md/googleLogout) and [External browser support](#faq.md/externalBrowser).

## cordova.plugins.IdmAuthFlows.newOpenIDConnectPropertiesBuilder
The object returned is a builder which can be used to create the authentication props for OpenId Connect authentication.
Open Id Connect is built on top of OAUTH, so the configuration is similar to OAUTH.
Builder exposes methods to add properties relevant to OpenId Connect authentication. The builder expects mandatory  parameters in the constructor.
Further optional properties can be set using the methods provided. The builder does basic validation of the properties being set.
It also populates the default properties needed for OAuth authentication. If there is any properties to be set that is not supported by
the builder, use put(k, v) on the builder.

```js
var authProps = IdmAuthFlows.newOpenIDConnectPropertiesBuilder('appName',
                                                        IdmAuthFlows.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
                                                        'http://discovery/endpoint',
                                                        'clientId')
    .oAuthClientSecret('clientSecret')
    .oAuthScope(['scope1', 'scope2'])
    .idleTimeOutInSeconds(300)
    .sessionTimeOutInSeconds(6000)
    .percentageToIdleTimeout(80)
    .logoutTimeOutInSeconds(60)
    .customAuthHeaders({'header':'value'})
    .enableWkWebView(true)
    .browserMode(IdmAuthFlows.BrowserMode.External)
    .put('customKey1', 'customValue1')
    .put('customKey2', true)
    .build();
```

All parameters of this method are mandatory:

* `applicationName` {String} Name of the application.
* `grantType` {cordova.plugins.IdmAuthFlows.OAuthAuthorizationGrantTypes} enum value.
* `discoveryEndpoint` {String} Valid OpenId Discovery end point URL.
* `clientId` {String}

The methods on the builder are:

* `oAuthClientSecret` {String}
* `oAuthScope` {Array} Set of scopes.
* `idleTimeOutInSeconds` {Number} of seconds before idle timeout should kick in.
* `sessionTimeOutInSeconds` {Number} of seconds - Avoid setting this if you need infinite timeout.
* `percentageToIdleTimeout`  {Number} between 0 and 100. Percentage of idle timeout before which the timeout callback should be invoked.
If this number is very low, the timeout callback is not guaranteed to be invoked.
* `logoutTimeOutInSeconds`  {Number} of seconds to wait for logout operation, before timing out.
* `customAuthHeaders` {Object} Key value pairs of custom headers
* `enableWkWebView` {Boolean} Used for indicating that the cordova app wants to use WkWebView. This works only for iOS 10+.
* `browserMode` {cordova.plugins.IdmAuthFlows.BrowserMode} enum value. 
`External` will open up the browser on the device to authenticate. 
`Embedded` will open a webview inside the app to authenticate.
* `put` {String}, {Object} Additional key value pairs for setting authentication properties not supported by the builder.

## cordova.plugins.IdmAuthFlows.init
Starting point for initiating login flows.
This method expects an object containing configuration for authentication built using one of the authentication builders explained previously.
The method returns a `Promise` on to which success and error callbacks can be attached.

```js
var authProps = IdmAuthFlows.newHttpBasicAuthPropertiesBuilder('appName',
           'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
           'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
           ...
           ...
           .build();
var initPromise = cordova.plugins.IdmAuthFlows.init(authProps);
initPromise.then(...).catch(...);
```

The parameters for this method are:
* `authProps` {Object} An object containing configuration for authentication. Use the builders provided to construct this object.
* `timeoutCallback` {Function} Callback invoked as per the timeout callback configuration.

Timeout can be configured using `builder.sessionTimeOutInSeconds`, `builder.idleTimeOutInSeconds` and `builder.percentageToIdleTimeout`.
Timeout callback will look like this:

```js
var timeoutCallback = function(response) {
    var timeoutType = response[cordova.plugins.IdmAuthFlows.TimeoutResponse.TimeoutType];
    var timeLeftInSeconds = response[cordova.plugins.IdmAuthFlows.TimeoutResponse.TimeLeftToTimeout];
}
```

The response object in this callback will have values for the keys present in `cordova.plugins.IdmAuthFlows.TimeoutResponse` enum.
The value for `cordova.plugins.IdmAuthFlows.TimeoutResponse.TimeoutType` will be enum value from `cordova.plugins.IdmAuthFlows.TimeoutType`
and `cordova.plugins.IdmAuthFlows.TimeoutResponse.TimeLeftToTimeout` is the number of seconds left before the timeout kicks in.

Things to know about the timeouts:
* An idle timeout with time left to timeout - Idle timeout can be extended by invoking `cordova.plugins.IdmAuthFlows.resetIdleTimeout`.
* An idle timeout with no time left to timeout - User has to be re-authenticated. The app has to call login, but if `auto login` is enabled,
login happens without challenge.
* A session timeout (time left to timeout will always be zero for this) - User has to be re-authenticated normally. `auto login` does not help here.

The return value of init is a {Promise}. `onFulfilled` callback of the {Promise} will be invoked after the authentication
flow has been initialized successfully and will  receive an authentication flow object. `onRejected` will be invoked in the event
of an error while initializing and will receive the error object describing the error.

## cordova.plugins.IdmAuthFlows.AuthenticationFlow object
An authentication flow object can be obtained upon a successful init. The application should use this flow object for doing further
authentication steps such as `login`, `isAuthenticated`, `logout` etc. The flow object can also be obtained upon successful `login` or `logout`.

The plugin allows multiple authentication flows in parallel.

```js
var initPromise = cordova.plugins.IdmAuthFlows.init(authProps);
initPromise.then(
    function(authenticationFlow) {
        // Use authenticationFlow to perform login, logout etc.
    }
);
```

### cordova.plugins.IdmAuthFlows.AuthenticationFlow.login
Login to the authentication flow.

```js
cordova.plugins.IdmAuthFlows.init(authProps).then(
    function(authenticationFlow) {
        var loginPromise = authenticationFlow.login(challengeCallback);
        loginPromise.then(...);
        loginPromise.catch(...);
    }
);
```

Login takes an optional parameter.

* `challengeCallback` {Method} Callback invoked if there is a user challenge to be filled.

The challenge callback will be called repeatedly, if the user provides wrong credentials.
This will continue for the `maxLoginAttempts` number configured.
The signature of the method will have two parameters - challengeFields {Object} and proceedHandler {Method}. The challengeFields is an object,
keys are from `cordova.plugins.IdmAuthFlows.AuthChallenge` enum. This object should be filled in with the values input by the user.
This object will also contain the error with `IdmAuthFlows.Error` structure, if any. This error can be used to display proper error messages to the user.
Once the information is collected from the user, proceedHandler should be invoked passing the challengeFields.

```js
var challengeCallback = function(fields, proceedHandler) {
    var error = fields[cordova.plugins.IdmAuthFlows.AuthChallenge.ErrorCode];
    // Show appropriate error message to the user.
    ...
    ...

    // Collect inputs from user and fill in fields.
    fields[cordova.plugins.IdmAuthFlows.AuthChallenge.UserName] = <userName input by user>
    fields[cordova.plugins.IdmAuthFlows.AuthChallenge.Password] = <password input by user, in clear text>
    ...
    ...

    proceedHandler(fields);
}
```

The return value of this method is a {Promise}. `onFulfilled` callback of the {Promise} will be invoked once login is successful
and will receive authentication flow object. `onRejected` will be invoked if there was an error and will receive the error object describing the error.

### cordova.plugins.IdmAuthFlows.AuthenticationFlow.isAuthenticated
Used to find out if the user is authenticated or not.

```js
authenticationFlow.isAuthenticated(props).then(
    function(authStatus){
      if (authStatus)
        // user is authenticated.
      else
        // user is not authenticated.
    }
).catch(...);
```

The parameter of this method is optional.

* `authProps` {Object} For 3-legged OAUTH it can contain IdmAuthFlows.OAuthScope and 'refreshExpiredTokens' boolean.

The return value of this method is a {Promise}. `onFulfilled` callback of the {Promise} will receive will receive `true|false`
which indicates if the user is logged in or not. `onRejected` will be invoked if there was and error and will receive the error
object describing the error.

### cordova.plugins.IdmAuthFlows.AuthenticationFlow.getHeaders
Used to get Authorization headers and any custom headers to be set for making XHR requests to secured end points. 
For HTTP basic authentication the Authorization header is returned only if `offlineAuthAllowed(true)`.

```js
authenticationFlow.getHeaders(fedAuthSecuredUrl, oauthScopes)).then(
    function(headers) {
        // Make secured resource request using headers.
        var request = new XMLHttpRequest();
        request.withCredentials = true;
        request.open('GET', '<secured url>');
        for (var key in headers) {
          if (headers.hasOwnProperty(key)) {
            request.setRequestHeader(key, headers[key]);
          }
        }

        request.onload = function() {
            ...
            ...
        };

        request.send();
    }
).catch(...);
```
The parameter of this method is optional.

* `fedAuthSecuredUrl` {String} URL for which cookies and headers need to retrieved. Need to be set only for federated auth usecases.
* `oauthScopes` {Array} Provides fine grained control on fetching header based on scopes.  
If not specified, the first OAUTH token available will be returned. 
If multiple OAUTH tokens are available for the scopes passed, the first OAUTH token will be returned as the header.
Need to be set only for oauth / openid usecases.

The return value of this method is a {Promise}. `onFulfilled` callback of the {Promise} will receive will receive an object
that contains key value pairs of headers. Headers are returned only if they exists. If no headers are available an empty object is returned.

Example:
* For HTTPBasicAuthentication only if `offlineAuthAllowed(true)`: `{Authorization: 'Basic <base64Encoded credentials>', customHeader1: 'headerValue1', ... }`
* For FedAuth: `{cookieName1: 'cookieValue1', ..., customHeader1: 'headerValue1', ... }`
* For OAuthAuthentication and OpenIdConnect: `{Authorization: 'Bearer oauthToken', customHeader1: 'headerValue1', ... }`

`onRejected` of the promise will be called in the event of an error while getting headers and will receive the error object describing the error.

### cordova.plugins.IdmAuthFlows.AuthenticationFlow.logout
Logout from the authentication flow.

```js
authenticationFlow.logout().then(...).catch(...);
```

The return value of this method is a {Promise}. `onFulfilled` callback of the {Promise} will be invoked upon successful logout and will receive
authentication flow object. `onRejected` will be invoked if logout was not successful and will receive the error object describing the error.

Also see relevant FAQ on logout about [logout errors](#logoutError) and [offline logout](#offlineLogout).

### cordova.plugins.IdmAuthFlows.AuthenticationFlow.resetIdleTimeout
Used for resetting the idle timeout. This method should be used in the timeout callback registered during `init`.

```js
var authenticationFlow;

var timeoutCallback = function(timeoutResp) {
    var timeoutType = response[cordova.plugins.IdmAuthFlows.TimeoutResponse.TimeoutType];
    var timeLeftInSeconds = response[cordova.plugins.IdmAuthFlows.TimeoutResponse.TimeLeftToTimeout];
    if (timeoutType === cordova.plugins.IdmAuthFlows.TimeoutType.IdleTimeout) && timeLeftInSeconds > 10)
        authenticationFlow.resetIdleTimeout();
}
cordova.plugins.IdmAuthFlows.init(authProps, timeoutCallback).then(
    function(flow) {
        authenticationFlow = flow;
    }
);
```

The return value of this method is a {Promise}. `onFulfilled` callback of the {Promise} will be called when idle timeout reset is
successful and receive authentication flow object. `onRejected` will be called if idle timeout reset failed and will receive the
error object describing the error.
