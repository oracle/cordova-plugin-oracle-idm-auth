/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
var exec = require('cordova/exec');

/**
 * The plugin object used to interact with IDM headless auth API.
 * Exposes methods and constrants required for IDM interactions.
 */
var IdmAuthFlows = function() {
  var TAG = 'IdmAuthFlows';
  var AuthFlowKey = 'AuthFlowKey';
  var IsAuthenticatedKey = 'isAuthenticated';

  /**
   * Keys to be used for passing authentication properties.
   */
  var authPropertyKeys = {
    // Common for all auth types
    // IdmAuthFlows.AuthServerTypes - enum values
    AuthServerType:'AuthServerType',
    // string - Name of the application
    ApplicationName:'ApplicationName',
    // IdmAuthFlows.ConnectivityMode - enum values
    ConnectivityMode:'ConnectivityMode',
    // number - in seconds
    SessionTimeOutValue:'SessionTimeOutValue',
    // number - in seconds
    IdleTimeOutValue:'IdleTimeOutValue',
    // number - [0 - 100]
    PercentageToIdleTimeout:'PercentageToIdleTimeout',
    // boolean
    OfflineAuthAllowed:'OfflineAuthAllowed',
    // number - in seconds
    LogoutTimeOutValue:'LogoutTimeOutValue',

    // HTTPBasicAuthentication specific.
    // app should not set this - defaulted to AES.
    CryptoScheme: 'CryptoScheme',
    // boolean
    RememberUsernameAllowed:'RememberUsernameAllowed',
    // boolean
    RememberCredentialsAllowed:'RememberCredentialsAllowed',
    // boolean
    RememberUsernameDefault:'RememberUsernameDefault',
    // boolean
    RememberCredentialDefault:'RememberCredentialDefault',
    // boolean
    AutoLoginDefault:'AutoLoginDefault',
    // boolean
    AutoLoginAllowed:'AutoLoginAllowed',
    // number
    MaxLoginAttempts:'MaxLoginAttempts',
    // object containing custom headers: {key: 'value', ...}
    CustomAuthHeaders:'CustomAuthHeaders',

    // Shared by HTTPBasicAuthentication and FederatedAuthentication.
    // string - url
    LoginURL:'LoginURL',
    // string - url
    LogoutURL:'LogoutURL',

    // Shared by HTTPBasicAuthentication and OAuthAuthentication
    SendAuthorizationHeaderInLogout:'SendAuthorizationHeaderInLogout',
    SendCustomAuthHeadersInLogout: 'SendCustomAuthHeadersInLogout',

    // FederatedAuthentication specific.
    // string - url
    LoginSuccessURL:'LoginSuccessURL',
    // string - url
    LoginFailureURL:'LoginFailureURL',
    // boolean
    ParseTokenRelayResponse: 'ParseTokenRelayResponse',
    // string - url
    LogoutSuccessURL:'LogoutSuccessURL',
    // string - url
    LogoutFailureURL:'LogoutFailureURL',
    //boolean
    ConfirmLogoutAutomatically:'ConfirmLogoutAutomatically',
    // string - Logout button ID on the confirmation page.
    ConfirmLogoutButtonId:'ConfirmLogoutButtonId',

    // OAuthAuthentication specific.
    // string - url
    OAuthTokenEndpoint:'OAuthTokenEndpoint',
    // string - url
    OAuthAuthorizationEndpoint:'OAuthAuthorizationEndpoint',
    // string - url
    OAuthRedirectEndpoint:'OAuthRedirectEndpoint',
    // IdmAuthFlows.OAuthAuthorizationGrantType enum values
    OAuthAuthorizationGrantType:'OAuthAuthorizationGrantType',
    // array of scope strings - ['scope1', 'scope2', ...]
    OAuthScope:'OAuthScope',
    // string
    OAuthClientID:'OAuthClientID',
    // string
    OAuthClientSecret:'OAuthClientSecret',
    // string - url
    // Only used for OpenId OAUTH flows.
    OpenIDConnectDiscoveryURL:'OpenIDConnectDiscoveryURL',

    // Shared by OAUTH2 3-legged and FederatedAuthentication only for iOS
    // boolean
    EnableWkWebView: 'enablewkwebview',
    // IdmAuthFlows.BrowserMode enum values
    BrowserMode: 'BrowserMode'
  };

  /**
   * Enum values for authPropertyKeys.AuthServerType.
   */
  var authServerTypes = {
    HTTPBasicAuthentication:'HTTPBasicAuthentication',
    FederatedAuthentication:'FederatedAuthentication',
    OAuthAuthentication:'OAuthAuthentication',
    OpenIDConnect:'OpenIDConnect10'
  };

  /**
   * Utility method to validate number.
   */
  var assertNumber = function(input, field)
  {
    if (typeof input !== 'number') {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid number should be passed.');
    }
  };

  /**
   * Utility method to validate boolean.
   */
  var assertBoolean = function(input, field)
  {
    if (typeof input !== 'boolean') {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid boolean should be passed.');
    }
  };

  /**
   * Utility method to validate object.
   */
  var assertObject = function(input, field)
  {
    if (typeof input !== 'object') {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid object should be passed.');
    }
  };

  /**
   * Utility method to validate string
   */
  var assertString = function(input, field)
  {
    if (typeof input !== 'string' || input === '') {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid string should be passed.');
    }
  };

  /**
   * Utility method to validate url.
   */
  var assertUrl = function(input, field)
  {
    assertString(input, field);
    // iOS webView does not have startsWith method. Therefore using indexOf.
    // App scheme can come in here. Use minimal check.
    if (input.indexOf(':/') > -1) {
      return;
    }
    throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid URL should be passed.');
  };

  /**
   * Base Builder object.
   */
  var BasicAuthPropertiesBuilder = function()
  {
    this.init = function() {
      return this;
    };
    this.put = function(key, value)
    {
      // Create when props is not found. This way it belongs to the object where it is called from and not a shared instance.
      if (!this.props)
      {
        this.props = {};
      }

      this.props[key] = value;
      return this;
    };
    this.idleTimeOutInSeconds = function(timeout)
    {
      assertNumber(timeout, authPropertyKeys.IdleTimeOutValue);
      this.put(authPropertyKeys.IdleTimeOutValue, timeout);
      return this;
    };
    this.percentageToIdleTimeout = function(percentage)
    {
      assertNumber(percentage, authPropertyKeys.PercentageToIdleTimeout);
      if (percentage < 0 || percentage > 100) {
        throw new Error(authPropertyKeys.PercentageToIdleTimeout + ' should be between [0 - 100].');
      }
      this.put(authPropertyKeys.PercentageToIdleTimeout, percentage);
      return this;
    };
    this.sessionTimeOutInSeconds = function(timeout)
    {
      assertNumber(timeout, authPropertyKeys.SessionTimeOutValue);
      this.put(authPropertyKeys.SessionTimeOutValue, timeout);
      return this;
    };
    this.logoutTimeOutInSeconds = function(timeout)
    {
      assertNumber(timeout, authPropertyKeys.LogoutTimeOutValue);
      this.put(authPropertyKeys.LogoutTimeOutValue, timeout);
      return this;
    };
    this.customAuthHeaders = function(headers)
    {
      assertObject(headers, authPropertyKeys.CustomAuthHeaders);
      this.put(authPropertyKeys.CustomAuthHeaders, headers);
      return this;
    };
    this.build = function()
    {
      return this.props;
    };

    return this;
  };

  /**
   * Builder for Basic HTTP authentication
   */
   var HttpBasicAuthPropertiesBuilder = function() {
    // Default properties.
    this.put(authPropertyKeys.AuthServerType, authServerTypes.HTTPBasicAuthentication);
    // AES is the only crypto scheme that the plugin will support.
    // This is because plugin needs to be able to retrieve unencrypted credentials for headers and AES is only way to do that.
    this.put(authPropertyKeys.CryptoScheme, 'AES');
    // Always set headers for logout.
    this.put(authPropertyKeys.SendAuthorizationHeaderInLogout, true);
    this.put(authPropertyKeys.SendCustomAuthHeadersInLogout, true);

    this.init = function(appName, loginUrl, logoutUrl) {
      // Set mandatory parameters.
      assertString(appName, authPropertyKeys.ApplicationName);
      this.put(authPropertyKeys.ApplicationName, appName);
      assertUrl(loginUrl, authPropertyKeys.LoginURL);
      this.put(authPropertyKeys.LoginURL, loginUrl);
      assertUrl(logoutUrl, authPropertyKeys.LogoutURL);
      this.put(authPropertyKeys.LogoutURL, logoutUrl);
      return this;
    };
    this.connectivityMode = function(mode)
    {
      assertString(mode, authPropertyKeys.ConnectivityMode);
      if (!IdmAuthFlows.ConnectivityModes.hasOwnProperty(mode)) {
        throw new Error(authPropertyKeys.ConnectivityMode + ' should be one from IdmAuthFlows.ConnectivityModes.');
      }
      this.put(authPropertyKeys.ConnectivityMode, mode);
      return this;
    };
    this.offlineAuthAllowed = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.OfflineAuthAllowed);
      this.put(authPropertyKeys.OfflineAuthAllowed, bool);
      return this;
    };
    this.maxLoginAttempts = function(attempts)
    {
      assertNumber(attempts, authPropertyKeys.MaxLoginAttempts);
      this.put(authPropertyKeys.MaxLoginAttempts, attempts);
      return this;
    };
    this.rememberUsernameAllowed = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberUsernameAllowed);
      this.put(authPropertyKeys.RememberUsernameAllowed, bool);
      return this;
    };
    this.rememberCredentialsAllowed = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberCredentialsAllowed);
      this.put(authPropertyKeys.RememberCredentialsAllowed, bool);
      return this;
    };
    this.rememberUsernameDefault = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberUsernameDefault);
      this.put(authPropertyKeys.RememberUsernameDefault, bool);
      return this;
    };
    this.rememberCredentialDefault = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberCredentialDefault);
      this.put(authPropertyKeys.RememberCredentialDefault, bool);
      return this;
    };
    this.autoLoginDefault = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.AutoLoginDefault);
      this.put(authPropertyKeys.AutoLoginDefault, bool);
      return this;
    };
    this.autoLoginAllowed = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.AutoLoginAllowed);
      this.put(authPropertyKeys.AutoLoginAllowed, bool);
      return this;
    };

    return this;
  };

  /**
   * Builder for federated authentication
   */
   var FedAuthPropertiesBuilder = function() {
    this.init = function(appName, loginUrl, logoutUrl, loginSuccessUrl, loginFailureUrl) {
      // Set mandatory parameters.
      this.put(authPropertyKeys.AuthServerType, authServerTypes.FederatedAuthentication);
      assertString(appName, authPropertyKeys.ApplicationName);
      this.put(authPropertyKeys.ApplicationName, appName);
      assertUrl(loginUrl, authPropertyKeys.LoginURL);
      this.put(authPropertyKeys.LoginURL, loginUrl);
      assertUrl(logoutUrl, authPropertyKeys.LogoutURL);
      this.put(authPropertyKeys.LogoutURL, logoutUrl);
      assertUrl(loginSuccessUrl, authPropertyKeys.LoginSuccessURL);
      this.put(authPropertyKeys.LoginSuccessURL, loginSuccessUrl);
      assertUrl(loginFailureUrl, authPropertyKeys.LoginFailureURL);
      this.put(authPropertyKeys.LoginFailureURL, loginFailureUrl);
      return this;
    };

    this.parseTokenRelayResponse = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.ParseTokenRelayResponse);
      this.put(authPropertyKeys.ParseTokenRelayResponse, bool);
      return this;
    };
    this.enableWkWebView = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.EnableWkWebView);
      this.put(authPropertyKeys.EnableWkWebView, bool);
      return this;
    };
    this.confirmLogoutAutomatically = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.ConfirmLogoutAutomatically);
      this.put(authPropertyKeys.ConfirmLogoutAutomatically, bool);
      return this;
    };
    this.confirmLogoutButtonId = function(buttonId)
    {
      assertString(buttonId, authPropertyKeys.ConfirmLogoutButtonId);
      this.put(authPropertyKeys.ConfirmLogoutButtonId, buttonId);
      return this;
    };
    this.logoutSuccessURL = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutSuccessURL);
      this.put(authPropertyKeys.LogoutSuccessURL, url);
      return this;
    };
    this.logoutFailureUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutFailureURL);
      this.put(authPropertyKeys.LogoutFailureURL, url);
      return this;
    };
    return this;
  };

  /**
   * Builder for OAUTH2 authentication
   */
  var OAuthPropertiesBuilder = function() {
    this.init = function(appName, grantType, tokenEndpoint, clientId) {
      // console.log('OAuthPropertiesBuilder init');
      // Set mandatory parameters.
      this.put(authPropertyKeys.AuthServerType, authServerTypes.OAuthAuthentication);
      assertString(appName, authPropertyKeys.ApplicationName);
      this.put(authPropertyKeys.ApplicationName, appName);
      assertString(grantType, authPropertyKeys.OAuthAuthorizationGrantType);
      if (!IdmAuthFlows.OAuthAuthorizationGrantTypes.hasOwnProperty(grantType)) {
        throw new Error(authPropertyKeys.OAuthAuthorizationGrantType + ' should be one from IdmAuthFlows.OAuthAuthorizationGrantTypes.');
      }
      this.put(authPropertyKeys.OAuthAuthorizationGrantType, grantType);
      assertUrl(tokenEndpoint, authPropertyKeys.OAuthTokenEndpoint);
      this.put(authPropertyKeys.OAuthTokenEndpoint, tokenEndpoint);
      assertString(clientId, authPropertyKeys.OAuthClientID);
      this.put(authPropertyKeys.OAuthClientID, clientId);
      return this;
    };
    this.enableWkWebView = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.EnableWkWebView);
      this.put(authPropertyKeys.EnableWkWebView, bool);
      return this;
    };
    this.oAuthAuthorizationEndpoint = function(url)
    {
      assertUrl(url, authPropertyKeys.OAuthAuthorizationEndpoint);
      this.put(authPropertyKeys.OAuthAuthorizationEndpoint, url);
      return this;
    };
    this.oAuthRedirectEndpoint = function(url)
    {
      assertUrl(url, authPropertyKeys.OAuthRedirectEndpoint);
      this.put(authPropertyKeys.OAuthRedirectEndpoint, url);
      return this;
    };
    this.oAuthClientSecret = function(secret)
    {
      assertString(secret, authPropertyKeys.OAuthClientSecret);
      this.put(authPropertyKeys.OAuthClientSecret, secret);
      return this;
    };
    this.oAuthScope = function(scopes)
    {
      assertObject(scopes, authPropertyKeys.OAuthScope);
      this.put(authPropertyKeys.OAuthScope, scopes);
      return this;
    };
    this.logoutURL = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutURL);
      this.put(authPropertyKeys.LogoutURL, url);
      return this;
    };
    this.browserMode = function(mode)
    {
      assertString(mode, authPropertyKeys.BrowserMode);
      if (!IdmAuthFlows.BrowserMode.hasOwnProperty(mode)) {
        throw new Error(authPropertyKeys.BrowserMode + ' should be one from IdmAuthFlows.BrowserMode.');
      }
      this.put(authPropertyKeys.BrowserMode, mode);
      return this;
    };
    return this;
  };

  var OpenIDConnectPropertiesBuilder = function() {
    this.init = function(appName, grantType, discoveryEndpoint, clientId) {
      // console.log('OpenIDConnectPropertiesBuilder init');
      // Set mandatory parameters.
      this.put(authPropertyKeys.AuthServerType, authServerTypes.OpenIDConnect);
      assertString(appName, authPropertyKeys.ApplicationName);
      this.put(authPropertyKeys.ApplicationName, appName);
      assertString(grantType, authPropertyKeys.OAuthAuthorizationGrantType);
      if (!IdmAuthFlows.OAuthAuthorizationGrantTypes.hasOwnProperty(grantType)) {
        throw new Error(authPropertyKeys.OAuthAuthorizationGrantType + ' should be one from IdmAuthFlows.OAuthAuthorizationGrantTypes.');
      }
      this.put(authPropertyKeys.OAuthAuthorizationGrantType, grantType);
      assertUrl(discoveryEndpoint, authPropertyKeys.OpenIDConnectDiscoveryURL);
      this.put(authPropertyKeys.OpenIDConnectDiscoveryURL, discoveryEndpoint);
      assertString(clientId, authPropertyKeys.OAuthClientID);
      this.put(authPropertyKeys.OAuthClientID, clientId);
      return this;
    };
  };



  HttpBasicAuthPropertiesBuilder.prototype = new BasicAuthPropertiesBuilder();
  FedAuthPropertiesBuilder.prototype = new BasicAuthPropertiesBuilder();
  OAuthPropertiesBuilder.prototype = new BasicAuthPropertiesBuilder();
  OpenIDConnectPropertiesBuilder.prototype = new OAuthPropertiesBuilder();

  /**
   * Authentication flow object passed to the success callback for the Promise returned from IdmAuthFlows#init method call.
   * This object can be used by the caller to further do login, logout, isAuthenticated, getHeaders and resetIdleTimeout.
   */
  var AuthenticationFlow = function(authFlowKey)
  {
    var self = this;
    // Insist for an authFlowKey to create AuthenticationFlow object.
    if (!authFlowKey)
    {
      throw new Error('Invalid flow key passed while creating AuthenticationFlow.');
    }

    /**
     * Method to start login process.
     * @param {challengeCallback} Callback invoked if there is a user challenge to be filled. The challenge will be called repeatedly, if the user provides wrong credentials.
     *                            This will continue for the number of times configured in IdmAuthFlows.AuthPropertyKeys.MaxLoginAttempts.
     *                            The signature of the method will have two parameters - challengeFields (Object) and proceedHandler (method).
     *                            The challengeFields is an object with the keys that need to be filled in by the user.
     *                            Once the information is collected from the user, proceedHandler should be invoked passing the challengeFields.
     * @return {Promise}          <ul><li>onFulfilled - will receive this AuthenticationFlow object itself.
     *                            <li>onRejected - will receive the error object describing the error with keys in IdmAuthFlows.Error.</ul>
     */
    this.login = function(challengeCallback) {
      // console.log('Login: start...' + authFlowKey);
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          // console.log('Login: isAuthenticated result: ' + JSON.stringify(resp));
          var isAuth = resp[IsAuthenticatedKey];

          if (isAuth)
          {
            // console.log('Login: user already authenticated.');
            resolve(self);
          }
          else
          {
            // console.log('Login: user not authenticated. Proceed to login.');
            var onSuccess = function me(resp) {
              if (resp.challengeFields && challengeCallback && typeof challengeCallback === 'function')
              {
                // console.log('Login: user not authenticated. Process challenge.');
                challengeCallback(resp.challengeFields, function(challengeFields) {
                  exec(me, reject, TAG, 'finishLogin', [authFlowKey, challengeFields]);
                });
              }
              else
              {
                // console.log('Login: user successfully authenticated.');
                resolve(self);
              }
            };
            exec(onSuccess, reject, TAG, 'startLogin', [authFlowKey]);
          }
        }, reject, TAG, 'isAuthenticated', [authFlowKey]);
      });
    };
    /**
     * This method can be used to find out if the user is authenticated.
     * @param {Object}   For 3-legged OAUTH it can contain IdmAuthFlows.OAuthScope and 'refreshExpiredTokens' boolean.
     * @return {Promise} <ul><li>onFulfilled - will receive true|false which indicates if the user is logged in or not.
     *                       <li>onRejected - will receive the error object describing the error with keys in IdmAuthFlows.Error.</ul>
     */
    this.isAuthenticated = function(authProps) {
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          resolve(resp[IsAuthenticatedKey]);
        }, reject, TAG, 'isAuthenticated', [authFlowKey, authProps]);
      });
    };
    /**
     * This method can be used to get Authorization headers and any custom headers to be set for making XHR requests to secured end points.
     * @param {String}   URL for which cookies and headers need to retrieved. Need to be set for federated auth usecases.
     * @param {Array}    Scopes for which header is requested. Need to be set for OAUTH cases where fine grained control on the token is needed.
     *                   If not specified, the first OAUTH token available will be returned.
     * @return {Promise} <ul><li>onFulfilled - an object that contains key value pairs of headers.
     *                   <ul><li>e.g. For HTTPBasicAuthentication, if offlineAuthAllowed is true - {Authorization: 'Basic <base64Encoded credentials>', customHeader1: 'headerValue1', ... }
     *                   <li>e.g. For OAuthAuthentication and OpenIdConnect, {Authorization: 'Bearer oauthToken', customHeader1: 'headerValue1', ... }</ul>
     *                   Headers are returned only if they exists. If no headers are available an empty object is returned.
     *                   <li>onRejected - will receive the error object describing the error with keys in IdmAuthFlows.Error.</ul>
     */
    this.getHeaders = function(fedAuthSecuredUrl, oauthScopes) {
      return new Promise(function (resolve, reject) {
        exec(resolve, reject, TAG, 'getHeaders', [authFlowKey, fedAuthSecuredUrl, oauthScopes]);
      });
    };
    /**
     * This method can be used to logout.
     * @return {Promise} <ul><li>onFulfilled - will receive this AuthenticationFlow object itself.
     *                   <li>onRejected - will receive the error object describing the error with keys in IdmAuthFlows.Error.</ul>
     */
    this.logout = function() {
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          resolve(self);
        }, reject, TAG, 'logout', [authFlowKey]);
      });
    };
    /**
     * This method resets the idle timeout. Can be used in the timeoutCallback registered during #init().
     * @return {Promise} <ul><li>onFulfilled - will receive this AuthenticationFlow object itself.
     *                   <li>onRejected - will receive the error object describing the error with keys in IdmAuthFlows.Error.</ul>
     */
    this.resetIdleTimeout = function() {
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          resolve(self);
        }, reject, TAG, 'resetIdleTimeout', [authFlowKey]);
      });
    };
  };

  return {
    /**
     * Enum values for HttpBasicAuthPropertiesBuilder#connectivityMode
     */
    ConnectivityModes: {
      Online:'Online',
      Offline:'Offline',
      Auto:'Auto'
    },
    /**
     * Enum values for OAuthPropertiesBuilder's OAuthAuthorizationGrantTypes
     */
    OAuthAuthorizationGrantTypes: {
      OAuthImplicit:'OAuthImplicit',
      OAuthAuthorizationCode:'OAuthAuthorizationCode',
      OAuthResourceOwner:'OAuthResourceOwner',
      OAuthClientCredentials:'OAuthClientCredentials'
    },
    /**
     * These keys can be used to respond the the login challenge for HTTPBasicAuthentication and 2-legged OAUTH.
     */
    AuthChallenge: {
      // string
      UserName: 'username_key',
      // string
      Password: 'password_key',
      // object with fields in IdmAuthFlows.Error
      Error: 'error',
      // string
      IdentityDomain: 'iddomain_key',
      // boolean
      RememberUserPreference:'remember_username_ui_preference_key',
      // boolean
      RememberCredentialsPreference: 'remember_credentials_ui_preference_key',
      // boolean
      AutoLoginPreference: 'autoLogin_ui_preference_key'
    },
    /**
     * Keys present in response object when timeoutCallback is invoked. timeoutCallback is passed during #init()
     */
    TimeoutResponse: {
      TimeoutType:'TimeoutType',
      TimeLeftToTimeout:'TimeLeftToTimeout'
    },
    /**
     * Possible values for TimeoutResponse.TimeoutType
     */
    TimeoutType: {
     SessionTimeout:'SESSION_TIMEOUT',
     IdleTimeout:'IDLE_TIMEOUT'
    },
    /**
     * Enum values for OAuthPropertiesBuilder#browserMode
     */
    BrowserMode: {
      External: 'External',
      Embedded: 'Embedded'
    },
    /**
     * Enum values for accessing information from error object in onReject callbacks.
     */
    Error: {
      ErrorCode: 'errorCode',
      ErrorSource: 'errorSource',
      TranslatedErrorMessage: 'translatedErrorMessage'
    },
    /**
     * Enum values for IdmAuthFlows.Error.ErrorSource in the error object.
     */
    ErrorSources: {
      Plugin: 'plugin',
      System: 'system'
    },
    /**
     * Starting point for creating an IDM AuthenticationFlow.
     * @param {Object} authProps - An object containing configuration for authentication. Use the builders provided to construct this object.
     * @param {timeoutCallback} timeoutCallback -  Callback invoked as per the timeout callback configuration. Timeout can be configured using
     * <ul>
     * <li>                     builder.sessionTimeOutInSeconds()
     * <li>                     builder.idleTimeOutInSeconds()
     * <li>                     builder.percentageToIdleTimeout
     * </ul>
     *                        The signature of the method will have one parameter, the response object.
     *                        This response object will be an object of the form:
     * <pre><code>
     *                         {
     *                            IdmAuthFlows.TimeoutResponse.TimeoutType: IdmAuthFlows.TimeoutResponse.SessionTimeout | IdmAuthFlows.TimeoutResponse.IdleTimeout,
     *                            IdmAuthFlows.TimeoutResponse.TimeLeftToTimeout: <number - timeLeftInSeconds>
     *                          }
     * </code></pre>
     * <ul>
     * <li>                   In the timeoutCallback if it is an IdmAuthFlows.TimeoutResponse.IdleTimeout and IdmAuthFlows.TimeoutResponse.TimeLeftToTimeout is not 0,
     *                        the idle timeout can be extended by invoking IdmAuthFlows.resetIdleTimeout.
     * <li>                   In the timeoutCallback if it is an IdmAuthFlows.TimeoutResponse.IdleTimeout and IdmAuthFlows.TimeoutResponse.TimeLeftToTimeout is 0,
     *                        the user has to be re-authenticated. The app has to call login, but if AUTOLOGIN is configured the login happens without challenge.
     * <li>                   In the timeoutCallback if it is an IdmAuthFlows.TimeoutResponse.SessionTimeout the user has to be re-authenticated normally.
     * </ul>
     * @return {Promise} <ul><li>onFulfilled - will receive this AuthenticationFlow object which can be used for login, logout etc.
     *                   <li>onRejected - will receive the error object describing the error with keys in IdmAuthFlows.Error.</ul>
     */
    init: function(authProps, timeoutCallback)
    {
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          // If there is a timeoutCallback, register that before calling the successCallback.
          var authFlowKey = resp[AuthFlowKey];
          if (timeoutCallback)
          {
            exec(timeoutCallback, reject,  TAG, 'addTimeoutCallback', [authFlowKey]);
          }
          // console.log('Creating auth flow for ' + authFlowKey);
          var authFlow = new AuthenticationFlow(authFlowKey);
          resolve(authFlow);
        }, reject, TAG, 'setup', [authProps]);
      });
    },
    /**
     * The object returned is a builder which can be used to create the authentication props for HTTPBasicAuthentication.
     * Builder exposes methods to add properties relevant to HTTPBasicAuthentication.
     * The builder expects mandatory parameters in the constructor. Further optional properties can be set using the methods provided.
     * The builder does basic validation of the properties being set. It also populates the default properties needed for HTTPBasicAuthentication.
     * If there is any properties to be set that is not supported by the builder, use put(k, v) on the builder.
     * Example usage:
     * <pre><code>
     *    var authProps = IdmAuthFlows.newHttpBasicAuthPropertiesBuilder('appName',
     *                'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
     *                'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
     *     .idleTimeOutInSeconds(300)
     *     .sessionTimeOutInSeconds(6000)
     *     .percentageToIdleTimeout(80)
     *     .maxLoginAttempts(2)
     *     .connectivityMode(IdmAuthFlows.ConnectivityModes.Offline)
     *     .offlineAuthAllowed(true)
     *     .customAuthHeaders({'a':'b'})
     *     .rememberUsernameAllowed(true)
     *     .rememberCredentialsAllowed(false)
     *     .autoLoginAllowed(false)
     *     .rememberUsernameDefault(true)
     *     .rememberCredentialDefault(true)
     *     .autoLoginDefault(false)
     *     .put('customKey1', 'customValue1')
     *     .put('customKey2', true)
     *     .build();
     * </code></pre>
     * @return {AuthenticationFlow}
     */
    newHttpBasicAuthPropertiesBuilder: function(appName, loginUrl, logoutUrl)
    {
      var builder = new HttpBasicAuthPropertiesBuilder();
      return builder.init(appName, loginUrl, logoutUrl);
    },
    /**
     * The object returned is a builder which can be used to create the authentication props for FederatedAuthentication.
     * Builder exposes methods to add properties relevant to FederatedAuthentication.
     * The builder expects mandatory parameters in the constructor. Further optional properties can be set using the methods provided.
     * The builder does basic validation of the properties being set. It also populates the default properties needed for FederatedAuthentication.
     * If there is any properties to be set that is not supported by the builder, use put(k, v) on the builder.
     * Example usage:
     * <pre><code>
     *   var authProps = IdmAuthFlows.newFedAuthPropertiesBuilder('appName', 'http://login/url', 'http://logout/url',
     *                                                            'http://login/success', 'http://logout/failed')
     *     .logoutSuccessURL('http://logout/success')
     *     .logoutFailureUrl('http://logout/failed')
     *     .confirmLogoutAutomatically(true)
     *     .confirmLogoutButtonId('buttonId')
     *     .idleTimeOutInSeconds(300)
     *     .sessionTimeOutInSeconds(6000)
     *     .percentageToIdleTimeout(80)
     *     .logoutTimeOutInSeconds(60)
     *     .customAuthHeaders({'header':'value'})
     *     .put('customKey1', 'customValue1')
     *     .put('customKey2', true)
     *     .build();
     * </code></pre>
     * @return {AuthenticationFlow}
     */
    newFedAuthPropertiesBuilder: function(appName, loginUrl, logoutUrl, loginSuccessUrl, loginFailureUrl)
    {
      var builder = new FedAuthPropertiesBuilder();
      return builder.init(appName, loginUrl, logoutUrl, loginSuccessUrl, loginFailureUrl);
    },
    /**
     * The object returned is a builder which can be used to create the authentication props for OAuthAuthentication.
     * Builder exposes methods to add properties relevant to OAuthAuthentication.
     * The builder expects mandatory  parameters in the constructor. Further optional properties can be set using the methods provided.
     * The builder does basic validation of the properties being set. It also populates the default properties needed for OAuthAuthentication.
     * If there is any properties to be set that is not supported by the builder, use put(k, v) on the builder.
     * Example usage:
     * <pre><code>
     *   var authProps = IdmAuthFlows.newOAuthPropertiesBuilder('appName',
     *                                                          IdmAuthFlows.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
     *                                                          'http://token/endpoint',
     *                                                          'clientId')
     *     .oAuthScope(['scope1', 'scope2'])
     *     .oAuthClientSecret('clientSecret')
     *     .oAuthAuthorizationEndpoint('http://auth/endpoint')
     *     .oAuthRedirectEndpoint('http://redirect/endpoint')
     *     .logoutURL('http://logout/url')
     *     .enableWkWebView(true)
     *     .browserMode(IdmAuthFlows.BrowserMode.External)
     *     .idleTimeOutInSeconds(300)
     *     .sessionTimeOutInSeconds(6000)
     *     .percentageToIdleTimeout(80)
     *     .logoutTimeOutInSeconds(60)
     *     .customAuthHeaders({'header':'value'})
     *     .put('customKey1', 'customValue1')
     *     .put('customKey2', true)
     *     .build();
     * </code></pre>
     * @return {AuthenticationFlow}
     */
    newOAuthPropertiesBuilder: function(appName, grantType, tokenEndpoint, clientId)
    {
      var builder = new OAuthPropertiesBuilder();
      return builder.init(appName, grantType, tokenEndpoint, clientId);
    },
    /**
     * The object returned is a builder which can be used to create the authentication props for OpenIdConnect.
     * Builder exposes methods to add properties relevant to OpenId Connect authentication.
     * The builder expects mandatory  parameters in the constructor. Further optional properties can be set using the methods provided.
     * The builder does basic validation of the properties being set. It also populates the default properties needed for OpenIdConnect.
     * If there is any properties to be set that is not supported by the builder, use put(k, v) on the builder.
     * Example usage:
     * <pre><code>
     *   var authProps = IdmAuthFlows.newOpenIDConnectPropertiesBuilder('appName',
     *                                                          IdmAuthFlows.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
     *                                                          'http://openid/discovery/url',
     *                                                          'clientId')
     *     .oAuthClientSecret('clientSecret')
     *     .oAuthScope(['scope1', 'scope2'])
     *     .enableWkWebView(true)
     *     .browserMode(IdmAuthFlows.BrowserMode.External)
     *     .idleTimeOutInSeconds(300)
     *     .sessionTimeOutInSeconds(6000)
     *     .percentageToIdleTimeout(80)
     *     .logoutTimeOutInSeconds(60)
     *     .customAuthHeaders({'header':'value'})
     *     .put('customKey1', 'customValue1')
     *     .put('customKey2', true)
     *     .build();
     * </code></pre>
     * @return {AuthenticationFlow}
     */
    newOpenIDConnectPropertiesBuilder: function(appName, grantType, discoveryEndpoint, clientId)
    {
      var builder = new OpenIDConnectPropertiesBuilder();
      return builder.init(appName, grantType, discoveryEndpoint, clientId);
    }
  };
}();

module.exports = IdmAuthFlows;
