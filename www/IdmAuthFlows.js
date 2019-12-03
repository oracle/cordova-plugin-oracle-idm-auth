/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */

/**
 * @file {@link https://github.com/oracle/cordova-plugin-oracle-idm-auth|cordova-plugin-oracle-idm-auth}
 * is a plugin that provides authentication and authorization functionality for
 * cordova based mobile applications, supporting standard protocols for remote authentication
 * such as Basic Auth, OAuth, OpenID Connect and webSSO / Federated auth.
 * The plugin also supports local device level authentication such as PIN and biometric based.
 * The plugin abstracts all aspects of authentication and authorization and enforces security best practices for mobile application developers.
 * Typically an app will use a single remote authentication and possibly local authentication.
 * But the plugin can handle multiple authentication flows in parallel, be it remote or local.
 * The APIs of this plugin are exposed through an object <code>IdmAuthFlows</code> in <code>cordova.plugins</code> namespace.
 * All objects in this documentation be it in "Global" or "Classes" are part of this object.
 * They have to be accessed as <code>cordova.plugins.IdmAuthFlows.&lt;Class&gt;</code>
 * or <code>cordova.plugins.IdmAuthFlows.&lt;Object&gt;</code>.
 * <p>Usage of this plugin:</p>
 * <p>Create authentication properties object for the type of authentication to be performed.
 * Use one of the builders for this:
 * <ul style="list-style: none;">
 *  <li>{@link HttpBasicAuthPropertiesBuilder}</li>
 *  <li>{@link FedAuthPropertiesBuilder}</li>
 *  <li>{@link OAuthPropertiesBuilder}</li>
 *  <li>{@link OpenIDConnectPropertiesBuilder}</li>
 *  <li>{@link LocalAuthPropertiesBuilder}</li>
 * </ul>
 * </p>
 * <p>{@link init|Init} the authentication flow using properties. The promise resolves with an object which is subclass of {@link AuthenticationFlow}.
 *    Preserve this object for further operations.</p>
 * <p>{@link Authentication flow|AuthenticationFlow} can be used for performing operations such as
 *    {@link AuthenticationFlow#login|login}, {@link AuthenticationFlow#logout|logout} etc.
 *  Depending on the type of authentication used, the object returned can be of these types. These support operations specific to the authentication used.
 *  <ul style="list-style: none;">
 *    <li>{@link RemoteAuthenticationFlow}</li>
 *    <li>{@link HttpBasicAuthenticationFlow}</li>
 *    <li>{@link LocalAuthenticationFlow}</li>
 *  </ul>
 * </p>
 * <p> Sample usage:</p>
 * <pre>
 *  // Preserve this authentication flow object to interact with the particular flow.
 *  var authFlow;
 *
 *  // The plugin will be available in onDeviceReady or an equivalent callback
 *  // which is executed after the application is loaded by the device.
 *  document.addEventListener("deviceready", onDeviceReady);
 *  function onDeviceReady() {
 *    // Create the authentication properties
 *    var authProperties = cordova.plugins.IdmAuthFlows.newHttpBasicAuthPropertiesBuilder(...).build();
 *
 *    var authPromise = cordova.plugins.IdmAuthFlows.init(authProperties);
 *    authPromise.then(function(flow) {
 *      authFlow = flow;
 *    });
 *  }
 *
 *  // Do login.
 *  var loginPromise = authFlow.login();
 *  loginPromise.then(function(resp) {
 *    // Perform after login tasks.
 *  })
 *
 *  // Retrieve headers - If applicable for the auth type.
 *  var getHeadersPromise = authFlow.getHeaders(options);
 *  getHeadersPromise.then(function(headers) {
 *    // Use headers for setting appropriate headers for performing an XHR request.
 *  });
 *
 *  // Find our use's authentication status.
 *  var isAuthenticatedPromise = authFlow.isAuthenticated(options);
 *  isAuthenticatedPromise.then(function(authenticated) {
 *    // Use headers for setting appropriate headers for performing an XHR request.
 *  });
 *
 *  // Logout from a particular authentication flow.
 *  var logoutPromise = authFlow.logout();
 *  logoutPromise.then(function(resp) {
 *    // Do after logout tasks
 *  });
 * </pre>
 */
var exec = require('cordova/exec');

var IdmAuthFlows = function() {
  var TAG = 'IdmAuthFlows';
  var AuthFlowKey = 'AuthFlowKey';
  var IsAuthenticatedKey = 'isAuthenticated';

  /**
   * Validation error codes for JS layer.
   */
  var errorCodes = {
    NoLocalAuthEnabled: 'P1013',
    UnknownLocalAuthenticatorType: 'P1014',
    DisablePinWhenBiometricEnabled: 'P1017',
    EnableBiometricWhenPinDisabled: 'P1016',
    UserCancelledAuthentication: '10029', // Reuse existing code from IDM SDK
    ChangePinWhenPinNotEnabled: 'P1020',
    GetEnabledAuthsError: 'P1021',
    OngoingTask: 'P1015'
  };

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

    // HttpBasicAuthentication specific.
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
    CustomHeadersForMobileAgent:'CustomHeadersForMobileAgent',
    // function to be invoked when there is a challenge for user credentials or PIN
    ChallengeCallback: "ChallengeCallback",
    // function to be invoked when there is an idle or session timeout.
    TimeoutCallback: 'TimeoutCallback',
    // boolean
    CollectIdentityDomain:'CollectIdentityDomain',
    // boolean
    IdentityDomainNameInHeader: 'IdentityDomainNameInHeader',
    // string - header name
    IdentityDomainHeaderName:'IdentityDomainHeaderName',
    // Shared by HttpBasicAuthentication and FederatedAuthentication.
    // string - url
    LoginURL:'LoginURL',
    // string - url
    LogoutURL:'LogoutURL',

    // Shared by HttpBasicAuthentication and OAuthAuthentication
    SendAuthorizationHeaderInLogout:'SendAuthorizationHeaderInLogout',
    SendCustomAuthHeadersInLogout: 'SendCustomAuthHeadersInLogout',

    // FederatedAuthentication specific.
    // string - url
    LoginSuccessURL:'LoginSuccessURL',
    // string - url
    LoginFailureURL:'LoginFailureURL',
    // boolean
    ParseTokenRelayResponse: 'ParseTokenRelayResponse',
    // Array
    EnableWebViewButtons: 'EnableWebViewButtons',
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
    // Only used for OpenId OAuth flows.
    OpenIDConnectDiscoveryURL:'OpenIDConnectDiscoveryURL',
    // boolean - to save the refresh token
    SessionActiveOnRestart:'SessionActiveOnRestart',

    // Shared by OAuth2 3-legged and FederatedAuthentication only for iOS
    // boolean
    EnableWkWebView: 'enablewkwebview',
    // IdmAuthFlows.BrowserMode enum values
    BrowserMode: 'BrowserMode',

    // Only for OpenID
    OAuthEnablePKCE: 'OAuthEnablePKCE',
    // Local Auth specific
    // string - unique id
    LocalAuthFlowId: 'LocalAuthFlowId',
    // function to be invoked when there is a challenge for user credentials or PIN
    PinChallengeCallback: "PinChallengeCallback",
    // Object containing localized strings for biometric prompt.
    Translations: "Translations"
 };

  /**
   * Enum values for authPropertyKeys.AuthServerType.
   */
  var authServerTypes = {
    HttpBasicAuthentication:'HTTPBasicAuthentication',
    FederatedAuthentication:'FederatedAuthentication',
    OAuthAuthentication:'OAuthAuthentication',
    OpenIDConnect:'OpenIDConnect10',
    LocalAuthenticator: 'LocalAuthenticator'
  };

  /**
   * Utility method to change enumerability of keys.
   */
  var changeEnumberability = function(inputObject, nonEnumerableKeys)
  {
    var returnObject = {};
    Object.keys(inputObject).forEach(function(keyName) {
      isEnumerable = (nonEnumerableKeys.indexOf(keyName) > -1) ? false : true;
      Object.defineProperty(returnObject, keyName, {
        value: inputObject[keyName],
        enumerable: isEnumerable
      });
    });
    return returnObject;
  };

  /**
   * Utility method to validate number is greater than or equal to zero.
   */
  var assertPositiveOrZero = function(input, field)
  {
    if (typeof input !== 'number') {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid number should be passed.');
    }
    if (input < 0) {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. Value should be greater than or equal to zero.');
    }
  };

  /**
   * Utility method to validate number is greater than zero.
   */
  var assertPositive = function(input, field)
  {
    if (typeof input !== 'number') {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid number should be passed.');
    }
    if (input <= 0) {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. Value should be greater than zero.');
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
    if (input === null || typeof input !== 'object') {
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
   * Utility method to validate string
   */
  var assertFunction = function(input, field)
  {
    if (typeof input !== 'function') {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid function should be passed.');
    }
  };

  /**
   * Utility method to validate buttons array
   */
  var assertButtonsArray = function(input, field)
  {
    if (input.constructor !== Array) {
      throw new Error('Invalid value ' + input + ' passed for ' + field + '. A valid array should be passed.');
    }
    else {
      var buttons = [];
      input.forEach(function(webViewButton) {
        if (!FedAuthPropertiesBuilder.Buttons.hasOwnProperty(webViewButton)) {
          throw new Error('Invalid value ' + input + ' passed for ' + field + '. Should be one from FedAuthPropertiesBuilder.Buttons.');
        }
        else {
          if(buttons.includes(webViewButton)) {
            throw new Error('Duplicate value ' + webViewButton + ' passed for ' + field + '. Value already present.');
          }
          else {
            buttons.push(webViewButton);
            if(buttons.includes(FedAuthPropertiesBuilder.Buttons.ALL) && buttons.length > 1)
              throw new Error('Invalid value ' + input + ' passed for ' + field + '. ALL cannot be present with other button types');
            if(buttons.includes(FedAuthPropertiesBuilder.Buttons.NONE) && buttons.length > 1)
              throw new Error('Invalid value ' + input + ' passed for ' + field + '. NONE cannot be present with other button types');
          }
        }
      })
    }
  };

  var initializeRemoteFlow = function(authProps, timeoutCb, resolve, reject) {
    exec(function(resp) {
      // If there is a timeoutCallback, register that before calling the successCallback.
      var authFlowKey = resp[AuthFlowKey];
      if (typeof timeoutCb === "function") {
        exec(timeoutCb, reject,  TAG, 'addTimeoutCallback', [authFlowKey]);
      }
      if (authProps[authPropertyKeys.AuthServerType] === authServerTypes.HttpBasicAuthentication) {
        resolve(new HttpBasicAuthenticationFlow(authFlowKey, authProps));
        return;
      }
      resolve(new RemoteAuthenticationFlow(authFlowKey, authProps));
    }, reject, TAG, 'setup', [authProps]);
  };

  var getError = function(errCode) {
    var error = {};
    error.errorCode = errCode;
    error.errorSource = IdmAuthFlows.ErrorSource.Plugin;
    error.translatedErrorMessage = "";
    return error;
  };

  var isTypeOf = function(type, instance) {
    for (var el in type)
      if (type.hasOwnProperty(el) && type[el] === instance)
        return true;

    return false;
  };
  // End: Util methods

  // Builders
  /**
   * @classdesc This class is the base builder for all auth types.
   * Use one of the subclasses to instantiate:
   * <ul style="list-style: none;">
   *  <li>{@link HttpBasicAuthPropertiesBuilder}</li>
   *  <li>{@link FedAuthPropertiesBuilder}</li>
   *  <li>{@link OAuthPropertiesBuilder}</li>
   *  <li>{@link OpenIDConnectPropertiesBuilder}</li>
   *  <li>{@link LocalAuthPropertiesBuilder}</li>
   * </ul>
   * @class PropertiesBuilder
   * @abstract
   */
  var PropertiesBuilder = function() {
    /**
     * Bag of all properties.
     * @memberof PropertiesBuilder.prototype
     */
    this.props = {};

    /**
     * Convenience method to add key value pairs of auth settings to properties.
     * @function put
     * @memberof PropertiesBuilder.prototype
     * @param {string} key - Authentication property key
     * @param {string} value - Authentication property value
     * @return {Builder}
     */
    this.put = function(key, value)
    {
      this.props[key] = value;
      return this;
    };
  };

  PropertiesBuilder.prototype = Object.create(Object.prototype, {
    /**
     * @function build
     * @memberof PropertiesBuilder.prototype
     * @return {Object} validate and return properties collected.
     */
    build: {
      value: function() {
        return this.props;
      }
    }
  });

  /**
   * @class RemoteAuthPropertiesBuilder
   * @classdesc This class is the base builder for all remote auth types.
   * Use one of the subclasses to instantiate:
   * <ul style="list-style: none;">
   *  <li>{@link HttpBasicAuthPropertiesBuilder}</li>
   *  <li>{@link FedAuthPropertiesBuilder}</li>
   *  <li>{@link OAuthPropertiesBuilder}</li>
   *  <li>{@link OpenIDConnectPropertiesBuilder}</li>
   * </ul>
   * @extends PropertiesBuilder
   * @param {string} appName - Application name
   * @abstract
   */
  var RemoteAuthPropertiesBuilder = function(appName)
  {
    PropertiesBuilder.call(this);

    /**
     * Authentication cancel callback. Used to cancel the challenge.
     * @callback RemoteAuthPropertiesBuilder~challengeCancelCallback
     */
    /**
     * Remote authentication challenge completion callback
     * @callback RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback
     * @param {RemoteAuthPropertiesBuilder~AuthChallenge} challenge - information collected from the user.
     */
    /**
     * Remote authentication challenge handler
     * @typedef {Object} RemoteAuthPropertiesBuilder~RemoteAuthChallengeHandler
     * @property {RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback} submit - App invokes this passing user input to proceed with the current challenge.
     * @property {RemoteAuthPropertiesBuilder~challengeCancelCallback} cancel - App invokes this to cancel the current challenge.
     */
    /**
     * This is the remote authentication challenge callback.
     * This callback is invoked when there is a challenge to collect credentials from the user in some authentications such as
     * {@link HttpBasicAuthPropertiesBuilder|HTTP basic auth} and {@link OAuthPropertiesBuilder|2 legged OAuth}.
     * This callback should be implemented by app and set to the respective builder as the {@link HttpBasicAuthPropertiesBuilder#challengeCallback|challenge callback}.
     * <p>In this callback app has to do the following:</p>
     * <p>On receiving this challenge, app should show a login screen to the user.
     * {@link RemoteAuthPropertiesBuilder~AuthChallenge|Challenge object} passed to this callback will contain any saved information,
     * such as saved username or password or saved preferences for remember user, remember credentials, auto login etc.
     * App should populate the login screen based on this information as explained in the {@link RemoteAuthPropertiesBuilder~AuthChallenge|challenge object documentation}.
     * Once user has provided the input, app should update the challenge object
     * and invoke {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|completion callback}.
     * If user wishes to cancel the login then app should invoke {@link RemoteAuthPropertiesBuilder~challengeCancelCallback|cancel callback}.
     * Both callbacks are passed to this as part of {@link RemoteAuthPropertiesBuilder~RemoteAuthChallengeHandler|challenge handler}</p>
     * @callback RemoteAuthPropertiesBuilder~remoteAuthChallengeCallback
     * @param {RemoteAuthPropertiesBuilder~AuthChallenge} challenge - Saved data if any and information to be collected from the user.
     * @param {RemoteAuthPropertiesBuilder~RemoteAuthChallengeHandler} challengeHandler - To be used by app to either submit or cancel the challenge.
     */
    /**
     * This callback represents remote authentication timeout callback. This is invoked when a timeout occurs in certain type of authentications.
     * <p>For {@link HttpBasicAuthPropertiesBuilder|HTTP basic auth} this callback will be invoked in following conditions:
     * <ul>
     * <li>{@link RemoteAuthPropertiesBuilder.TimeoutType|Idle timeout} with non zero {@link RemoteAuthPropertiesBuilder~TimeoutResponse|time left to timeout}
     * - This happens when {@link HttpBasicAuthPropertiesBuilder#percentageToIdleTimeout|percentage to idle timeout} is set to a non zero value.
     * In this case, the timeout can be extended by invoking {@link HttpBasicAuthenticationFlow#resetIdleTimeout}.</li>
     * <li>{@link RemoteAuthPropertiesBuilder.TimeoutType|Idle timeout} with zero {@link RemoteAuthPropertiesBuilder~TimeoutResponse|time left to timeout}
     * - User has to be re-authenticated. The app has to invoke {@link HttpBasicAuthenticationFlow#login}.
     * If {@link HttpBasicAuthPropertiesBuilder#autoLoginAllowed|auto login is allowed} and {@link RemoteAuthPropertiesBuilder~AuthChallenge|enabled} by user, login happens without challenge.</li>
     * <li>{@link RemoteAuthPropertiesBuilder.TimeoutType|Session timeout} ({@link RemoteAuthPropertiesBuilder~TimeoutResponse|time left to timeout} will always be zero for this)
     * - User has to be re-authenticated. The app has to invoke {@link AuthenticationFlow#login}. Auto login does not help here.</li>
     * </ul></p>
     * <p> For {@link FedAuthPropertiesBuilder|Federated auth}, there is only session timeout.
     * User has to be re-authenticated. The app has to invoke {@link AuthenticationFlow#login}.</p>
     * @callback RemoteAuthPropertiesBuilder~timeoutCallback
     * @param {RemoteAuthPropertiesBuilder~TimeoutResponse} timeoutResponse
     */
    /**
     * Object passed in {@link RemoteAuthPropertiesBuilder~timeoutCallback|timeout callback}
     * @typedef RemoteAuthPropertiesBuilder~TimeoutResponse
     * @property {RemoteAuthPropertiesBuilder.TimeoutType} TimeoutType - Type of timeout.
     * @property {number} TimeLeftToTimeout - Time in seconds after which timeout will happen.
     */
    /**
     * Challenge object passed in {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCallback|remote challenge callback}
     * @typedef RemoteAuthPropertiesBuilder~AuthChallenge
     * @property {String} username_key - <p>This is the username.</p> <p><i>When challenged:</i> Populated with saved username if any. App should use this value to display on the login screen.
     * Typically this is a text field on the UI.</p>
     * <p><i>When submitting:</i> Should contain user input when submitting the challenge using {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|submit callback}.</p>
     * @property {String} password_key - <p>This is the password.</p> <p><i>When challenged:</i> Populated with saved password if any. App should use this value to display on the login screen.
     * Typically this is a password field on the UI.</p>
     * <p><i>When submitting:</i> Should contain user input when submitting the challenge using {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|submit callback}.
     * @property {boolean} CollectIdentityDomain - <p>This is a read only property. This will indicate if app should collect identity domain from user or not.
     * @property {String=} iddomain_key - <p>This is the identity domain. <p><i>When challenged:</i> Populated with saved identity domain if any.
     * This is an optional field. App should use this value to display on the login screen.
     * Typically this is a text field on the UI. App should not showing this field if this key is missing in the challenge object.</p>
     * <p><i>When submitting:</i> Should contain user input when submitting the challenge using {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|submit callback}.
     * @property {AuthError=} error - <p>This is an error object.</p> <p><i>When challenged:</i> Populated with any error associated with previous login attempt.
     * This is available only when previous login attempt failed the user is re-challenged.
     * Typically used to display error message to the user.
     * <p><i>When submitting:</i> This need not be set when submitting the challenge using {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|submit callback}.</p>
     * @property {boolean} RememberUsernameAllowed - <p>This is a read only property. This will indicate if remember username feature is enabled or not.
     * App can decide to show this option to the user on the login screen depending on the value.
     * @property {boolean=} remember_username_ui_preference_key - <p>This is a user preference to say if the user wants app to remember the username or not.</p>
     * <p><i>When challenged:</i> Populated with saved preference if any.
     * This field is available only if {@link HttpBasicAuthPropertiesBuilder#rememberUsernameAllowed|allow remember user} is set to true in the configuration.
     * The value of this will be driven by {@link HttpBasicAuthPropertiesBuilder#rememberUsernameDefault|remember user default value}.
     * Typically collected using a checkbox. App should not showing this field if this key is missing in the challenge object.
     * It means {@link HttpBasicAuthPropertiesBuilder#rememberUsernameAllowed|allow remember user} is set to false in the configuration. </p>
     * <p><i>When submitting:</i> User can modify this value and modified value should be part of the challenge when
     * submitting using {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|submit callback}.
     * User provided value will have precedence over {@link HttpBasicAuthPropertiesBuilder#rememberUsernameDefault|remember user  default value} initially.
     * @property {boolean} RememberCredentialsAllowed - <p>This is a read only property. This will indicate if remember credentials feature is enabled or not.
     * App can decide to show this option to the user on the login screen depending on the value.
     * @property {boolean=} remember_credentials_ui_preference_key - <p>This is a user preference to say if the user wants app to remember credentials or not.</p>
     * <p><i>When challenged:</i> Populated with saved preference if any.
     * This field is available only if {@link HttpBasicAuthPropertiesBuilder#rememberCredentialsAllowed| allow remember credentials} is true in the configuration.
     * The value of this will be driven by {@link HttpBasicAuthPropertiesBuilder#rememberCredentialDefault|remember credentials default value} initially.
     * Typically collected using a checkbox. App should not showing this field if this key is missing in the challenge object.
     * It means {@link HttpBasicAuthPropertiesBuilder#rememberCredentialsAllowed|allow remember credentials} is set to false in the configuration. </p>
     * <p><i>When submitting:</i> User can modify this value and modified value should be part of the challenge when
     * submitting using {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|submit callback}.
     * User provided value will have precedence over {@link HttpBasicAuthPropertiesBuilder#rememberCredentialDefault|remember credentials default value}.
     * @property {boolean} AutoLoginAllowed - <p>This is a read only property. This will indicate if auto login is enabled or not.
     * App can decide to show this option to the user on the login screen depending on the value.
     * @property {boolean=} autoLogin_ui_preference_key - <p>This is a user preference to say if the user wants app to automatically login the user or not.</p>
     * <p><i>When challenged:</i> Populated with saved preference if any.
     * This field is available only if {@link HttpBasicAuthPropertiesBuilder#autoLoginAllowed| allow auto login} is set to true in the configuration.
     * The value of this will be driven by {@link HttpBasicAuthPropertiesBuilder#autoLoginDefault|auto login default value} initially.
     * Typically collected using a checkbox. App should not showing this field if this key is missing in the challenge object.
     * It means {@link HttpBasicAuthPropertiesBuilder#autoLoginAllowed|allow auto login} is set to false in the configuration.</p>
     * <p><i>When submitting:</i> User can modify this value and modified value should be part of the challenge when submitting using {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCompletionCallback|submit callback}.
     * User provided value will have precedence over {@link HttpBasicAuthPropertiesBuilder#autoLoginDefault|auto login default value}.</p>
     */

    /**
     * @function appName
     * @memberof RemoteAuthPropertiesBuilder.prototype
     * @param {String} appName - Application name
     * @return {RemoteAuthPropertiesBuilder}
     */
    this.appName = function(name) {
      assertString(name, authPropertyKeys.ApplicationName);
      this.put(authPropertyKeys.ApplicationName, name);
      return this;
    };

    /**
     * Deprecated: This is not applicable for all remote authentications. Use method available in builder subclasses where applicable.
     * @function idleTimeOutInSeconds
     * @memberof RemoteAuthPropertiesBuilder.prototype
     * @param {number} timeout - seconds after which which idle timeout should kick in when user is idle.
     * @return {RemoteAuthPropertiesBuilder}
     * @deprecated This is not applicable for all remote authentications. Use method available in builder subclasses where applicable.
     */
    this.idleTimeOutInSeconds = function(timeout)
    {
      assertPositiveOrZero(timeout, authPropertyKeys.IdleTimeOutValue);
      this.put(authPropertyKeys.IdleTimeOutValue, timeout);
      return this;
    };
    /**
     * Deprecated: This is not applicable for all remote authentications. Use method available in builder subclasses where applicable.
     * @function percentageToIdleTimeout
     * @memberof RemoteAuthPropertiesBuilder.prototype
     * @param {number} percentage - percentage of idle timeout before which timeout callback should be invoked.
     * @return {RemoteAuthPropertiesBuilder}
     * @deprecated This is not applicable for all remote authentications. Use method available in builder subclasses where applicable.
     */
    this.percentageToIdleTimeout = function(percentage)
    {
      assertPositiveOrZero(percentage, authPropertyKeys.PercentageToIdleTimeout);
      if (percentage < 0 || percentage > 100) {
        throw new Error(authPropertyKeys.PercentageToIdleTimeout + ' should be between [0 - 100].');
      }
      this.put(authPropertyKeys.PercentageToIdleTimeout, percentage);
      return this;
    };
    /**
     * Deprecated: This is not applicable for all remote authentications. Use method available in builder subclasses where applicable.
     * @function sessionTimeOutInSeconds
     * @memberof RemoteAuthPropertiesBuilder.prototype
     * @param {number} timeout - seconds after which which session timeout should kick in.
     * @return {RemoteAuthPropertiesBuilder}
     * @deprecated This is not applicable for all remote authentications. Use method available in builder subclasses where applicable.
     */
    this.sessionTimeOutInSeconds = function(timeout)
    {
      assertPositiveOrZero(timeout, authPropertyKeys.SessionTimeOutValue);
      this.put(authPropertyKeys.SessionTimeOutValue, timeout);
      return this;
    };
    /**
     * @function logoutTimeOutInSeconds
     * @memberof RemoteAuthPropertiesBuilder.prototype
     * @param {number} timeout - specifiy timeout before which ongoing logout attempt will be aborted.
     * @return {RemoteAuthPropertiesBuilder}
     */
    this.logoutTimeOutInSeconds = function(timeout)
    {
      assertPositiveOrZero(timeout, authPropertyKeys.LogoutTimeOutValue);
      this.put(authPropertyKeys.LogoutTimeOutValue, timeout);
      return this;
    };
    /**
     * @function customAuthHeaders
     * @memberof RemoteAuthPropertiesBuilder.prototype
     * @param {Object.<string, string>} headers - any custom headers. These are returned along with other authentication headers in RemoteAuthenticationFlow#getHeaders()
     * @return {RemoteAuthPropertiesBuilder}
     */
    this.customAuthHeaders = function(headers)
    {
      assertObject(headers, authPropertyKeys.CustomAuthHeaders);
      this.put(authPropertyKeys.CustomAuthHeaders, headers);
      this.put(authPropertyKeys.CustomHeadersForMobileAgent, headers);
      return this;
    };

    if (appName)
      this.appName(appName);
  };

  RemoteAuthPropertiesBuilder.prototype = Object.create(PropertiesBuilder.prototype, {
    /**
     * @function build
     * @memberof RemoteAuthPropertiesBuilder.prototype
     * @return {Object} validate and return properties collected.
     */
    build: {
      value: function() {
        if (!this.props[authPropertyKeys.ApplicationName])
          throw new Error('Mandatory parameter appName not set.');
        return Object.getPrototypeOf(RemoteAuthPropertiesBuilder.prototype).build.call(this);
      }
    }
  });
  RemoteAuthPropertiesBuilder.prototype.constructor = RemoteAuthPropertiesBuilder;
  /**
   * Possible values for {@link RemoteAuthPropertiesBuilder~TimeoutResponse|RemoteAuthPropertiesBuilder.TimeoutResponse.TimeoutType}
   * @memberof RemoteAuthPropertiesBuilder
   * @enum
   * @readonly
   */
  RemoteAuthPropertiesBuilder.TimeoutType = {
    /**
     * Timeout type is session timeout
     * @type {string}
     */
   SessionTimeout:'SESSION_TIMEOUT',
    /**
     * Timeout type is idle timeout
     * @type {string}
     */
   IdleTimeout:'IDLE_TIMEOUT'
  };


  /**
   * @class HttpBasicAuthPropertiesBuilder
   * @classdesc This class is the builder for HTTP Basic Authentication.
   * Using this builder to {@link init} an authentication flow will return {@link HttpBasicAuthenticationFlow} in the init promise.
   * <p>In this type of authentication, while logging in, user will be challenged to provide credentials and preferences.
   * At this time {@link HttpBasicAuthPropertiesBuilder#challengeCallback|challenge callback} provided by app will get invoked.
   * App should collect these from the user and pass it back.
   * See {@link RemoteAuthPropertiesBuilder~remoteAuthChallengeCallback|remote authentication challenge callback documentation} for details.
   * In addition, app can attach {@link RemoteAuthPropertiesBuilder~timeoutCallback|timeout callback} to handle authentication timeouts.</p>
   * @extends RemoteAuthPropertiesBuilder
   * @param {string} appName - Application name
   * @param {string} loginUrl - Basic auth login end point.
   * @param {string} logoutUrl - Basic auth logout end point.
   */
  var HttpBasicAuthPropertiesBuilder = function(appName, loginUrl, logoutUrl) {
    RemoteAuthPropertiesBuilder.call(this, appName);
    this.put(authPropertyKeys.AuthServerType, authServerTypes.HttpBasicAuthentication);
    // AES is the only crypto scheme that the plugin will support.
    // This is because plugin needs to be able to retrieve unencrypted credentials for headers and AES is only way to do that.
    this.put(authPropertyKeys.CryptoScheme, 'AES');
    // Always set headers for logout.
    this.put(authPropertyKeys.SendAuthorizationHeaderInLogout, true);
    this.put(authPropertyKeys.SendCustomAuthHeadersInLogout, true);

    /**
     * @function loginUrl
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {string} url - Basic auth login end point.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.loginUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LoginURL);
      this.put(authPropertyKeys.LoginURL, url);
      return this;
    };
    /**
     * @function logoutUrl
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {string} url - Basic auth logout end point.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.logoutUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutURL);
      this.put(authPropertyKeys.LogoutURL, url);
      return this;
    };
    /**
     * This has effect only when {@link HttpBasicAuthPropertiesBuilder#offlineAuthAllowed} is set to 'true'.
     * When set to 'false' will result in an {@link ConnectivityMode|Online} login always.
     * @function connectivityMode
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {HttpBasicAuthPropertiesBuilder.ConnectivityMode} mode - connectivity mode to be used
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.connectivityMode = function(mode)
    {
      assertString(mode, authPropertyKeys.ConnectivityMode);
      if (!HttpBasicAuthPropertiesBuilder.ConnectivityMode.hasOwnProperty(mode)) {
        throw new Error(authPropertyKeys.ConnectivityMode + ' should be one from HttpBasicAuthPropertiesBuilder.ConnectivityMode.');
      }
      this.put(authPropertyKeys.ConnectivityMode, mode);
      return this;
    };

    /**
     * Defaults to true. In general, apps want to retrieve headers for secured resource access.
     * Apps can set this to false if they do not want the functionality.
     * <p>
     * Setting this to true results in credentials being stored offline in secured storage.
     * App will be authenticated against this, when {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode|Offline} login applies.</p>
     * <p> No matter what {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode} is set, first time login will always be ONLINE.
     * Offline credentials will be cleared if user exceeds the {@link HttpBasicAuthPropertiesBuilder#maxLoginAttempts} while logging in.</p>
     * <ul>
     * <li>When set to false results in ONLINE login always, no matter what {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode} is set.</li>
     * <li>When set to true and {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode} is set to ONLINE. This results in an ONLINE login always.</li>
     * <li>When set to true and {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode} is set to OFFLINE.
     * This results in OFFLINE login for subsequent attempts. In the case of wrong credentials,
     * an ONLINE login will be attempted after maxLoginAttempts is exceeded.</li>
     * <li>When set to true and {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode} is set to AUTO.
     * Cookie validity determines the type if subsequent login performed.
     * If cookies are valid, it will be an OFFLINE login, otherwise it will be ONLINE login.</li>
     * </ul></p>
     * <p> Note: {@link RemoteAuthenticationFlow#getHeaders} API depends on this to be able to retrieve the Authorization headers.</p>
     * @function offlineAuthAllowed
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} allowed - if offline auth is allowed or not. Defaults to 'true'.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.offlineAuthAllowed = function(allowed)
    {
      assertBoolean(allowed, authPropertyKeys.OfflineAuthAllowed);
      this.put(authPropertyKeys.OfflineAuthAllowed, allowed);
      return this;
    };

    /**
     * @function maxLoginAttempts
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {number} attempts - maximum login attempts
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.maxLoginAttempts = function(attempts)
    {
      assertPositiveOrZero(attempts, authPropertyKeys.MaxLoginAttempts);
      this.put(authPropertyKeys.MaxLoginAttempts, attempts);
      return this;
    };

    /**
     * This method is for specifying if user is allowed to configure remember user preference or not.
     * This allows app to control what the user can do in the login screen. If this is set to 'true'
     * value set in {@link HttpBasicAuthPropertiesBuilder#rememberUsernameDefault} will be returned in the
     * {@link RemoteAuthPropertiesBuilder~AuthChallenge| challenge} for remember user preference.
     * @function rememberUsernameAllowed
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} allowed - if user can be allowed to change the preference for remembering user name .
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.rememberUsernameAllowed = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberUsernameAllowed);
      this.put(authPropertyKeys.RememberUsernameAllowed, bool);
      return this;
    };

    /**
     * This method is for specifying if user is allowed to configure remember credentials preference or not.
     * This allows app to control what the user can do in the login screen. If this is set to 'true'
     * value set in {@link HttpBasicAuthPropertiesBuilder#rememberCredentialDefault} will be returned in the
     * {@link RemoteAuthPropertiesBuilder~AuthChallenge| challenge} for remember password preference.
     * @function rememberCredentialsAllowed
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} allowed - if user can be allowed to change the preference for remembering credential.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.rememberCredentialsAllowed = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberCredentialsAllowed);
      this.put(authPropertyKeys.RememberCredentialsAllowed, bool);
      return this;
    };

    /**
     * This method is for specifying if user is allowed to configure automatic login preference or not.
     * This allows app to control what the user can do in the login screen. If this is set to 'true'
     * value set in {@link HttpBasicAuthPropertiesBuilder#autoLoginDefault} will be returned in the
     * {@link RemoteAuthPropertiesBuilder~AuthChallenge| challenge} for auto login preference.
     * This feature enables user to login without challenge, after first successful login, until session times out or user logs out.
     * @function autoLoginAllowed
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} allowed - if user can be allowed to change the preference for auto login.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.autoLoginAllowed = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.AutoLoginAllowed);
      this.put(authPropertyKeys.AutoLoginAllowed, bool);
      return this;
    };

    /**
     * This method sets the default value for remember user preference.
     * This preference is applicable only when {HttpBasicAuthPropertiesBuilder#rememberUsernameAllowed} is true
     * @function rememberUsernameDefault
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} allowed - default value for remember username preference.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.rememberUsernameDefault = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberUsernameDefault);
      this.put(authPropertyKeys.RememberUsernameDefault, bool);
      return this;
    };

    /**
     * This method sets the default value for remember credentials preference.
     * This preference is applicable only when {HttpBasicAuthPropertiesBuilder#rememberCredentialsAllowed} is true
     * @function rememberCredentialDefault
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} allowed - default value for remember credential preference.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.rememberCredentialDefault = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.RememberCredentialDefault);
      this.put(authPropertyKeys.RememberCredentialDefault, bool);
      return this;
    };

    /**
     * This method sets the default value for automatic login preference.
     * This preference is applicable only when {HttpBasicAuthPropertiesBuilder#autoLoginAllowed} is true
     * @function autoLoginDefault
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} allowed - default value for auto login preference.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.autoLoginDefault = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.AutoLoginDefault);
      this.put(authPropertyKeys.AutoLoginDefault, bool);
      return this;
    };

    /**
     * @function idleTimeOutInSeconds
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {number} timeout - seconds after which which idle timeout should kick in when user is idle.
     * After these many seconds {@link RemoteAuthPropertiesBuilder~timeoutCallback|timeout callback} will be invoked.
     * Note: 'Idle' is not tied to app usage yet. It is based on IDM isValid API invocation.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.idleTimeOutInSeconds = function(timeout)
    {
      assertPositiveOrZero(timeout, authPropertyKeys.IdleTimeOutValue);
      this.put(authPropertyKeys.IdleTimeOutValue, timeout);
      return this;
    };

    /**
     * @function percentageToIdleTimeout
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {number} percentage - percentage of idle timeout before which timeout callback should be invoked.
     * This can be used to alerted user about the upcoming idle timeout in {@link RemoteAuthPropertiesBuilder~timeoutCallback|timeout callback}
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.percentageToIdleTimeout = function(percentage)
    {
      assertPositiveOrZero(percentage, authPropertyKeys.PercentageToIdleTimeout);
      if (percentage < 0 || percentage > 100) {
        throw new Error(authPropertyKeys.PercentageToIdleTimeout + ' should be between [0 - 100].');
      }
      this.put(authPropertyKeys.PercentageToIdleTimeout, percentage);
      return this;
    };

    /**
     * @function sessionTimeOutInSeconds
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {number} timeout - seconds after which which session timeout should kick in.
     * After these many seconds {@link RemoteAuthPropertiesBuilder~timeoutCallback|timeout callback} will be invoked.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.sessionTimeOutInSeconds = function(timeout)
    {
      assertPositiveOrZero(timeout, authPropertyKeys.SessionTimeOutValue);
      this.put(authPropertyKeys.SessionTimeOutValue, timeout);
      return this;
    };

    /**
     * @function challengeCallback
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {RemoteAuthPropertiesBuilder~remoteAuthChallengeCallback} callback - Callback to handle credential challenge.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.challengeCallback = function(callback)
    {
      assertFunction(callback, authPropertyKeys.ChallengeCallback);
      this.put(authPropertyKeys.ChallengeCallback, callback);
      return this;
    };

    /**
     * @function timeoutCallback
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {RemoteAuthPropertiesBuilder~timeoutCallback} callback - Callback to handle timeout notifications.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.timeoutCallback = function(callback)
    {
      assertFunction(callback, authPropertyKeys.TimeoutCallback);
      this.put(authPropertyKeys.TimeoutCallback, callback);
      return this;
    };

    /**
     * This is to specify if the user challenge should contain identity domain or not. Defaults to false.
     * @function collectIdentityDomain
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} collect - true to collect identity domain when user is challenged.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.collectIdentityDomain = function(collect) {
      assertBoolean(collect, authPropertyKeys.CollectIdentityDomain);
      this.put(authPropertyKeys.CollectIdentityDomain, collect);
      return this;
    };

    /**
     * This is to specify whether identity domain is sent as header value as
     * per {@link HttpBasicAuthPropertiesBuilder#identityDomainHeaderName}, when set to true,
     * or should be prepended with the user name as identity_domain_name.user_name,
     * when set to false.
     * Default value is false.
     * @function passIdentityDomainNameInHeader
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {boolean} pass - true to pass identity domain in header
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.passIdentityDomainNameInHeader = function(pass) {
      assertBoolean(pass, authPropertyKeys.IdentityDomainNameInHeader);
      this.put(authPropertyKeys.IdentityDomainNameInHeader, pass);
      return this;
    };

    /**
     * Works only when {@link HttpBasicAuthPropertiesBuilder#passIdentityDomainNameInHeader} is set to true.
     * Default value is X-USER-IDENTITY-DOMAIN-NAME.
     * @function identityDomainHeaderName
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @param {string} headerName - header name to be used.
     * @return {HttpBasicAuthPropertiesBuilder}
     */
    this.identityDomainHeaderName = function(headerName) {
      assertString(headerName, authPropertyKeys.IdentityDomainHeaderName);
      this.put(authPropertyKeys.IdentityDomainHeaderName, headerName);
      return this;
    };

    if (loginUrl)
      this.loginUrl(loginUrl);
    if (logoutUrl)
      this.logoutUrl(logoutUrl);

    this.offlineAuthAllowed(true);
  };

  HttpBasicAuthPropertiesBuilder.prototype = Object.create(RemoteAuthPropertiesBuilder.prototype, {
    /**
     * @function build
     * @memberof HttpBasicAuthPropertiesBuilder.prototype
     * @return {Object} validate and return properties collected.
     */
    build: {
      value: function() {
        if (!this.props[authPropertyKeys.LoginURL])
          throw new Error('Mandatory parameter loginUrl not set.');
        if (!this.props[authPropertyKeys.LogoutURL])
          throw new Error('Mandatory parameter logoutUrl not set.');
        return Object.getPrototypeOf(HttpBasicAuthPropertiesBuilder.prototype).build.call(this);
      }
    }
  });
  HttpBasicAuthPropertiesBuilder.prototype.constructor = HttpBasicAuthPropertiesBuilder;
  /**
   * Enum values for {@link HttpBasicAuthPropertiesBuilder#connectivityMode}
   * @memberof HttpBasicAuthPropertiesBuilder
   * @enum
   * @readonly
   */
  HttpBasicAuthPropertiesBuilder.ConnectivityMode = {
    /**
     * Connectivity mode is online
     * @type {string}
     */
    Online:'Online',
    /**
     * Connectivity mode is offline
     * @type {string}
     */
    Offline:'Offline',
    /**
     * Connectivity mode is auto
     * @type {string}
     */
    Auto:'Auto'
  };

  /**
   * @class FedAuthPropertiesBuilder
   * @classdesc This is the builder for federated authentication / web SSO.
   * Using this builder to {@link init} an authentication flow will return {@link RemoteAuthenticationFlow} in the init promise.
   * <p>In this type of authentication, while logging in, the plugin brings up a WebView and loads the {@link FedAuthPropertiesBuilder#loginUrl|login page} provided in the configuration.
   * User has credentials on this page. When login is successful, the WebView will be removed and user will be redirected back to the app.
   * While showing the WebView, plugin provides basic operations such as "Forward", "Back", "Reload" and "Cancel" to deal with any issues the user faces on this page.
   * For example, user may accidentally click a link on the login page. In this case, user can use "Back" button to come back to the login page.
   * For example, if the login page is not loaded correctly, user may want to try reloading the page, before cancelling the login.
   * If user cancels the login, the promise returned by {@link AuthenticationFlow#login} will be rejected.
   * For iOS, {@link https://developer.apple.com/documentation/uikit/uiwebview|UIWebView} will be used by default.
   * App can choose to use {@link https://developer.apple.com/documentation/webkit/wkwebview|WKWebView} through {@link FedAuthPropertiesBuilder#enableWkWebView|configuration}.
   * </p>
   * <p>
   * While logging out, the plugin brings up a WebView and loads the {@link FedAuthPropertiesBuilder#logoutUrl|logout page} provided in the configuration.
   * Typically this step does not have any user interaction. The logout page loads with a confirmation and then is dismissed.
   * However, some federated authentication servers provide a logout confirmation screen where the user is expected to provide his consent for logout.
   * This feature is introduced by certain federated auth servers as they wanted the user to be fully aware that they are logging out and does not do so accidentally.
   * There are two ways to handle this situation. First by having the confirmation screen dismissed automatically, without user interaction.
   * This can be achieved by setting {@link FedAuthPropertiesBuilder#confirmLogoutAutomatically} to true and providing
   * {@link FedAuthPropertiesBuilder#confirmLogoutButtonId} if needed. The other way is to wait for user to provide his consent.
   * This can be done by specifying {@link FedAuthPropertiesBuilder#logoutSuccessUrl} and {@link FedAuthPropertiesBuilder#logoutFailureUrl}.
   * Note: Irrespective of whether user cancels the logout or accepts the logout in the confirmation screen, the user is logged out.</p>
   * @extends RemoteAuthPropertiesBuilder
   * @param {string} appName - Application name
   * @param {string} loginUrl - Fed auth login end point.
   * @param {string} logoutUrl - Fed auth logout end point.
   * @param {string} loginSuccessUrl - End point to which server redirects after successful login.
   * @param {string} loginFailureUrl - End point to which server redirects after unsuccessful login.
   */
   var FedAuthPropertiesBuilder = function(appName, loginUrl, logoutUrl, loginSuccessUrl, loginFailureUrl) {
    RemoteAuthPropertiesBuilder.call(this, appName);
    this.put(authPropertyKeys.AuthServerType, authServerTypes.FederatedAuthentication);
    // There is a feature to remember the user name for fed auth cases.
    // Android has this support inbuilt in the OS level. So setting this property does not make a difference for Android.
    // iOS SDK needs this flag to remember the user name. So to make things consistent across platforms, this is set by default.
    // In android, user has to long press the user name field to get access to the remembered username.
    // In iOS, it is pre-populated.
    this.put(authPropertyKeys.RememberUsernameAllowed, true);

    /**
     * @function loginUrl
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {string} url - Fed auth login end point.
     * @return {FedAuthPropertiesBuilder}
     */
    this.loginUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LoginURL);
      this.put(authPropertyKeys.LoginURL, url);
      return this;
    };
    /**
     * @function logoutUrl
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {string} url - Fed auth logout end point.
     * @return {FedAuthPropertiesBuilder}
     */
    this.logoutUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutURL);
      this.put(authPropertyKeys.LogoutURL, url);
      return this;
    };
    /**
     * @function loginSuccessUrl
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {string} url - End point to which server redirects after successful login.
     * @return {FedAuthPropertiesBuilder}
     */
    this.loginSuccessUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LoginSuccessURL);
      this.put(authPropertyKeys.LoginSuccessURL, url);
      return this;
    };
    /**
     * @function loginFailureUrl
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {string} url - End point to which server redirects after unsuccessful login.
     * @return {FedAuthPropertiesBuilder}
     */
    this.loginFailureUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LoginFailureURL);
      this.put(authPropertyKeys.LoginFailureURL, url);
      return this;
    };
    /**
     * @function parseTokenRelayResponse
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {boolean} allow - if relay response token needs to be parsed. Used in case of SAML flows.
     * @return {FedAuthPropertiesBuilder}
     */
    this.parseTokenRelayResponse = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.ParseTokenRelayResponse);
      this.put(authPropertyKeys.ParseTokenRelayResponse, bool);
      return this;
    };

    /**
     * @function enableWebViewButtons
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {Array.<string>} actionButtonList - List of buttons to be enabled in web view. Defaults to ['ALL'].
     * @return {FedAuthPropertiesBuilder}
     */
    this.enableWebViewButtons = function(actionButtonList)
    {
      assertButtonsArray(actionButtonList, authPropertyKeys.EnableWebViewButtons);
      this.put(authPropertyKeys.EnableWebViewButtons, actionButtonList);
      return this;
    };

    /**
     * @function enableWkWebView
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {boolean} enable - if WKWebView should be enabled. Applicable only for iOS.
     * Note: App should install cordova-plugin-wkwebview-engine when using this.
     * @return {FedAuthPropertiesBuilder}
     */
    this.enableWkWebView = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.EnableWkWebView);
      this.put(authPropertyKeys.EnableWkWebView, bool);
      return this;
    };

    /**
     * @function confirmLogoutAutomatically
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {boolean} automatic - whether to confirm the logout automatically when presented with a logout confirmation screen from the server.
     * @return {FedAuthPropertiesBuilder}
     */
    this.confirmLogoutAutomatically = function(bool)
    {
      assertBoolean(bool, authPropertyKeys.ConfirmLogoutAutomatically);
      this.put(authPropertyKeys.ConfirmLogoutAutomatically, bool);
      return this;
    };

    /**
     * @function confirmLogoutButtonId
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {string} buttonId - DOM id of the logout confirmation button. Used when FedAuthPropertiesBuilder#confirmLogoutAutomatically is turned on.
     * @return {FedAuthPropertiesBuilder}
     */
    this.confirmLogoutButtonId = function(buttonId)
    {
      assertString(buttonId, authPropertyKeys.ConfirmLogoutButtonId);
      this.put(authPropertyKeys.ConfirmLogoutButtonId, buttonId);
      return this;
    };

    /**
     * @function logoutSuccessUrl
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {string} url - End point to which server redirects after successful logout. Used along with logout confirmation screen usecase.
     * @return {FedAuthPropertiesBuilder}
     */
    this.logoutSuccessUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutSuccessURL);
      this.put(authPropertyKeys.LogoutSuccessURL, url);
      return this;
    };

    /**
     * @function logoutFailureUrl
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {string} url - End point to which server redirects after unsuccessful logout. Used along with logout confirmation screen usecase.
     * @return {FedAuthPropertiesBuilder}
     */
    this.logoutFailureUrl = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutFailureURL);
      this.put(authPropertyKeys.LogoutFailureURL, url);
      return this;
    };

    /**
     * @function sessionTimeOutInSeconds
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {number} timeout - set to the same value as configured in the fed auth server.
     * After these many seconds {@link RemoteAuthPropertiesBuilder~timeoutCallback|timeout callback} will be invoked.
     * Note: This does not trigger any session timeout on the server. That configuration is controlled by the server.
     * The effect of setting this is only to remove cookies after such time when server session would have time out.
     * @return {FedAuthPropertiesBuilder}
     */
    this.sessionTimeOutInSeconds = function(timeout)
    {
      assertPositiveOrZero(timeout, authPropertyKeys.SessionTimeOutValue);
      this.put(authPropertyKeys.SessionTimeOutValue, timeout);
      return this;
    };

    /**
     * @function timeoutCallback
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {RemoteAuthPropertiesBuilder~timeoutCallback} callback - Callback to handle timeout notifications.
     * @return {FedAuthPropertiesBuilder}
     */
    this.timeoutCallback = function(callback)
    {
      assertFunction(callback, authPropertyKeys.TimeoutCallback);
      this.put(authPropertyKeys.TimeoutCallback, callback);
      return this;
    };

    /**
     * This does not work for normal FedAuth cases. This is applicable for SAML kind of cases where
     * {@link FedAuthPropertiesBuilder#parseTokenRelayResponse} is turned on.
     * In this context, this parameter can be used for turning on access token reuse over app restarts.
     * With this turned on, when app is restarted, a user trying to login won't be prompted for
     * credentials, if there is a valid JWT token.
     * @function sessionActiveOnRestart
     * @memberof FedAuthPropertiesBuilder.prototype
     * @param {boolean} active - Whether to preserve login across restarts.
     * @return {FedAuthPropertiesBuilder}
     */
    this.sessionActiveOnRestart = function(active) {
      assertBoolean(active, authPropertyKeys.SessionActiveOnRestart);
      this.put(authPropertyKeys.SessionActiveOnRestart, active);
      return this;
    }

    if (loginUrl)
      this.loginUrl(loginUrl);
    if (logoutUrl)
      this.logoutUrl(logoutUrl);
    if (loginSuccessUrl)
      this.loginSuccessUrl(loginSuccessUrl);
    if (loginFailureUrl)
      this.loginFailureUrl(loginFailureUrl);
  };

  FedAuthPropertiesBuilder.prototype = Object.create(RemoteAuthPropertiesBuilder.prototype, {
    /**
     * @function build
     * @memberof FedAuthPropertiesBuilder.prototype
     * @return {Object} validate and return properties collected.
     */
    build: {
      value: function() {
        if (!this.props[authPropertyKeys.LoginURL])
          throw new Error('Mandatory parameter loginUrl not set.');
        if (!this.props[authPropertyKeys.LogoutURL])
          throw new Error('Mandatory parameter logoutUrl not set.');
        if (!this.props[authPropertyKeys.LoginSuccessURL])
          throw new Error('Mandatory parameter loginSuccessUrl not set.');
        if (!this.props[authPropertyKeys.LoginFailureURL])
          throw new Error('Mandatory parameter loginFailureUrl not set.');

        // As per IDM SDK, when SessionActiveOnRestart is set, session timeout and idle timeout should not be set.
        if (this.props[authPropertyKeys.SessionActiveOnRestart]) {
          delete this.props[authPropertyKeys.SessionTimeOutValue];
          delete this.props[authPropertyKeys.IdleTimeOutValue];
        }

        return Object.getPrototypeOf(FedAuthPropertiesBuilder.prototype).build.call(this);
      }
    }
  });
  FedAuthPropertiesBuilder.prototype.constructor = FedAuthPropertiesBuilder;

  /**
   * Enum values for types of button supported.
   * @enum
   * @readonly
   * @memberof FedAuthPropertiesBuilder
   */
  FedAuthPropertiesBuilder.Buttons = {
    /**
     * Button type is BACK. This button on the webview can be used by the user to
     * navigate back if they navigate away from the login page and wants to come back.
     * @type {string}
     */
    BACK: 'BACK',
    /**
     * Button type is FORWARD. This button on the webview can be used by the user to
     * navigate to the next from login page.
     * @type {string}
     */
    FORWARD: 'FORWARD',
    /**
     * Button type is REFRESH. This button on the webview can be used by the user to
     * refresh the current login screen.
     * @type {string}
     */
    REFRESH: 'REFRESH',
    /**
     * Button type is CANCEL. This button on the webview can be used by the user to
     * cancel the current flow of navigation to login screen and go back to home screen.
     * @type {string}
     */
    CANCEL: 'CANCEL',
    /**
     * Button type is ALL. Represents scenario where all the buttons are to be displayed
     * @type {string}
     */
    ALL: 'ALL',
    /**
     * Button type is NONE. Represents scenario where none of the button is to be displayed
     * @type {string}
     */
    NONE: 'NONE'
  };
  /**
   * @class OAuthPropertiesBuilder
   * @classdesc This is the builder for OAuth.
   * Using this builder to {@link init} an authentication flow will return {@link RemoteAuthenticationFlow} in the init promise.
   * <p>In this type of authentication login can be configured to use an embedded WebView or an external browser.
   * This can be {@link OAuthPropertiesBuilder#browserMode|configured}.
   * <ul style="list-style:none">
   * <li>{@link OAuthPropertiesBuilder.BrowserMode|Using Embedded WebView}: Plugin brings up a WebView where OAuth login webpage is loaded.
   * User has to provide credentials on this page and login. When login is successful, the WebView will be removed and user will be redirected back to the app.
   * While showing the WebView, plugin provides basic operations such as "Forward", "Back", "Reload" and "Cancel" to deal with any issues the user faces on this page.
   * For example, user may accidentally click a link on the login page. In this case, user can use "Back" button to come back to the login page.
   * For example, if the login page is not loaded correctly, user may want to try reloading the page, before cancelling the login.
   * If user cancels the login, the promise returned by {@link AuthenticationFlow#login} will be rejected.</li>
   * <li>{@link OAuthPropertiesBuilder.BrowserMode|Using External Browser}: Plugin redirects user to the default browser in the device and loads the OAuth login webpage.
   * User has to provide credentials on this page and login. When login is successful, user will be redirected back to the app.
   *
   * For using this feature there are three prerequisites:
   * <ul>
   * <li>App needs to configure a {@link https://www.npmjs.com/package/cordova-plugin-customurlscheme|custom URL scheme}.
   * It has to be noted that once the external browser is launched and login page is loaded, app does not have any control.
   * Custom URL scheme is the way for any redirects back to the app.</li>
   * <li>OAuth server should have the capability to use the same custom URL scheme and redirect the user back to app after successful login or logout.
   * This is typically part of OAuth server configuration.
   * For example, "Redirect URL" should be configured from the admin console to point to app's custom URL scheme in case of IDCS server.</li>
   * <li>{@link OAuthPropertiesBuilder#oAuthRedirectEndpoint|Redirect end point} in configuration should be provided as the URL scheme.</li>
   * </ul>
   * The advantage of using external browser is that it makes this login as a single sign on for all the apps in the device.
   * For example, this is advantageous for Google OAuth usecases.
   * </li>
   * </ul>
   * </p>
   * <p>
   * In case of OAuth, typically user does not logout when using external browser as it defeats the purpose.
   * User will be challenged to login only if the OAuth token expires.
   * Still, if the app wants to provide a logout option to the user, it can be done by calling {@link AuthenticationFlow#logout}.
   * This step does not have any user interaction.
   * OAuth logout page is loaded either in WebView or external browser as configured and then is dismissed once logout is complete.</p
   * <p>
   * Some OAuth servers supports refresh token.
   * Auth tokens generally are short lived and refresh tokens are long lived.
   * When the auth token expires, the refresh token can be used to obtain a new auth token and there is no need to challenge the user.
   * For obtaining the refresh token, some servers requires special scope to be passed.
   * For e.g: IDCS needs "offline_access" scope to be used.
   * App needs to pass the relevant scope, if needed by the server, for this feature to work</p>
   *
   * @extends RemoteAuthPropertiesBuilder
   * @param {string} appName - Application name
   * @param {OAuthPropertiesBuilder.OAuthAuthorizationGrantType} oAuthAuthorizationGrantType - OAuth authorization grant type.
   * @param {string} oAuthTokenEndpoint - OAuth token end point.
   * @param {string} oAuthClientID - OAuth client id.
   */
  var OAuthPropertiesBuilder = function(appName, grantType, tokenEndpoint, clientId) {
    RemoteAuthPropertiesBuilder.call(this, appName);
    this.put(authPropertyKeys.AuthServerType, authServerTypes.OAuthAuthentication);
    this.put(authPropertyKeys.SessionActiveOnRestart, true);

    /**
     * @function oAuthAuthorizationGrantType
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {OAuthPropertiesBuilder.OAuthAuthorizationGrantType} grantType - authorization end point.
     * @return {OAuthPropertiesBuilder}
     */
    this.oAuthAuthorizationGrantType = function(grantType)
    {
      assertString(grantType, authPropertyKeys.OAuthAuthorizationGrantType);
      if (!OAuthPropertiesBuilder.OAuthAuthorizationGrantType.hasOwnProperty(grantType)) {
        throw new Error(authPropertyKeys.OAuthAuthorizationGrantType + ' should be one from OAuthPropertiesBuilder.OAuthAuthorizationGrantType.');
      }
      this.put(authPropertyKeys.OAuthAuthorizationGrantType, grantType);
      return this;
    };

    /**
     * @function oAuthTokenEndpoint
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {string} url - OAuth token end point.
     * @return {OAuthPropertiesBuilder}
     */
    this.oAuthTokenEndpoint = function(url)
    {
      assertUrl(url, authPropertyKeys.OAuthTokenEndpoint);
      this.put(authPropertyKeys.OAuthTokenEndpoint, url);
      return this;
    };
    /**
     * @function oAuthClientID
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {string} clientId - OAuth client id.
     * @return {OAuthPropertiesBuilder}
     */
    this.oAuthClientID = function(clientId)
    {
      assertString(clientId, authPropertyKeys.OAuthClientID);
      this.put(authPropertyKeys.OAuthClientID, clientId);
      return this;
    };
    /**
     * @function oAuthAuthorizationEndpoint
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {string} url - authorization end point.
     * @return {OAuthPropertiesBuilder}
     */
    this.oAuthAuthorizationEndpoint = function(url)
    {
      assertUrl(url, authPropertyKeys.OAuthAuthorizationEndpoint);
      this.put(authPropertyKeys.OAuthAuthorizationEndpoint, url);
      return this;
    };

    /**
     * @function oAuthRedirectEndpoint
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {string} url - End point to redirect after successful authentication. Typically this is app's URL scheme.
     * @return {OAuthPropertiesBuilder}
     */
    this.oAuthRedirectEndpoint = function(url)
    {
      assertUrl(url, authPropertyKeys.OAuthRedirectEndpoint);
      this.put(authPropertyKeys.OAuthRedirectEndpoint, url);
      return this;
    };

    /**
     * @function oAuthClientSecret
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {string} secret - client secret.
     * @return {OAuthPropertiesBuilder}
     */
    this.oAuthClientSecret = function(secret)
    {
      assertString(secret, authPropertyKeys.OAuthClientSecret);
      this.put(authPropertyKeys.OAuthClientSecret, secret);
      return this;
    };

    /**
     * @function oAuthScope
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {Array.<string>} scopes - OAuth scopes.
     * @return {OAuthPropertiesBuilder}
     */
    this.oAuthScope = function(scopes)
    {
      assertObject(scopes, authPropertyKeys.OAuthScope);
      this.put(authPropertyKeys.OAuthScope, scopes);
      return this;
    };

    /**
     * @function logoutURL
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {string} url - OAuth logout URL.
     * @return {OAuthPropertiesBuilder}
     */
    this.logoutURL = function(url)
    {
      assertUrl(url, authPropertyKeys.LogoutURL);
      this.put(authPropertyKeys.LogoutURL, url);
      return this;
    };

    /**
     * @function browserMode
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {OAuthPropertiesBuilder.BrowserMode} mode - Browser mode to be used.
     * @return {OAuthPropertiesBuilder}
     */
    this.browserMode = function(mode)
    {
      assertString(mode, authPropertyKeys.BrowserMode);
      if (!OAuthPropertiesBuilder.BrowserMode.hasOwnProperty(mode)) {
        throw new Error(authPropertyKeys.BrowserMode + ' should be one from OAuthPropertiesBuilder.BrowserMode.');
      }
      this.put(authPropertyKeys.BrowserMode, mode);
      return this;
    };

    /**
     * Applicable for 2 legged OAuth flows when user is challenge to collect user credentials.
     * @function challengeCallback
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {RemoteAuthPropertiesBuilder~remoteAuthChallengeCallback} callback - Callback to handle credential challenge.
     * @return {OAuthPropertiesBuilder}
     */
    this.challengeCallback = function(callback)
    {
      assertFunction(callback, authPropertyKeys.ChallengeCallback);
      this.put(authPropertyKeys.ChallengeCallback, callback);
      return this;
    };

    /**
     * This method can be used to enable PKCE for OAuth. PKCE is more secured way of using OAUTH for mobile apps.
     * See {@link http://www.ateam-oracle.com/identity-cloud-service-mobile-clients-and-pkce-support|this blog}
     * @function enablePKCE
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {boolean} enable - whether to enable PKCE or not.
     * @return {OAuthPropertiesBuilder}
     */
    this.enablePKCE = function(enable) {
      assertBoolean(enable, authPropertyKeys.EnablePKCE);
      this.put(authPropertyKeys.OAuthEnablePKCE, enable);
      return this;
    };

    /**
     * @function enableWebViewButtons
     * @memberof OAuthPropertiesBuilder.prototype
     * @param {Array.<string>} actionButtonList - List of buttons to be enabled in web view. Defaults to ['ALL'].
     * @return {FedAuthPropertiesBuilder}
     */
    this.enableWebViewButtons = function(actionButtonList)
    {
      assertButtonsArray(actionButtonList, authPropertyKeys.EnableWebViewButtons);
      this.put(authPropertyKeys.EnableWebViewButtons, actionButtonList);
      return this;
    };

    if (grantType)
      this.oAuthAuthorizationGrantType(grantType);
    if (tokenEndpoint)
      this.oAuthTokenEndpoint(tokenEndpoint);
    if (clientId)
      this.oAuthClientID(clientId);
  };

  OAuthPropertiesBuilder.prototype = Object.create(RemoteAuthPropertiesBuilder.prototype, {
    /**
     * @function build
     * @memberof OAuthPropertiesBuilder.prototype
     * @return {Object} validate and return properties collected.
     */
    build: {
      value: function() {
        if (!this.props[authPropertyKeys.OAuthAuthorizationGrantType])
          throw new Error('Mandatory parameter oAuthAuthorizationGrantType not set.');
        if (!this.props[authPropertyKeys.OAuthTokenEndpoint] && Object.getPrototypeOf(this) === OAuthPropertiesBuilder.prototype)
          throw new Error('Mandatory parameter oAuthTokenEndpoint not set.');
        if (!this.props[authPropertyKeys.OAuthClientID])
          throw new Error('Mandatory parameter oAuthClientID not set.');
        return Object.getPrototypeOf(OAuthPropertiesBuilder.prototype).build.call(this);
      }
    }
  });
  OAuthPropertiesBuilder.prototype.constructor = OAuthPropertiesBuilder;
  /**
   * Enum values for {@link OAuthPropertiesBuilder#browserMode}
   * @memberof OAuthPropertiesBuilder
   * @enum
   * @readonly
   */
  OAuthPropertiesBuilder.BrowserMode = {
   /**
    * Browser mode is external. An external browser will be opened.
    * @type {string}
    */
   External: 'External',
   /**
    * Browser mode is embedded. An embedded browser will be opened within the app.
    * @type {string}
    */
   Embedded: 'Embedded'
  };

  /**
   * Enum values for {@link OAuthPropertiesBuilder#oAuthAuthorizationGrantType}
   * @memberof OAuthPropertiesBuilder
   * @enum
   * @readonly
   */
  OAuthPropertiesBuilder.OAuthAuthorizationGrantType = {
    /**
     * OAuth grant type is implicit
     * @type {string}
     */
    OAuthImplicit:'OAuthImplicit',
    /**
     * OAuth grant type is authorization code
     * @type {string}
     */
    OAuthAuthorizationCode:'OAuthAuthorizationCode',
    /**
     * OAuth grant type is resource owner
     * @type {string}
     */
    OAuthResourceOwner:'OAuthResourceOwner',
    /**
     * OAuth grant type is client credentials
     * @type {string}
     */
    OAuthClientCredentials:'OAuthClientCredentials'
  };
  /**
   * @class OpenIDConnectPropertiesBuilder
   * @classdesc This is the builer for OpenIDConnect. Specifics of this type of authentication is similar to
   * {@link OAuthPropertiesBuilder|OAuth}.
   * @extends OAuthPropertiesBuilder
   * @param {string} appName - Application name
   * @param {OAuthPropertiesBuilder.OAuthAuthorizationGrantType} oAuthAuthorizationGrantType - OAuth grant type to be used.
   * @param {string} discoveryEndpoint - OpenId discovery end point.
   * @param {string} clientId - client id.
   */
  var OpenIDConnectPropertiesBuilder = function(appName, oAuthAuthorizationGrantType, discoveryEndpoint, clientId) {
    OAuthPropertiesBuilder.call(this, appName, oAuthAuthorizationGrantType, undefined, clientId);
    this.put(authPropertyKeys.AuthServerType, authServerTypes.OpenIDConnect);

    /**
     * @function discoveryEndpoint
     * @memberof OpenIDConnectPropertiesBuilder.prototype
     * @param {string} url - OAuth token end point.
     * @return {OpenIDConnectPropertiesBuilder}
     */
    this.discoveryEndpoint = function(url)
    {
      assertUrl(url, authPropertyKeys.OpenIDConnectDiscoveryURL);
      this.put(authPropertyKeys.OpenIDConnectDiscoveryURL, url);
      return this;
    };

    if (discoveryEndpoint)
      this.discoveryEndpoint(discoveryEndpoint);

  };

  OpenIDConnectPropertiesBuilder.prototype = Object.create(OAuthPropertiesBuilder.prototype, {
    /**
     * @function build
     * @memberof OpenIDConnectPropertiesBuilder.prototype
     * @return {Object} validate and return properties collected.
     */
    build: {
      value: function() {
        if (!this.props[authPropertyKeys.OpenIDConnectDiscoveryURL])
          throw new Error('Mandatory parameter discoveryEndpoint not set.');
        return Object.getPrototypeOf(OpenIDConnectPropertiesBuilder.prototype).build.call(this);
      }
    }
  });
  OpenIDConnectPropertiesBuilder.prototype.constructor = OpenIDConnectPropertiesBuilder;


  /**
   * @class LocalAuthPropertiesBuilder
   * @classdesc This is the builder for Local auth. This can be used for for device level authentication.
   * Using this builder to {@link init} an authentication flow will return {@link LocalAuthenticationFlow} in the init promise.
   * Multiple types of {@link LocalAuthPropertiesBuilder.LocalAuthenticatorType|local authentications} are supported.
   * <p>For biometric based local auth, biometric is collected by the device using native UI. This UI is provided by each device OS.
   * Device OS allows certain customizations to this UI, such as labels and titles.
   * App can optionally set
   * {@link LocalAuthPropertiesBuilder~Translations| localized strings for biometric prompt}
   * using {@link LocalAuthPropertiesBuilder#translations} method. If these strings are not provided,
   * default, english strings will be shown to the user.
   * In addition, app can control the look and feel of the biometric dialog by providing appropriate theme for the MainActivity in AndroidManifest.xml.
   * </p>
   * <p>For PIN based local authentication, the UI for collecting PIN from the user should be provided by the app.
   * App provides this through {@link LocalAuthPropertiesBuilder#pinChallengeCallback}.
   * The callback implementation details are explained in {@link LocalAuthPropertiesBuilder~localAuthPinChallengeCallback| pin challenge callback} documentation.
   * </p>
   * @extends PropertiesBuilder
   * @param {String} id - Unique id for the local authentication flow.
   * @param {LocalAuthPropertiesBuilder~localAuthPinChallengeCallback} pinChallengeCallback - Callback for handling PIN challenges.
   */
  var LocalAuthPropertiesBuilder = function(id, pinChallengeCallback){
    PropertiesBuilder.call(this);
    this.put(authPropertyKeys.AuthServerType, authServerTypes.LocalAuthenticator);
    this.put(authPropertyKeys.MaxLoginAttempts, 1);

    /**
     * Local authentication challenge handler
     * @typedef {Object} LocalAuthPropertiesBuilder~LocalAuthPinChallengeHandler
     * @property {LocalAuthPropertiesBuilder~localAuthCompletionCallback} submit - App invokes this passing pin collector to proceed with the current challenge.
     * @property {RemoteAuthPropertiesBuilder~challengeCancelCallback} cancel - App invokes this to cancel the current challenge.
     */

    /**
     * Local authentication completion callback. Used to complete a PIN challenge by submitting the PIN collected from the user.
     * @callback LocalAuthPropertiesBuilder~localAuthCompletionCallback
     * @param {number=} currentPin - Existing PIN collected from user. To be passed when
     *                  {@link LocalAuthPropertiesBuilder.PinChallengeReason|LocalAuthPropertiesBuilder.PinChallengeReason.Login} is requested.
     *                  Since {@link LocalAuthenticationFlowManager#changePin|changePin} now does a login upfront,
     *                  there is no need to pass this parameter for
     *                  {@link LocalAuthPropertiesBuilder.PinChallengeReason|LocalAuthPropertiesBuilder.PinChallengeReason.ChangePin} requests.
     * @param {number=} newPin - New PIN to be set, collected from user. To be passed when
     *                  {@link LocalAuthPropertiesBuilder.PinChallengeReason|LocalAuthPropertiesBuilder.PinChallengeReason.SetPin}
     *                  or {@link LocalAuthPropertiesBuilder.PinChallengeReason|LocalAuthPropertiesBuilder.PinChallengeReason.ChangePin} is requested.
     */

    /**
     * Local authentication PIN challenge callback
     * This callback is invoked when there is a requirement to collect PIN from the user.
     * App should show a UI for collecting PIN from the user.
     * Depending on the {@link LocalAuthPropertiesBuilder.PinChallengeReason|challenge reason} passed to this callback,
     * app should collect existing PIN and / or new PIN from the user.
     * App should then use the {@link LocalAuthPropertiesBuilder~localAuthCompletionCallback|completion callback} to submit the PIN.
     * If user wishes to cancel the login attempt, app should invoke {@link RemoteAuthPropertiesBuilder~challengeCancelCallback|cancel callback}.
     * Both callbacks are provided as part of {@link LocalAuthPropertiesBuilder~LocalAuthPinChallengeHandler|challenge handler} passed to this callback.
     *
     * @callback LocalAuthPropertiesBuilder~localAuthPinChallengeCallback
     * @param {LocalAuthPropertiesBuilder.PinChallengeReason} challengeReason
     * @param {LocalAuthPropertiesBuilder~LocalAuthPinChallengeHandler} challengeHandler - To be used by the app to either submit or cancel the current challenge.
     * @param {Error=} error - Error (if any) with the previous attempt to login using PIN and maxLoginAttemptsForPIN has not reached.
     * @param {LocalAuthPropertiesBuilder~PinChallengeOptions=} options - Object containing additional information (if any) passed to the PIN challenge callback.
     */

    /**
     * @typedef {Object} LocalAuthPropertiesBuilder~PinChallengeOptions
     * @property {number} loginAttemptCount - Current login attempt. When maxLoginAttemptsForPIN is set, this will track the current retry attempt.
     */

    /**
     * Localized strings for biometric authentication dialog prompt.
     * @typedef {Object} LocalAuthPropertiesBuilder~Translations
     * @property {String=} promptMessage - Text to be shown to the user on the dialog.
     * @property {String=} pinFallbackButtonLabel - Label for the PIN fallback button in the dialog.
     * @property {String=} cancelButtonLabel - Label for the cancel button in the dialog.
     * @property {String=} successMessage - Text to be shown when biometric authentication is successful. Applicable to Android only.
     * @property {String=} errorMessage - Text to be shown when biometric authentication is unsuccessful. Applicable to Android only.
     * @property {String=} promptTitle - Title for the dialog. Applicable to Android only.
     * @property {String=} hintText - Hint text to be shown to the user. Applicable to Android only.
     */

    /**
     * @function id
     * @param {string} id - Unique id for the local authentication flow.
     * @memberof LocalAuthPropertiesBuilder.prototype
     * @return {LocalAuthPropertiesBuilder}
     */
    this.id = function (id) {
      assertString(id, authPropertyKeys.LocalAuthFlowId);
      this.put(authPropertyKeys.LocalAuthFlowId, id);
      return this;
    };
    /**
     * @function pinChallengeCallback
     * @param {LocalAuthPropertiesBuilder~localAuthPinChallengeCallback} pinCallback - Callback for handling PIN challenges.
     * @memberof LocalAuthPropertiesBuilder.prototype
     * @return {LocalAuthPropertiesBuilder}
     */
    this.pinChallengeCallback = function(pinCallback) {
      assertFunction(pinCallback, authPropertyKeys.PinChallengeCallback);
      this.put(authPropertyKeys.PinChallengeCallback, pinCallback);
      return this;
    };

    /**
     * @function translations
     * @param {LocalAuthPropertiesBuilder~Translations} translations
     * @param {boolean} override - Whether to override the existing translations or not. Defaults to true.
     * @memberof LocalAuthPropertiesBuilder.prototype
     * @return {LocalAuthPropertiesBuilder}
     */
    this.translations = function(translations, override) {
      if (typeof override === "undefined" || override === null)
        override = true;

      assertObject(translations, authPropertyKeys.Translations);
      var target, existing = this.props[authPropertyKeys.Translations];

      if (!existing) {
       target = translations;
      } else {
        target = {};
        var firstPreference, secondPreference;

        if (override) {
          firstPreference = translations;
          secondPreference = existing;
        } else {
          firstPreference = existing;
          secondPreference = translations;
        }

        for (var key in secondPreference)
          target[key] = secondPreference[key];
        for (var key in firstPreference)
          target[key] = firstPreference[key];
      }

      this.put(authPropertyKeys.Translations, target);
      return this;
    };

    /**
     * This property comes into play whenever user is challenged to login using PIN.
     * Typically this happens with {@link LocalAuthenticationFlow#login} is invoked.
     * This also happens when {@link LocalAuthenticationFlowManager#disable} or {@link LocalAuthenticationFlowManager#changePin}
     * is called, because as a first step for those actions, user has to login using PIN.
     * When this property is set to a number greater than 1, user has those many attempts to login, if a wrong PIN was provided.
     * Once max attempts are reached, the respective action's promise will be rejected.
     * @function maxLoginAttemptsForPIN
     * @memberof LocalAuthPropertiesBuilder.prototype
     * @param {number} attempts - maximum login attempts, should be greater than zero. Defaults to 1.
     * @return {LocalAuthPropertiesBuilder}
     */
    this.maxLoginAttemptsForPIN = function(maxAttempts) {
      assertPositive(maxAttempts, authPropertyKeys.MaxLoginAttempts);
      this.put(authPropertyKeys.MaxLoginAttempts, maxAttempts);
      return this;
    }

    if (id)
      this.id(id);
    if (pinChallengeCallback)
      this.pinChallengeCallback(pinChallengeCallback);
  };

  LocalAuthPropertiesBuilder.prototype = Object.create(PropertiesBuilder.prototype, {
    /**
     * @function build
     * @memberof LocalAuthPropertiesBuilder.prototype
     * @return {Object} validate and return properties collected.
     */
    build: {
      value: function() {
        if (!this.props[authPropertyKeys.LocalAuthFlowId])
          throw new Error('Mandatory parameter id not set.');
        if (!this.props[authPropertyKeys.PinChallengeCallback])
          throw new Error('Mandatory parameter pinChallengeCallback not set.');
        return Object.getPrototypeOf(LocalAuthPropertiesBuilder.prototype).build.call(this);
      }
    }
  });
  LocalAuthPropertiesBuilder.prototype.constructor = LocalAuthPropertiesBuilder;

  /**
   * Enum values for challenge reason in {@link LocalAuthPropertiesBuilder~localAuthPinChallengeCallback|pin challenge callback}.
   * @enum
   * @readonly
   * @memberof LocalAuthPropertiesBuilder
   */
  LocalAuthPropertiesBuilder.PinChallengeReason = {
    /**
     * Reason for pin challenge is to login.
     * In this case current pin has to be collected from the user and passed to {@link LocalAuthPropertiesBuilder~localAuthCompletionCallback|completion callback}
     * @type {string}
     */
    Login: 'Login',
    /**
     * Reason for pin challenge is to set a new pin.
     * In this case a new pin has to be collected from the user and passed to {@link LocalAuthPropertiesBuilder~localAuthCompletionCallback|completion callback}
     * @type {string}
     */
    SetPin: 'SetPin',
    /**
     * Reason for pin challenge is to change existing pin.
     * In this case both current and new pin has to be collected from the user and passed to {@link LocalAuthPropertiesBuilder~localAuthCompletionCallback|completion callback}
     * @type {string}
     */
    ChangePin: 'ChangePin'
  };
  /**
   * Enum values for types of local authenticators supported. Used in {@link LocalAuthenticationFlow} and {@link LocalAuthenticationFlowManager}
   * @enum
   * @readonly
   * @memberof LocalAuthPropertiesBuilder
   */
  LocalAuthPropertiesBuilder.LocalAuthenticatorType = {
    /**
     * Local authentication type is PIN.
     * @type {string}
     */
    PIN: 'cordova.plugins.IdmAuthFlows.PIN',
    /**
     * Local authentication type is Fingerprint.
     * @type {string}
     */
    Fingerprint: 'cordova.plugins.IdmAuthFlows.Fingerprint',
    /**
     * Local authentication type can be any Biometric.
     * Currently supports:
     * FaceID OR TouchID in iOS
     * Fingerprint in Android
     * @type {string}
     */
    Biometric: 'cordova.plugins.IdmAuthFlows.Biometric'
  };
  // End: Builders


  // AuthenticationFlows
  /**
   * @class AuthenticationFlow
   * @classdesc This is the base class for authentication flow object that represents a single authentication.
   * This class implements basic functionality for any authentication flow such as login, logout, isAuthenticated.
   * This class should not instantiated directly.
   * Instance of its sub class can be obtained when the promise returned from {@link init} resolves.
   * @abstract
   * @hideconstructor
   * @param {string} authFlowKey - Unique key for identifying an auth flow.
   * @param {Object} authProps - properties object obtained from {@link Builder#build}
   * @see RemoteAuthenticationFlow
   * @see LocalAuthenticationFlow
   */
  var AuthenticationFlow = function(authFlowKey, authProps)
  {
    var self = this;
    // Insist for an authFlowKey to create AuthenticationFlow object.
    if (!authFlowKey)
    {
      throw new Error('Invalid flow key passed while creating AuthenticationFlow.');
    }

    /**
     * Option object to be used with {@link AuthenticationFlow#isAuthenticated}
     * @typedef {Object} AuthenticationFlow~IsAuthenticatedOptions
     * @property {Array.<String>} OAuthScope - OAuth scopes for which isAuthenticated should be checked. Applicable only for OAuth. Default is empty array.
     * @property {boolean} refreshExpiredTokens - Whether to refresh token or not. Applicable only for for OAuth. Defaults to true.
     */
    /**
     * @abstract
     * @function login
     * @memberof AuthenticationFlow.prototype
     * @return {Promise.<AuthenticationFlow>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.login = function() {};

    /**
     * @abstract
     * @function isAuthenticated
     * @param {AuthenticationFlow~IsAuthenticatedOptions} options - options to be used
     * @memberof AuthenticationFlow.prototype
     * @return {Promise.<boolean>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.isAuthenticated = function(options) {};

    /**
     * @abstract
     * @function logout
     * @memberof AuthenticationFlow.prototype
     * @param {boolean} purgeSettings - pass true to reset all saved information for this auth.
     * @return {Promise.<AuthenticationFlow>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.logout = function(purgeSettings) {};
  };


  /**
   * @class RemoteAuthenticationFlow
   * @classdesc Remote authentication flow object.
   * This class is not directly instantiated.
   * Instance of this class can be obtained when the promise returned from {@link init} resolves.
   * Auth properties passed to {@link init} should be from one of:
   * <ul style="list-style: none;">
   * <li>{@link FedAuthPropertiesBuilder}</li>
   * <li>{@link OAuthPropertiesBuilder}</li>
   * <li>{@link OpenIDConnectPropertiesBuilder}</li>
   * </ul>
   * Setting up and using these authentication flows are explained in the respective builder documentations.
   * @hideconstructor
   * @extends AuthenticationFlow
   * @param {string} authFlowKey - Unique key for identifying an auth flow.
   * @param {Object} authProps - properties object obtained from {@link Builder#build}
   * @see HttpBasicAuthenticationFlow
   */
  var RemoteAuthenticationFlow = function(authFlowKey, authProps) {
    AuthenticationFlow.call(this, authFlowKey, authProps);
    var self = this;

    /**
     * This method is used to login. <p>The promise is resolved when login succeeds. Once login is successful,
     * if this authentication is for accessing the app, user can be allowed to do so.
     * If it is to access data secured resources this operation can now be performed.
     * It may also be required to obtain certain headers for accessing the secured resource.
     * In this case {@link RemoteAuthenticationFlow#getHeaders} can be used.</p>
     * <p>The promise gets rejected with an {@link AuthError} object which contains information on the reason of failure.
     * This information can be used to shown the reason why login did not succeed.
     * App can keep track of these failures and implement specific policies related to maximum attempts and steps to do after multiple failures here.</p>
     * <p>Sample usage:</p><pre>
     * cordova.plugins.IdmAuthFlows.init(authProps).then(
     *   function(authenticationFlow) {
     *     var loginPromise = authenticationFlow.login();
     *     loginPromise.then(...);
     *     loginPromise.catch(...);
     *   }
     * );</pre>
     * @function login
     * @memberof RemoteAuthenticationFlow.prototype
     * @return {Promise.<AuthenticationFlow>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.login = function() {
      // Backwards compatibility
      if (typeof arguments[0] === "function") {
        console.warn("Parameter challengeCallback in AuthenticationFlow.login is deprecated. Use builder.challengeCallback().");
      }

      var challengeCallback = arguments[0];
      if (typeof authProps[authPropertyKeys.ChallengeCallback] === "function")
        challengeCallback = authProps[authPropertyKeys.ChallengeCallback];
      // End: Backwards compatibility

      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          var isAuth = resp[IsAuthenticatedKey];

          if (isAuth)
          {
            resolve(self);
          }
          else
          {
            var onSuccess = function me(resp) {
              if (resp.challengeFields && typeof challengeCallback === 'function')
              {
                var executed = false;
                var callback = function(challengeFields) {
                  if (!executed) {
                    executed = true;
                    exec(me, reject, TAG, 'finishLogin', [authFlowKey, challengeFields]);
                  }
                };
                callback.submit = function(fields) {
                  callback(fields);
                };
                callback.cancel = function() {
                  exec(function() {
                    reject(getError(errorCodes.UserCancelledAuthentication));
                  }, reject, TAG, 'cancelLogin', [authFlowKey]);
                };
                challengeCallback(resp.challengeFields, callback);
              }
              else
              {
                resolve(self);
              }
            };
            exec(onSuccess, reject, TAG, 'startLogin', [authFlowKey]);
          }
        }, reject, TAG, 'isAuthenticated', [authFlowKey]);
      });
    };

    /**
     * This method is used to find out if the user is authenticated.
     * @function isAuthenticated
     * @param {AuthenticationFlow~IsAuthenticatedOptions} options - options to be used
     * @memberof RemoteAuthenticationFlow.prototype
     * @return {Promise.<boolean>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.isAuthenticated = function(options) {
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          resolve(resp[IsAuthenticatedKey]);
        }, reject, TAG, 'isAuthenticated', [authFlowKey, options]);
      });
    };

    /**
     * This method is used to logout.
     * <p>Once the promise is resolved, the user can be shown the login page to re-login or a way to attempt for the same.
     * {@link AuthenticationFlow#login} can be invoked on the same {@link AuthenticationFlow} object.
     * There is no need to create a new one, unless there is some change in the authentication properties such as server details.</p>
     * <p>User is essentially logged out even if logout promise is rejected.
     * App can decide not to show the logout error to the end user as there is no action associated with it.
     * There is one special case when device is offline. In this case, logout will throw an error because logout URL loading will fail.
     * But device local logout will be successful. Application should handle this error, check for the device status (offline / online)
     * and then decide to show the error message to the user.</p>
     * The following table describes what is cleared on logout with different values for purgeSettings:
     *
     * |     purgeSettings       |  false                       | true                |
     * | :---------------------- | :-------------------------   | :------------------ |
     * | HttpBasicAuthentication | Clear remembered credentials | Clears offline, remembered credentials, user preferences |
     * | FederatedAuthentication | Clear Cookies by loading logout URL | |
     * | OAuth, OpenID           | Clear access token           | Invalidate session maintained by the browser by loading logout URL. |
     *
     * @function logout
     * @memberof RemoteAuthenticationFlow.prototype
     * @param {boolean} purgeSettings - pass true to reset all saved information for this auth. Falls back to 'false' if non boolean is passed.
     * @return {Promise.<AuthenticationFlow>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.logout = function(purgeSettings) {
      if (purgeSettings !== true && purgeSettings !== false)
        purgeSettings = false;
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          resolve(self);
        }, reject, TAG, 'logout', [authFlowKey, purgeSettings]);
      });
    };

    /**
     * Option object to be used with {@link RemoteAuthenticationFlow#getHeaders}
     * @typedef {Object} RemoteAuthenticationFlow~GetHeadersOptions
     * @property {String} fedAuthSecuredUrl - URL for which cookies and headers need to retrieved. Applicable only for for FedAuth.
     * @property {Array.<String>} oauthScopes - Scopes for which header is requested.
     * Need to be set for OAuth cases where fine grained control on the token is needed.
     * If not specified, the first OAuth token available will be returned. Applicable only for for OAuth
     */
    /**
     * This method is used to get Authorization headers and any custom headers to be set for making XHR requests to secured end points.
     * Headers are returned as an object in a format that can be directly added to the XHR request headers.
     * <pre>
     * authFlow.getHeaders().then(function(headers){
     *   var request; // Represents an XHR request
     *   ...
     *   for (var key in headers) {
     *     if (headers.hasOwnProperty(key)) {
     *       request.setRequestHeader(key, headers[key]);
     *     }
     *   }
     *   ...
     * }
     * </pre>
     * @function getHeaders
     * @memberof RemoteAuthenticationFlow.prototype
     * @param {RemoteAuthenticationFlow~GetHeadersOptions} options - options to be used
     * @return {Promise.<Object.<string, string>>} - headers needed to be used for accessing secured resource.
     *
     * |     Type of Auth        |  What headers are returned | Comments |
     * | :---------------------- | :------------------------- | :------- |
     * | HttpBasicAuthentication | Basic auth header | Generated from stored credentials. {@link HttpBasicAuthPropertiesBuilder#offlineAuthAllowed} should be true for SDK to store the credentials. |
     * | FederatedAuthentication | Relevant cookies as header | options.fedAuthSecuredUrl has to be set |
     * | FederatedAuthentication with {@link FedAuthPropertiesBuilder#parseTokenRelayResponse} turned ON | Bearer token | Can specify options.oauthScopes to get token for scope or a set of scopes. |
     * | OAuth, OpenID           | Bearer token | Can specify options.oauthScopes to get token for scope or a set of scopes. |
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.getHeaders = function(options) {
      // Backwards compatibility
      var opt = {};
      if (arguments[0] !== null && typeof arguments[0] === "object") {
        opt.fedAuthSecuredUrl = arguments[0].fedAuthSecuredUrl;
        opt.oauthScopes = arguments[0].oauthScopes;
      } else {
        if (typeof arguments[0] === "string") {
          console.warn("Parameter fedAuthSecuredUrl in AuthenticationFlow.getHeaders is deprecated.  Use options.fedAuthSecuredUrl.");
          opt.fedAuthSecuredUrl = arguments[0];
        }
        if (typeof arguments[1] === "object") {
          console.warn("Parameter oauthScopes in AuthenticationFlow.getHeaders is deprecated. Use options.oauthScopes.");
          opt.oauthScopes = arguments[1];
        }
      }
      // End: Backwards compatibility

      var NON_ENUMERABLE_KEYS = ['ExpiryTime']; // ToDo: Pass this as a variable to backend

      var getHeadersPromise = new Promise(function (resolve, reject) {
        exec(resolve, reject, TAG, 'getHeaders', [authFlowKey, opt.fedAuthSecuredUrl, opt.oauthScopes]);
      });

      return getHeadersPromise.then(function(response) {
        return changeEnumberability(response, NON_ENUMERABLE_KEYS);
      });
    };
  };

  RemoteAuthenticationFlow.prototype.constructor = RemoteAuthenticationFlow;

  /**
   * @class HttpBasicAuthenticationFlow
   * @classdesc This class represents HTTP Basic authentication flow object.
   * This class is not directly instantiated.
   * Instance of this class can be obtained when the promise returned from {@link init} resolves, when using properties from {@link HttpBasicAuthPropertiesBuilder}.
   * Setting up and using HTTP basic authentication flow is explained in the {@link HttpBasicAuthenticationFlow|builder} documentation.
   * @hideconstructor
   * @extends RemoteAuthenticationFlow
   * @param {string} authFlowKey - Unique key for identifying an auth flow.
   * @param {Object} authProps - properties object obtained from {@link Builder#build}
   */
  var HttpBasicAuthenticationFlow = function(authFlowKey, authProps) {
    RemoteAuthenticationFlow.call(this, authFlowKey, authProps);
    var self = this;
    /**
     * This method resets the idle timeout. This can be used in {@link RemoteAuthPropertiesBuilder~timeoutCallback|timeout callback} to reset timeout when idle timeout occurs.
     * @function resetIdleTimeout
     * @memberof HttpBasicAuthenticationFlow.prototype
     * @return {Promise.<HttpBasicAuthenticationFlow>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.resetIdleTimeout = function() {
      return new Promise(function (resolve, reject) {
        exec(function(resp) {
          resolve(self);
        }, reject, TAG, 'resetIdleTimeout', [authFlowKey]);
      });
    };
  };

  HttpBasicAuthenticationFlow.prototype = Object.create(RemoteAuthenticationFlow.prototype);
  HttpBasicAuthenticationFlow.prototype.constructor = HttpBasicAuthenticationFlow;

  /**
   * @class LocalAuthenticationFlow
   * @classdesc This class represents local authentication flow object which can be used for performing local authentications.
   * This class is not directly instantiated.
   * Instance of this class can be obtained when the promise returned from {@link init} resolves, when using properties from {@link LocalAuthPropertiesBuilder}.
   * Setting up and using a local authentication flow is explained in the {@link LocalAuthPropertiesBuilder|builder} documentation.
   * <p>
   * Multiple {@link LocalAuthPropertiesBuilder.LocalAuthenticatorType|types} of local authentications are supported by this flow.
   * App can provide a configuration area where user can enable / disable the local authentication types that app wants to support.
   * App should use the {@link LocalAuthenticationFlow#getManager|manager} instance for {@link LocalAuthenticationFlowManager#enable|enabling}
   * and {@link LocalAuthenticationFlowManager#disable|disabling} local authentications.
   * While enabling PIN authentication, {@link LocalAuthPropertiesBuilder#pinChallengeCallback|pin challenge callback} will be invoked.
   * Note that Fingerprint or Biometric cannot be enabled unless PIN is already enabled.
   * Also, PIN cannot be disabled when Fingerprint or Biometric is enabled.
   * App UI can take care of this in the UI by manipulating the UI controls.
   * For PIN based authentication, app can provide an option for the user to change pin.
   * App should invoke {@link LocalAuthenticationFlow#getManager|manager} instance's
   * {@link LocalAuthenticationFlowManager#changePin|changePin} method for doing this.
   * {@link LocalAuthPropertiesBuilder#pinChallengeCallback|Pin challenge callback} will be invoked at this time.</p>
   * <p>For a given {@link LocalAuthenticationFlow} there is always a primary authentication, the one that was enabled by the user last.
   * So, if user enabled PIN, then that is the primary authentication.
   * If user enabled Fingerprint or Biometric, then that is the primary authentication. Even though PIN is still active, it becomes secondary authentication.
   * Local authentication can be triggered by invoking {@link LocalAuthenticationFlow#login}. This will trigger the primary authentication.
   * When PIN authentication is triggered, {@link LocalAuthPropertiesBuilder#pinChallengeCallback|pin challenge callback} will be invoked.
   * When Fingerprint or Biometric authentication is triggered, then the device prompts the user to provide the relevant biometric.
   * User will have an option to fallback on the secondary authentication, which is PIN, as per the device's policies.
   * This is a standard mechanism provided by devices to help user to access the app even when user is unable to provide biometric.
   * </p>
   * <p>There is no concept of logging out in case of local auth. So {@link LocalAuthenticationFlow#logout} is a noop.</p>
   * <p>Often local authentication is used in conjunction with a remote authentication. The objective is to have
   * user log in once and not to prompt user for credentials, until needed due to session expiry or server policy.
   * In this usecase, user logs in for the first time with the credentials and configures / authorizes
   * app to use fingerprint or biometric login. This has to be implemented by the app as a setting or on the login screen.
   * Once fingerprint or biometric authentication is allowed / enabled by the user, app should seek fingerprint or biometric whenever user login is needed.
   * App should perform remote login transparently in the background. This can be achieved by chaining local
   * authentication with remote authentication.
   * </p>
   * <p> More specifically, to implement this use case, app has to trigger login on {@link LocalAuthenticationFlow}
   * first and after that is successful, trigger login on {@link RemoteAuthenticationFlow}. If the {@link RemoteAuthenticationFlow}
   * is able to do login transparently, without user credentials, we have the desired outcome.
   * For this, {@link RemoteAuthenticationFlow} should support
   * {@link HttpBasicAuthPropertiesBuilder#autoLoginAllowed|auto login} as {@link HttpBasicAuthPropertiesBuilder} does
   * or support refresh tokens as {@link OAuthPropertiesBuilder} or {@link OpenIDConnectPropertiesBuilder} does.
   * </p>
   * <p> Another common use case with local authentication is to prompt user to provide fingerprint or biometric when app
   * is relaunched or comes to foreground from background. This can be done by invoking {@link LocalAuthenticationFlow#login}
   * in the resume listener / on startup as appropriate.
   * {@link LocalAuthenticationFlow#login} can be invoked any time after {@link LocalAuthenticationFlow} is initialized
   * and any number of times as needed. Each time user will be challenged.
   * </p>
   * @hideconstructor
   * @extends AuthenticationFlow
   * @param {Object} authProps - properties object obtained from {@link Builder#build}
   */
  var LocalAuthenticationFlow = function(authProps) {
    var id = authProps[authPropertyKeys.LocalAuthFlowId];
    AuthenticationFlow.call(this, id, authProps);
    var maxAttempts = authProps[authPropertyKeys.MaxLoginAttempts];
    var currentAttempt;
    var pinCallback = authProps[authPropertyKeys.PinChallengeCallback];
    var lastAuthenticated;
    var self = this;

    var loginUsingPin = function(resolve, reject, primaryAuth, err) {
      var options = {};
      options.loginAttemptCount = currentAttempt;
      pinCallback(LocalAuthPropertiesBuilder.PinChallengeReason.Login, {
        cancel: function() {
          reject(getError(errorCodes.UserCancelledAuthentication));
        },
        submit: function(currentPin, newPin) {
          exec(function() {
            lastAuthenticated = primaryAuth;
            resolve({flow: self, loginPin: currentPin});
          }, function(err) {
            if (currentAttempt >= maxAttempts)
              reject(err);
            else {
              currentAttempt++;
              loginUsingPin(resolve, reject, primaryAuth, err);
            }
          }, TAG, 'authenticatePin', [id, currentPin]);
        }
      }, err, options);
    };

    var loginUsingPinWithRetry = function(primaryAuth) {
      currentAttempt = 1;
      return new Promise(function(resolve, reject) {
        loginUsingPin(resolve, reject, primaryAuth);
      });
    };

    var manager = new LocalAuthenticationFlowManager(authProps, loginUsingPinWithRetry);

    /**
     * Returns the local auth manager associated with this flow.
     * @function getManager
     * @memberof LocalAuthenticationFlow.prototype
     * @return {LocalAuthenticationFlowManager}
     */
    this.getManager = function() {
      return manager;
    };

    /**
     * This method is used to login. <p>The promise is resolved when login succeeds. The user can be redirected to the app once this happens.</p>
     * <p>The promise gets rejected with an {@link AuthError} object which contains information on the reason of failure.
     * This information can be used to shown the reason why login did not succeed.
     * App keep track of these failures and implement specific policies related to maximum attempts and steps to do after multiple failures here.</p>
     * <p>Sample usage:</p><pre>
     * cordova.plugins.IdmAuthFlows.init(authProps).then(
     *   function(authenticationFlow) {
     *     var loginPromise = authenticationFlow.login();
     *     loginPromise.then(...);
     *     loginPromise.catch(...);
     *   }
     * );
     * </pre>
     * <p>In case of PIN authentication,
     * {@link LocalAuthPropertiesBuilder~localAuthPinChallengeCallback | PIN challenge callback} will be invoked.
     * App should show UI for collecting PIN from the user and pass it back to the plugin via callback as explained in {@link LocalAuthPropertiesBuilder} documentation.
     * </p>
     * <p>In case of fingerprint or biometric based local authentication, the device native UI for collecting biometric will be provided to the user.
     * This UI can be customized by the app as explained in {@link LocalAuthPropertiesBuilder} documentation.
     * User will have a way to fall back on to PIN based authentication as per device policies. In this case the PIN authentication flow will kick in.
     * </p>
     * @function login
     * @memberof LocalAuthenticationFlow.prototype
     * @return {Promise.<AuthenticationFlow>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.login = function() {
      return new Promise(function(resolve, reject) {
        manager.getEnabled().then(function(enabled) {
          if (enabled.length === 0 || enabled[0] === undefined) {
            reject(getError(errorCodes.NoLocalAuthEnabled));
            return;
          }

          var primaryAuth = enabled[0];

          if (!isTypeOf(LocalAuthPropertiesBuilder.LocalAuthenticatorType, primaryAuth)) {
            // This should not happen.
            reject(getError(errorCodes.UnknownLocalAuthenticatorType));
            return;
          }

          if (primaryAuth === LocalAuthPropertiesBuilder.LocalAuthenticatorType.PIN) {
            loginUsingPinWithRetry(primaryAuth)
              .then(function(result) {
                resolve(result.flow);
              })
              .catch(function(err) {
                reject(err);
              });
          } else if (primaryAuth === LocalAuthPropertiesBuilder.LocalAuthenticatorType.Biometric ||
                      primaryAuth === LocalAuthPropertiesBuilder.LocalAuthenticatorType.Fingerprint) {
            exec(function(resp){
              if (resp === "fallback") {
                loginUsingPinWithRetry(primaryAuth)
                  .then(function(result) {
                    resolve(result.flow);
                  })
                  .catch(function(err) {
                    reject(err);
                  });
              } else {
                lastAuthenticated = primaryAuth;
                resolve(self);
              }
            }, reject, TAG, 'authenticateBiometric', [id, primaryAuth, authProps[authPropertyKeys.Translations]]);
          }
        }).catch(function(err) {
          reject(getError(errorCodes.GetEnabledAuthsError));
        });
      });
    };

    /**
     * Logout is a noop for local authentication. The promise returned resolves immediately.
     * @function logout
     * @memberof LocalAuthenticationFlow.prototype
     * @param {boolean} purgeSettings - pass true to reset saved information for this auth. Not applicable in this case.
     * @return {Promise.<AuthenticationFlow>}
     */
    this.logout = function(purgeSettings) {
      Promise.resolve(self);
    };

    /**
     * This method is used for checking if the user is authenticated or not.
     * @function isAuthenticated
     * @memberof LocalAuthenticationFlow.prototype
     * @return {Promise.<boolean>}
     */
    this.isAuthenticated = function(options) {
      // Since there is no concept of logout with local auth,
      // once user logged in, is always logged in.
      if (lastAuthenticated)
        return Promise.resolve(true);

      // If there is no lastAuthenticated,
      // we need to check if there are any authenticators enabled.
      return new Promise(function(resolve, reject) {
        manager.getEnabled().then(function(enabled) {
          resolve(enabled.length == 0);
        }).catch(function(err) {
          reject(getError(errorCodes.GetEnabledAuthsError));
        });
      });
    };
  };

  LocalAuthenticationFlow.prototype = Object.create(AuthenticationFlow.prototype);
  LocalAuthenticationFlow.prototype.constructor = LocalAuthenticationFlow;

  /**
   * @classdesc This class represents local authentication manager object which can be
   * used for managing local authentication. This class is not directly instantiated.
   * Instance of this class is returned from {@link LocalAuthenticationFlow#getManager}
   * General usage of this class is explained in {@link LocalAuthenticationFlow} documentation.
   * @class LocalAuthenticationFlowManager
   * @hideconstructor
   * @param {Object} authProps - properties object obtained from {@link Builder#build}
   * @param {Function} loginUsingPinWithRetry - method that can be used to have user login using PIN.
   */
  var LocalAuthenticationFlowManager = function(authProps, loginUsingPinWithRetry) {
    var id = authProps[authPropertyKeys.LocalAuthFlowId];
    var maxAttempts = authProps[authPropertyKeys.MaxLoginAttempts];
    var pinCallback = authProps[authPropertyKeys.PinChallengeCallback];
    var enablePromise, disablePromise;
    var self = this;

    /**
     * Store given [key,value] into local authenticator's secured keystore. There are two keystores available.
     * First is the default keystore and second one is the local authenticator's keystore.
     * Keys stored in default keystore can be retrieved even before the user is authenticated using local authenticator.
     * This is suitable for storing app level preferences which are needed at app launch time before user login.
     * Local authenticator keystore can be accessed only after successful local authentication.
     * So user has to be logged in before data can be stored in this manner.
     * Needless to say, second one is more secure than first. So apps should not store confidential information using first method.
     *
     * Using same key across default and local authenticator keystores are not allowed.
     * The value last set will be the one that will be stored and the value set into other keystore will be lost.
     * For e.g., if you set ("foo","bar") in default authenticator and then after login, set ("foo","hello"), then when 
     * you try to get back the key "foo" you will get the value as "hello".
     * @function setPreference
     * @memberof LocalAuthenticationFlowManager.prototype
     * @param {String} key - key to store
     * @param {String} value - value to store
     * @param {boolean} secure - false to store in default keystore. Defaults to true.
     * @return {Promise.<LocalAuthPropertiesBuilder.LocalAuthenticatorType>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.setPreference = function(key, value, secure) {
      assertString(key, "key");
      return new Promise(function(resolve, reject) {
        exec(resolve, reject, TAG, 'setPreference', [id, key, value, secure])
      });
    };

    /**
     * Fetches given key's value from local authenticator's keystore.
     * Firstly user authentication is checked. If user is autehnticated using local authenticator, a check is performed
     * on secured keystore. If key is found there its corresponding value is being returned. If key is not found in secured
     * keystore, it fallsback to default keystore and searches the key overthere.
     * If user is not authenticated, key will be searched from default keystore.
     * @function enable
     * @memberof LocalAuthenticationFlowManager.prototype
     * @param {String} key - key to fetch
     * @return {Promise.<LocalAuthPropertiesBuilder.LocalAuthenticatorType>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.getPreference = function(key) {
      assertString(key, "key");
      return new Promise(function(resolve, reject) {
        exec(resolve, reject, TAG, 'getPreference', [id, key])
      });
    };

    /**
     * Get all enabled local authenticator types, in primary first order.
     * This means that if {@link LocalAuthenticationFlow#login} is triggered on the corresponding {@link LocalAuthenticationFlow},
     * it will trigger the first authentication type returned.
     * Note: PIN is always allowed. Fingerprint or Biometric is allowed based on device capabilities.
     * @function getEnabled
     * @memberof LocalAuthenticationFlowManager.prototype
     * @return {Promise.<Array.<LocalAuthPropertiesBuilder.LocalAuthenticatorType>>} Enabled local auths, in primary first order.
     */
    this.getEnabled = function() {
      var promises = [];

      if (enablePromise)
        promises.push(enablePromise);
      if (disablePromise)
        promises.push(disablePromise);

      return Promise.all(promises)
        .then(function() {
          return new Promise(function(resolve, reject) {
            exec(function(enabledAuthsPrimaryFirst){
              resolve(enabledAuthsPrimaryFirst);
            }, reject, TAG, 'enabledLocalAuthsPrimaryFirst', [id]);
          })
        });
    };

    /**
     * Enable authenticator denoted by localAuthenticationType.
     * Note: PIN has to be enabled before fingerprint or biometric is enabled.
     * @function enable
     * @memberof LocalAuthenticationFlowManager.prototype
     * @param {LocalAuthPropertiesBuilder.LocalAuthenticatorType} type - local auth type to be enabled.
     * @return {Promise.<LocalAuthPropertiesBuilder.LocalAuthenticatorType>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.enable = function(localAuthenticationType) {
      if (enablePromise)
        return Promise.reject(getError(errorCodes.OngoingTask));

      enablePromise = new Promise(function(resolve, reject) {
        if (!isTypeOf(LocalAuthPropertiesBuilder.LocalAuthenticatorType, localAuthenticationType)) {
          reject(getError(errorCodes.UnknownLocalAuthenticatorType));
          return;
        }

        self.getEnabled().then(function(enabledAuths) {
          if (enabledAuths.indexOf(localAuthenticationType) != -1) {
            resolve();
            return;
          }

          if (localAuthenticationType === LocalAuthPropertiesBuilder.LocalAuthenticatorType.Biometric ||
                localAuthenticationType === LocalAuthPropertiesBuilder.LocalAuthenticatorType.Fingerprint) {
            if (enabledAuths.indexOf(LocalAuthPropertiesBuilder.LocalAuthenticatorType.PIN) == -1) {
              reject(getError(errorCodes.EnableBiometricWhenPinDisabled));
              return;
            }

            pinCallback(LocalAuthPropertiesBuilder.PinChallengeReason.Login, {
                cancel: function() {
                  reject(getError(errorCodes.UserCancelledAuthentication));
                },
                submit: function(currentPin, newPin) {
                  exec(function() {
                    exec(function() {
                      resolve();
                    }, reject, TAG, 'enableLocalAuth', [id, localAuthenticationType, currentPin]);
                  }, reject, TAG, 'authenticatePin', [id, currentPin]);
                }
              });
          } else if (localAuthenticationType === LocalAuthPropertiesBuilder.LocalAuthenticatorType.PIN) {
            pinCallback(LocalAuthPropertiesBuilder.PinChallengeReason.SetPin, {
              cancel: function() {
                reject(getError(errorCodes.UserCancelledAuthentication));
              },
              submit: function(currentPin, newPin) {
                exec(resolve, reject, TAG, 'enableLocalAuth', [id, localAuthenticationType, newPin]);
              }
            });
          }
        });
      });

      var clearPromise = function() {
        enablePromise = undefined;
      };

      enablePromise.then(clearPromise).catch(clearPromise);

      return enablePromise;
    };

    /**
     * Disable local authenticator denoted by localAuthenticationType.
     * Note: User can disable PIN only after disabling fingerprint or biometric.
     *
     * @function disable
     * @memberof LocalAuthenticationFlowManager.prototype
     * @param {LocalAuthPropertiesBuilder.LocalAuthenticatorType} type - local auth type to be disabled.
     * @return {Promise.<LocalAuthPropertiesBuilder.LocalAuthenticatorType>}
     */
    this.disable = function(localAuthenticationType) {
      if (disablePromise)
        return Promise.reject(getError(errorCodes.OngoingTask));

      disablePromise = new Promise(function(resolve, reject) {
        if (!isTypeOf(LocalAuthPropertiesBuilder.LocalAuthenticatorType, localAuthenticationType)) {
          reject(getError(errorCodes.UnknownLocalAuthenticatorType));
          return;
        }

        self.getEnabled().then(function(enabledAuths) {
          var primaryAuth = enabledAuths[0];
          if (enabledAuths.indexOf(localAuthenticationType) == -1 || primaryAuth === undefined) {
            resolve();
            return;
          }

          if (localAuthenticationType === LocalAuthPropertiesBuilder.LocalAuthenticatorType.PIN &&
              (primaryAuth === LocalAuthPropertiesBuilder.LocalAuthenticatorType.Biometric ||
                primaryAuth === LocalAuthPropertiesBuilder.LocalAuthenticatorType.Fingerprint)) {
            reject(getError(errorCodes.DisablePinWhenBiometricEnabled));
            return;
          }

          loginUsingPinWithRetry(LocalAuthPropertiesBuilder.LocalAuthenticatorType.PIN)
          .then(function() {
            exec(resolve, reject, TAG, 'disableLocalAuth', [id, localAuthenticationType]);
          })
          .catch(function(err) {
            reject(err);
          });
        });
      });

      var clearPromise = function() {
        disablePromise = undefined;
      };

      disablePromise.then(clearPromise).catch(clearPromise);

      return disablePromise;
    };

    /**
     * Change pin for currently enabled local authenticator.
     *
     * @function changePin
     * @memberof LocalAuthenticationFlowManager.prototype
     * @return {Promise.<undefined>}
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    this.changePin = function() {
      var changePinPromise = new Promise(function(resolve, reject) {
        self.getEnabled().then(function(enabledAuths) {
          if (enabledAuths.indexOf(LocalAuthPropertiesBuilder.LocalAuthenticatorType.PIN) == -1) {
            reject(getError(errorCodes.ChangePinWhenPinNotEnabled));
            return;
          }

          loginUsingPinWithRetry(LocalAuthPropertiesBuilder.LocalAuthenticatorType.PIN)
          .then(function(result) {
            pinCallback(LocalAuthPropertiesBuilder.PinChallengeReason.ChangePin, {
              cancel: function() {
                reject(getError(errorCodes.UserCancelledAuthentication));
              },
              submit: function(currentPin, newPin) {
                exec(resolve, reject, TAG, 'changePin', [id, result.loginPin, newPin]);
              }
            });
          }).catch(function(err) {
            reject(err);
          });
        });
      });

      return changePinPromise;
    };
  };

  /**
   * @classdesc This class contains helper methods for local authentication related functionality.
   * @class LocalAuthenticationHelper
   * @hideconstructor
   */
  var LocalAuthenticationHelper =  {
    /**
     * Device level availability states for local authentication.
     * @enum
     * @readonly
     * @memberof LocalAuthenticationHelper
     */
    Availability: {
      /**
       * Local auth type is supported and configured on device.
       * This type of local auth is ready to be enabled.
       * @type {string}
       */
      Enrolled: 'Enrolled',
      /**
       * Local auth type is supported but not configured on device.
       * User should be prompted to enroll the auth type on device and try again.
       * @type {string}
       */
      NotEnrolled: 'NotEnrolled',
      /**
       * Local auth type is supported but is locked out due to many failed attempts.
       * User should be prompted to unlock the auth type and then try again.
       * @type {string}
       */
      LockedOut: 'LockedOut',
      /**
       * Local auth type is not supported by the device.
       * @type {string}
       */
      NotAvailable: 'NotAvailable'
    },

     /**
     * The method returns capabilities supported by device.
     * LocalAuthentications supported by the device can be obtained from this.
     * @function getLocalAuthSupportInfo
     * @memberof LocalAuthenticationHelper
     * @return {Promise.<Object.<LocalAuthPropertiesBuilder.LocalAuthenticatorType, LocalAuthenticationHelper.Availability>>}
     *   Local authentications supported by the device and their availability.
     */
    getLocalAuthSupportInfo: function() {
      return new Promise(function(resolve, reject) {
        exec(function(resp) {
          resolve(resp);
        }, reject, TAG, 'getLocalAuthSupportInfo');
      });
    }
  };

  return {
    /**
     * Deprecated: Use {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode}
     * @enum
     * @readonly
     * @deprecated Use {@link HttpBasicAuthPropertiesBuilder.ConnectivityMode}
     */
    ConnectivityModes: {
      /**
       * Connectivity mode is online
       * @type {string}
       */
      Online:'Online',
      /**
       * Connectivity mode is offline
       * @type {string}
       */
      Offline:'Offline',
      /**
       * Connectivity mode is auto
       * @type {string}
       */
      Auto:'Auto'
    },
    /**
     * Deprecated: Use {@link OAuthPropertiesBuilder.OAuthAuthorizationGrantType}
     * @enum
     * @readonly
     * @deprecated Use {@link OAuthPropertiesBuilder.OAuthAuthorizationGrantType}
     */
    OAuthAuthorizationGrantTypes: {
      /**
       * OAuth grant type is implicit
       * @type {string}
       */
      OAuthImplicit:'OAuthImplicit',
      /**
       * OAuth grant type is authorization code
       * @type {string}
       */
      OAuthAuthorizationCode:'OAuthAuthorizationCode',
      /**
       * OAuth grant type is resource owner
       * @type {string}
       */
      OAuthResourceOwner:'OAuthResourceOwner',
      /**
       * OAuth grant type is client credentials
       * @type {string}
       */
      OAuthClientCredentials:'OAuthClientCredentials'
    },
    /**
     * Deprecated: Use {@link RemoteAuthPropertiesBuilder~AuthChallenge}
     * @enum
     * @readonly
     * @deprecated Use {@link RemoteAuthPropertiesBuilder~AuthChallenge}
     */
    AuthChallenge: {
      /**
       * Saved user name or user input
       * @type {String}
       */
      UserName: 'username_key',
      /**
       * Saved password or user input
       * @type {String}
       */
      Password: 'password_key',
      /**
       * Saved identity domain or user input
       * @type {String=}
       */
      IdentityDomain: 'iddomain_key',
      /**
       * Any error with previous login attempt
       * @type {Error=}
       */
      Error: 'error',
    },
    /**
     * Deprecated: Use {@link RemoteAuthPropertiesBuilder~TimeoutResponse}
     * @enum
     * @readonly
     * @deprecated Use {@link RemoteAuthPropertiesBuilder~TimeoutResponse}
     */
    TimeoutResponse: {
      /**
       * Type of timeout.
       * @type {TimeoutType}
       */
      TimeoutType:'TimeoutType',
      /**
       * Time in seconds after which timeout will happen.
       * @type {String}
       */
      TimeLeftToTimeout:'TimeLeftToTimeout'
    },
    /**
     * Deprecated: Use {@link RemoteAuthPropertiesBuilder.TimeoutType}
     * @enum
     * @readonly
     * @deprecated Use {@link RemoteAuthPropertiesBuilder.TimeoutType}
     */
    TimeoutType: {
      /**
       * Timeout type is session timeout
       * @type {string}
       */
     SessionTimeout:'SESSION_TIMEOUT',
      /**
       * Timeout type is idle timeout
       * @type {string}
       */
     IdleTimeout:'IDLE_TIMEOUT'
    },
    /**
     * Deprecated: Use {@link OAuthPropertiesBuilder.BrowserMode}
     * @enum
     * @readonly
     * @deprecated Use {@link OAuthPropertiesBuilder.BrowserMode}
     */
    BrowserMode: {
      /**
       * Browser mode is external. An external browser will be opened.
       * @type {string}
       */
      External: 'External',
      /**
       * Browser mode is embedded. An embedded browser will be opened within the app.
       * @type {string}
       */
      Embedded: 'Embedded'
    },
    /**
     * @typedef {Object} AuthError - Error object passed to the callback with a Promise is rejected.
     * @property {String} errorCode - Error code as defined in the plugin documentation or system error code only in case of iOS.
     * @property {ErrorSource} errorSource - Source of the error.
     * @property {String=} translatedErrorMessage - Available in case of System error messages only for iOS.
     */
    /**
     * Deprecated: Use {@link AuthError}
     * @enum
     * @readonly
     * @deprecated Use {@link AuthError}
     */
    Error: {
      /**
       * Error code as defined in the plugin documentation or system error code only in case of iOS.
       * @type {String}
       */
      ErrorCode: 'errorCode',
      /**
       * Source of the error.
       * @type {ErrorSource}
       */
      ErrorSource: 'errorSource',
      /**
       * Available in case of System error messages only for iOS.
       * @type {String=}
       */
      TranslatedErrorMessage: 'translatedErrorMessage'
    },
    /**
     * Deprecated: Use {@link ErrorSource}.
     * @enum
     * @readonly
     * @deprecated Use {@link ErrorSource}.
     */
    ErrorSources: {
      /**
       * Source of the error is plugin.
       * @type {string}
       */
      Plugin: 'plugin',
      /**
       * Source of the error is system.
       * @type {string}
       */
      System: 'system'
    },
    /**
     * Enum values for {@link Error#ErrorSource}.
     * @enum
     * @readonly
     */
    ErrorSource: {
      /**
       * Source of the error is plugin.
       * @type {string}
       */
      Plugin: 'plugin',
      /**
       * Source of the error is system.
       * @type {string}
       */
      System: 'system'
    },
    RemoteAuthPropertiesBuilder: RemoteAuthPropertiesBuilder,
    HttpBasicAuthPropertiesBuilder: HttpBasicAuthPropertiesBuilder,
    FedAuthPropertiesBuilder: FedAuthPropertiesBuilder,
    OAuthPropertiesBuilder: OAuthPropertiesBuilder,
    OpenIDConnectPropertiesBuilder: OpenIDConnectPropertiesBuilder,
    LocalAuthPropertiesBuilder: LocalAuthPropertiesBuilder,
    LocalAuthenticationHelper: LocalAuthenticationHelper,
    /**
     * Starting point for creating an {@link AuthenticationFlow} instance.
     * Example usage:
     * <pre>
     * var authProps = new cordova.plugins.IdmAuthFlows.HttpBasicAuthPropertiesBuilder()
     *                     ...
     *                     ...
     *                     .build();
     * var initPromise = cordova.plugins.IdmAuthFlows.init(authProps);
     * initPromise.then(...).catch(...)
     * </pre>
     * @function init
     * @param {Object} authProps - An object containing configuration for authentication constructed
     * using one of the {@link PropertiesBuilder|builder} sub classes provided.
     * @return {Promise.<AuthenticationFlow>}
     * <p>Promise is resolved with a subclass of {@link AuthenticationFlow} depending on the type of authentication being inited:</p>
     * <ul style="list-style: none;">
     *  <li>Using {@link HttpBasicAuthPropertiesBuilder} will receive {@link HttpBasicAuthenticationFlow}</li>
     *  <li>Using {@link FedAuthPropertiesBuilder} or {@link OAuthPropertiesBuilder} or {@link OpenIDConnectPropertiesBuilder} will receive {@link RemoteAuthenticationFlow}</li>
     *  <li>Using {@link LocalAuthPropertiesBuilder} will receive {@link LocalAuthenticationFlow}</li>
     * </ul>
     * If the promise is rejected, the callback will receive and object of type {@link AuthError}
     */
    init: function(authProps)
    {
      if (!authProps || !authProps[authPropertyKeys.AuthServerType])
        return Promise.reject(getError("P1005"));

      if (authProps[authPropertyKeys.AuthServerType] === authServerTypes.LocalAuthenticator) {
        return Promise.resolve(new LocalAuthenticationFlow(authProps));
      }

      // Backwards compatibility
      if (typeof arguments[1] === "function") {
        console.warn("Parameter timeoutCallback in IdmAuthFlows.init is deprecated. Use authPropsBuilder.timeoutCallback().");
      }

      var timeoutCb = arguments[1];
      if (typeof authProps[authPropertyKeys.TimeoutCallback] === 'function')
        timeoutCb = authProps[authPropertyKeys.TimeoutCallback];
      // End: Backwards compatibility

      return new Promise(function (resolve, reject) {
        initializeRemoteFlow(authProps, timeoutCb, resolve, reject);
      });
    },
    /**
     * <p>Deprecated: Use new HttpBasicAuthPropertiesBuilder</p>
     * The object returned is a builder which can be used to create the authentication props for HttpBasicAuthentication.
     * Builder exposes methods to add properties relevant to HttpBasicAuthentication.
     * Example usage:
     * <pre><code>
     *    var authProps = IdmAuthFlows.newHttpBasicAuthPropertiesBuilder('appName',
     *                'http://loginUrl',
     *                'http://logoutUrl')
     *     .idleTimeOutInSeconds(300)
     *     .sessionTimeOutInSeconds(6000)
     *     .percentageToIdleTimeout(80)
     *     .maxLoginAttempts(2)
     *     .connectivityMode(IdmAuthFlows.ConnectivityMode.Offline)
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
     * @function newHttpBasicAuthPropertiesBuilder
     * @return {HttpBasicAuthPropertiesBuilder}
     * @deprecated Use new HttpBasicAuthPropertiesBuilder
     */
    newHttpBasicAuthPropertiesBuilder: function(appName, loginUrl, logoutUrl)
    {
      return new HttpBasicAuthPropertiesBuilder(appName, loginUrl, logoutUrl);
    },
    /**
     * <p>Deprecated: Use new FedAuthPropertiesBuilder</p>
     * The object returned is a builder which can be used to create the authentication props for FederatedAuthentication.
     * Builder exposes methods to add properties relevant to FederatedAuthentication.
     * Example usage:
     * <pre><code>
     *   var authProps = IdmAuthFlows.newFedAuthPropertiesBuilder('appName', 'http://login/url', 'http://logout/url',
     *                                                            'http://login/success', 'http://logout/failed')
     *     .logoutSuccessURL('http://logout/success')
     *     .logoutFailureUrl('http://logout/failed')
     *     .confirmLogoutAutomatically(true)
     *     .confirmLogoutButtonId('buttonId')
     *     .sessionTimeOutInSeconds(6000)
     *     .logoutTimeOutInSeconds(60)
     *     .customAuthHeaders({'header':'value'})
     *     .put('customKey1', 'customValue1')
     *     .put('customKey2', true)
     *     .build();
     * </code></pre>
     * @function newFedAuthPropertiesBuilder
     * @return {FedAuthPropertiesBuilder}
     * @deprecated Use new FedAuthPropertiesBuilder
     */
    newFedAuthPropertiesBuilder: function(appName, loginUrl, logoutUrl, loginSuccessUrl, loginFailureUrl)
    {
      return new FedAuthPropertiesBuilder(appName, loginUrl, logoutUrl, loginSuccessUrl, loginFailureUrl);
    },
    /**
     * <p>Deprecated: Use new OAuthPropertiesBuilder</p>
     * The object returned is a builder which can be used to create the authentication props for OAuthAuthentication.
     * Builder exposes methods to add properties relevant to OAuthAuthentication.
     * Example usage:
     * <pre><code>
     *   var authProps = IdmAuthFlows.newOAuthPropertiesBuilder('appName',
     *                                                          IdmAuthFlows.OAuthAuthorizationGrantType.OAuthResourceOwner,
     *                                                          'http://token/endpoint',
     *                                                          'clientId')
     *     .oAuthScope(['scope1', 'scope2'])
     *     .oAuthClientSecret('clientSecret')
     *     .oAuthAuthorizationEndpoint('http://auth/endpoint')
     *     .oAuthRedirectEndpoint('http://redirect/endpoint')
     *     .logoutURL('http://logout/url')
     *     .browserMode(IdmAuthFlows.BrowserMode.External)
     *     .logoutTimeOutInSeconds(60)
     *     .customAuthHeaders({'header':'value'})
     *     .put('customKey1', 'customValue1')
     *     .put('customKey2', true)
     *     .build();
     * </code></pre>
     * @function newOAuthPropertiesBuilder
     * @return {OAuthPropertiesBuilder}
     * @deprecated Use new OAuthPropertiesBuilder
     */
    newOAuthPropertiesBuilder: function(appName, grantType, tokenEndpoint, clientId)
    {
      return new OAuthPropertiesBuilder(appName, grantType, tokenEndpoint, clientId);
    },
    /**
     * <p>Deprecated: Use new OpenIDConnectPropertiesBuilder</p>
     * The object returned is a builder which can be used to create the authentication props for OpenIdConnect.
     * Builder exposes methods to add properties relevant to OpenId Connect authentication.
     * Example usage:
     * <pre><code>
     *   var authProps = IdmAuthFlows.newOpenIDConnectPropertiesBuilder('appName',
     *                                                          IdmAuthFlows.OAuthAuthorizationGrantType.OAuthResourceOwner,
     *                                                          'http://openid/discovery/url',
     *                                                          'clientId')
     *     .oAuthClientSecret('clientSecret')
     *     .oAuthScope(['scope1', 'scope2'])
     *     .browserMode(IdmAuthFlows.BrowserMode.External)
     *     .logoutTimeOutInSeconds(60)
     *     .customAuthHeaders({'header':'value'})
     *     .put('customKey1', 'customValue1')
     *     .put('customKey2', true)
     *     .build();
     * </code></pre>
     * @function newOpenIDConnectPropertiesBuilder
     * @return {OpenIDConnectPropertiesBuilder}
     * @deprecated Use new OpenIDConnectPropertiesBuilder
     */
    newOpenIDConnectPropertiesBuilder: function(appName, grantType, discoveryEndpoint, clientId)
    {
      return new OpenIDConnectPropertiesBuilder(appName, grantType, discoveryEndpoint, clientId);
    }
  };
}();

module.exports = IdmAuthFlows;
