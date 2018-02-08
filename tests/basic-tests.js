/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('idmAuthFlowPlugin', function () {
    it('idmAuthFlowPlugin is defined.', function() {
      expect(idmAuthFlowPlugin).toBeDefined();
    });
    it('init is defined.', function() {
      expect(idmAuthFlowPlugin.init).toBeDefined();
    });
    it('newHttpBasicAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder).toBeDefined();
    });
    it('newFedAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.newFedAuthPropertiesBuilder).toBeDefined();
    });
    it('newOAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.newOAuthPropertiesBuilder).toBeDefined();
    });
  });

  describe('idmAuthFlowPlugin.newHttpBasicAuthentication', function () {
    var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('appName',
                'http://login',
                'http://logout')
      .idleTimeOutInSeconds(300)
      .sessionTimeOutInSeconds(6000)
      .percentageToIdleTimeout(80)
      .maxLoginAttempts(2)
      .connectivityMode(idmAuthFlowPlugin.ConnectivityModes.Offline)
      .offlineAuthAllowed(true)
      .customAuthHeaders({'a':'b'})
      .rememberUsernameAllowed(true)
      .rememberCredentialsAllowed(false)
      .rememberUsernameDefault(true)
      .rememberCredentialDefault(true)
      .autoLoginDefault(false)
      .put('customKey1', 'customValue1')
      .put('customKey2', true)
      .build();
    it('should create auth props with correct values.', function() {
      expect(authProps.AuthServerType).toBe('HTTPBasicAuthentication');
      expect(authProps.CryptoScheme).toBe('AES');
      expect(authProps.ApplicationName).toBe('appName');
      expect(authProps.IdleTimeOutValue).toBe(300);
      expect(authProps.SessionTimeOutValue).toBe(6000);
      expect(authProps.PercentageToIdleTimeout).toBe(80);
      expect(authProps.MaxLoginAttempts).toBe(2);
      expect(authProps.ConnectivityMode).toBe(idmAuthFlowPlugin.ConnectivityModes.Offline);
      expect(authProps.OfflineAuthAllowed).toBe(true);
      expect(authProps.LoginURL).toBe('http://login');
      expect(authProps.LogoutURL).toBe('http://logout');
      expect(authProps.CustomAuthHeaders.a).toBe('b');
      expect(authProps.RememberUsernameAllowed).toBe(true);
      expect(authProps.RememberCredentialsAllowed).toBe(false);
      expect(authProps.RememberUsernameDefault).toBe(true);
      expect(authProps.RememberCredentialDefault).toBe(true);
      expect(authProps.AutoLoginDefault).toBe(false);
      expect(authProps.customKey1).toBe('customValue1');
      expect(authProps.customKey2).toBe(true);
    });
    it('should validate applicationName.',function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder(); })
      .toThrow(new Error('Invalid value undefined passed for ApplicationName. A valid string should be passed.'));
    });
    it('should not allow undefined for loginURL.',function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests'); })
      .toThrow(new Error('Invalid value undefined passed for LoginURL. A valid string should be passed.'));
    });
    it('should not allow number for loginURL.',function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 1234); })
      .toThrow(new Error('Invalid value 1234 passed for LoginURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for loginURL.',function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for LoginURL. A valid URL should be passed.'));
    });
    it('should not allow undefined for logoutURL.',function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login'); })
      .toThrow(new Error('Invalid value undefined passed for LogoutURL. A valid string should be passed.'));
    });
    it('should not allow number for logoutURL.',function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 1234); })
      .toThrow(new Error('Invalid value 1234 passed for LogoutURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for logoutURL.',function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for LogoutURL. A valid URL should be passed.'));
    });
    it('should not allow string for idleTimeout', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').idleTimeOutInSeconds('20'); })
      .toThrow(new Error('Invalid value 20 passed for IdleTimeOutValue. A valid number should be passed.'));
    });
    it('should not allow string for sessionTimeout', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').sessionTimeOutInSeconds('20'); })
      .toThrow(new Error('Invalid value 20 passed for SessionTimeOutValue. A valid number should be passed.'));
    });
    it('should not allow string for percentageToIdleTimeout', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').percentageToIdleTimeout('20'); })
      .toThrow(new Error('Invalid value 20 passed for PercentageToIdleTimeout. A valid number should be passed.'));
    });
    it('should not allow < 0 for percentageToIdleTimeout', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').percentageToIdleTimeout(-112); })
      .toThrow(new Error('PercentageToIdleTimeout should be between [0 - 100].'));
    });
    it('should not allow > 100 for percentageToIdleTimeout', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').percentageToIdleTimeout(302); })
      .toThrow(new Error('PercentageToIdleTimeout should be between [0 - 100].'));
    });
    it('should not allow string for maxLoginAttempts', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').maxLoginAttempts('2'); })
      .toThrow(new Error('Invalid value 2 passed for MaxLoginAttempts. A valid number should be passed.'));
    });
    it('should not allow string for connectivityMode', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').connectivityMode('wrong'); })
      .toThrow(new Error('ConnectivityMode should be one from IdmAuthFlows.ConnectivityModes.'));
    });
    it('should not allow string for offlineAuthAllowed', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').offlineAuthAllowed('true'); })
      .toThrow(new Error('Invalid value true passed for OfflineAuthAllowed. A valid boolean should be passed.'));
    });
    it('should not allow string for customAuthHeaders', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').customAuthHeaders('wrong'); })
      .toThrow(new Error('Invalid value wrong passed for CustomAuthHeaders. A valid object should be passed.'));
    });
    it('should not allow number for customAuthHeaders', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').customAuthHeaders(1); })
      .toThrow(new Error('Invalid value 1 passed for CustomAuthHeaders. A valid object should be passed.'));
    });
    it('should not allow string for rememberUsernameAllowed', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').rememberUsernameAllowed('true'); })
      .toThrow(new Error('Invalid value true passed for RememberUsernameAllowed. A valid boolean should be passed.'));
    });
    it('should not allow string for rememberCredentialsAllowed', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').rememberCredentialsAllowed('false'); })
      .toThrow(new Error('Invalid value false passed for RememberCredentialsAllowed. A valid boolean should be passed.'));
    });
    it('should not allow string for rememberUsernameDefault', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').rememberUsernameDefault('true'); })
      .toThrow(new Error('Invalid value true passed for RememberUsernameDefault. A valid boolean should be passed.'));
    });
    it('should not allow string for rememberCredentialDefault', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').rememberCredentialDefault('true'); })
      .toThrow(new Error('Invalid value true passed for RememberCredentialDefault. A valid boolean should be passed.'));
    });
    it('should not allow string for autoLoginDefault', function() {
      expect(function() { idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout').autoLoginDefault('true'); })
      .toThrow(new Error('Invalid value true passed for AutoLoginDefault. A valid boolean should be passed.'));
    });
  });
  describe('idmAuthFlowPlugin.newFederatedAuthentication', function () {
    var authProps = idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login/url', 'http://logout/url',
                                                            'http://login/success', 'http://logout/failed')
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
    it('should create auth props with correct values.', function() {
      expect(authProps.AuthServerType).toBe('FederatedAuthentication');
      expect(authProps.IdleTimeOutValue).toBe(300);
      expect(authProps.SessionTimeOutValue).toBe(6000);
      expect(authProps.PercentageToIdleTimeout).toBe(80);
      expect(authProps.ParseTokenRelayResponse).toBe(true);
      expect(authProps.enablewkwebview).toBe(true);
      expect(authProps.CustomAuthHeaders).toBeDefined();
      expect(authProps.CustomAuthHeaders.header).toBe('value');
      expect(authProps.customKey1).toBe('customValue1');
      expect(authProps.customKey2).toBe(true);
      expect(authProps.LoginURL).toBe('http://login/url');
      expect(authProps.LogoutURL).toBe('http://logout/url');
      expect(authProps.LoginSuccessURL).toBe('http://login/success');
      expect(authProps.LoginFailureURL).toBe('http://logout/failed');
    });
    it('should validate applicationName.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder(); })
      .toThrow(new Error('Invalid value undefined passed for ApplicationName. A valid string should be passed.'));
    });
    it('should not allow undefined for loginURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests'); })
      .toThrow(new Error('Invalid value undefined passed for LoginURL. A valid string should be passed.'));
    });
    it('should not allow number for loginURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 1234); })
      .toThrow(new Error('Invalid value 1234 passed for LoginURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for loginURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for LoginURL. A valid URL should be passed.'));
    });
    it('should not allow undefined for logoutURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login'); })
      .toThrow(new Error('Invalid value undefined passed for LogoutURL. A valid string should be passed.'));
    });
    it('should not allow number for logoutURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 1234); })
      .toThrow(new Error('Invalid value 1234 passed for LogoutURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for logoutURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for LogoutURL. A valid URL should be passed.'));
    });
    it('should not allow undefined for loginSuccessURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout'); })
      .toThrow(new Error('Invalid value undefined passed for LoginSuccessURL. A valid string should be passed.'));
    });
    it('should not allow number for loginSuccessURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 1234); })
      .toThrow(new Error('Invalid value 1234 passed for LoginSuccessURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for loginSuccessURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for LoginSuccessURL. A valid URL should be passed.'));
    });
    it('should not allow undefined for loginFailureURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc'); })
      .toThrow(new Error('Invalid value undefined passed for LoginFailureURL. A valid string should be passed.'));
    });
    it('should not allow number for loginFailureURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 1234); })
      .toThrow(new Error('Invalid value 1234 passed for LoginFailureURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for loginFailureURL.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for LoginFailureURL. A valid URL should be passed.'));
    });
    it('should not allow string for parseTokenRelayResponse.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').parseTokenRelayResponse('true'); })
      .toThrow(new Error('Invalid value true passed for ParseTokenRelayResponse. A valid boolean should be passed.'));
    });
    it('should not allow string for parseTokenRelayResponse.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').parseTokenRelayResponse('false'); })
      .toThrow(new Error('Invalid value false passed for ParseTokenRelayResponse. A valid boolean should be passed.'));
    });
    it('should not allow string for parseTokenRelayResponse.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').parseTokenRelayResponse('abcd'); })
      .toThrow(new Error('Invalid value abcd passed for ParseTokenRelayResponse. A valid boolean should be passed.'));
    });
    it('should not allow string for parseTokenRelayResponse.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').parseTokenRelayResponse(1234); })
      .toThrow(new Error('Invalid value 1234 passed for ParseTokenRelayResponse. A valid boolean should be passed.'));
    });
    it('should not allow string for enableWkWebView.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').enableWkWebView('true'); })
      .toThrow(new Error('Invalid value true passed for enablewkwebview. A valid boolean should be passed.'));
    });
    it('should not allow string for enableWkWebView.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').enableWkWebView('false'); })
      .toThrow(new Error('Invalid value false passed for enablewkwebview. A valid boolean should be passed.'));
    });
    it('should not allow string for enableWkWebView.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').enableWkWebView('abcd'); })
      .toThrow(new Error('Invalid value abcd passed for enablewkwebview. A valid boolean should be passed.'));
    });
    it('should not allow string for enableWkWebView.',function() {
      expect(function() { idmAuthFlowPlugin.newFedAuthPropertiesBuilder('jasmineJsTests', 'http://login', 'http://logout', 'http://loginSucc', 'http://loginFail').enableWkWebView(1234); })
      .toThrow(new Error('Invalid value 1234 passed for enablewkwebview. A valid boolean should be passed.'));
    });
  });
  describe('idmAuthFlowPlugin.newOAuthAuthentication', function () {
    var authProps = idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests',
          idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
          'http://tokenEndPoint',
          'clientId')
      .oAuthAuthorizationEndpoint('http://authEndPoint')
      .oAuthRedirectEndpoint('http://redirectEndPoint')
      .logoutURL('http://logoutURL')
      .oAuthScope(['scope1', 'scope2'])
      .oAuthClientSecret('secret')
      .browserMode(idmAuthFlowPlugin.BrowserMode.External)
      .idleTimeOutInSeconds(300)
      .sessionTimeOutInSeconds(6000)
      .percentageToIdleTimeout(80)
      .logoutTimeOutInSeconds(60)
      .customAuthHeaders({'header':'value'})
      .put('customKey1', 'customValue1')
      .put('customKey2', true)
      .build();
    it('should create auth props with correct values.', function() {
      expect(authProps.AuthServerType).toBe('OAuthAuthentication');
      expect(authProps.OAuthTokenEndpoint).toBe('http://tokenEndPoint');
      expect(authProps.OAuthAuthorizationEndpoint).toBe('http://authEndPoint');
      expect(authProps.OAuthRedirectEndpoint).toBe('http://redirectEndPoint');
      expect(authProps.LogoutURL).toBe('http://logoutURL');
      expect(authProps.OAuthAuthorizationGrantType).toBe(idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthResourceOwner);
      expect(authProps.OAuthScope).toBeDefined();
      expect(authProps.OAuthScope[0]).toBe('scope1');
      expect(authProps.OAuthScope[1]).toBe('scope2');
      expect(authProps.OAuthClientID).toBe('clientId');
      expect(authProps.OAuthClientSecret).toBe('secret');
      expect(authProps.BrowserMode).toBe(idmAuthFlowPlugin.BrowserMode.External);
      expect(authProps.IdleTimeOutValue).toBe(300);
      expect(authProps.SessionTimeOutValue).toBe(6000);
      expect(authProps.PercentageToIdleTimeout).toBe(80);
      expect(authProps.CustomAuthHeaders).toBeDefined();
      expect(authProps.CustomAuthHeaders.header).toBe('value');
      expect(authProps.customKey1).toBe('customValue1');
      expect(authProps.customKey2).toBe(true);
    });
    it('should validate applicationName is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder(); })
      .toThrow(new Error('Invalid value undefined passed for ApplicationName. A valid string should be passed.'));
    });
    it('should not allow undefined for OAuthAuthorizationGrantType', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests'); })
      .toThrow(new Error('Invalid value undefined passed for OAuthAuthorizationGrantType. A valid string should be passed.'));
    });
    it('should not allow number for OAuthAuthorizationGrantType', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', 111); })
      .toThrow(new Error('Invalid value 111 passed for OAuthAuthorizationGrantType. A valid string should be passed.'));
    });
    it('should not allow random string for OAuthAuthorizationGrantType', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', 'abcd'); })
      .toThrow(new Error('OAuthAuthorizationGrantType should be one from IdmAuthFlows.OAuthAuthorizationGrantTypes.'));
    });
    it('should not allow undefined for OAuthTokenEndpoint is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit); })
      .toThrow(new Error('Invalid value undefined passed for OAuthTokenEndpoint. A valid string should be passed.'));
    });
    it('should not allow number for OAuthTokenEndpoint is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 1234); })
      .toThrow(new Error('Invalid value 1234 passed for OAuthTokenEndpoint. A valid string should be passed.'));
    });
    it('should not allow non URL string for OAuthTokenEndpoint is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for OAuthTokenEndpoint. A valid URL should be passed.'));
    });
    it('should not allow undefined for oAuthClientID', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint'); })
      .toThrow(new Error('Invalid value undefined passed for OAuthClientID. A valid string should be passed.'));
    });
    it('should not allow number for oAuthClientID', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 2222); })
      .toThrow(new Error('Invalid value 2222 passed for OAuthClientID. A valid string should be passed.'));
    });
    it('should not allow number for oAuthAuthorizationEndpoint', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').oAuthAuthorizationEndpoint(1234); })
      .toThrow(new Error('Invalid value 1234 passed for OAuthAuthorizationEndpoint. A valid string should be passed.'));
    });
    it('should not allow non URL string for oAuthAuthorizationEndpoint', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').oAuthAuthorizationEndpoint('abcd'); })
      .toThrow(new Error('Invalid value abcd passed for OAuthAuthorizationEndpoint. A valid URL should be passed.'));
    });
    it('should not allow number for oAuthRedirectEndpoint', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').oAuthRedirectEndpoint(1234); })
      .toThrow(new Error('Invalid value 1234 passed for OAuthRedirectEndpoint. A valid string should be passed.'));
    });
    it('should not allow non URL string for oAuthRedirectEndpoint', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').oAuthRedirectEndpoint('abcd'); })
      .toThrow(new Error('Invalid value abcd passed for OAuthRedirectEndpoint. A valid URL should be passed.'));
    });
    it('should not allow number for logoutURL', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').logoutURL(1234); })
      .toThrow(new Error('Invalid value 1234 passed for LogoutURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for logoutURL', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').logoutURL('abcd'); })
      .toThrow(new Error('Invalid value abcd passed for LogoutURL. A valid URL should be passed.'));
    });
    it('should not allow number for browserMode', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').browserMode(1234); })
      .toThrow(new Error('Invalid value 1234 passed for BrowserMode. A valid string should be passed.'));
    });
    it('should not allow random string for browserMode', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').browserMode('abcd'); })
      .toThrow(new Error('BrowserMode should be one from IdmAuthFlows.BrowserMode.'));
    });
    it('should not allow number for oAuthScope', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').oAuthScope('scope'); })
      .toThrow(new Error('Invalid value scope passed for OAuthScope. A valid object should be passed.'));
    });
    it('should not allow number for oAuthClientSecret', function() {
      expect(function() { idmAuthFlowPlugin.newOAuthPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://tokenEndPoint', 'clientId').oAuthClientSecret(2222); })
      .toThrow(new Error('Invalid value 2222 passed for OAuthClientSecret. A valid string should be passed.'));
    });
  });
  describe('idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder', function () {
    var authProps = idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests',
          idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
          'http://discoveryEndPoint',
          'clientId')
      .oAuthScope(['scope1', 'scope2'])
      .oAuthClientSecret('secret')
      .browserMode(idmAuthFlowPlugin.BrowserMode.External)
      .idleTimeOutInSeconds(300)
      .sessionTimeOutInSeconds(6000)
      .percentageToIdleTimeout(80)
      .logoutTimeOutInSeconds(60)
      .customAuthHeaders({'header':'value'})
      .put('customKey1', 'customValue1')
      .put('customKey2', true)
      .build();
    it('should create auth props with correct values.', function() {
      expect(authProps.AuthServerType).toBe('OpenIDConnect10');
      expect(authProps.OpenIDConnectDiscoveryURL).toBe('http://discoveryEndPoint');
      expect(authProps.OAuthAuthorizationGrantType).toBe(idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthResourceOwner);
      expect(authProps.OAuthScope).toBeDefined();
      expect(authProps.OAuthScope[0]).toBe('scope1');
      expect(authProps.OAuthScope[1]).toBe('scope2');
      expect(authProps.OAuthClientID).toBe('clientId');
      expect(authProps.OAuthClientSecret).toBe('secret');
      expect(authProps.BrowserMode).toBe(idmAuthFlowPlugin.BrowserMode.External);
      expect(authProps.IdleTimeOutValue).toBe(300);
      expect(authProps.SessionTimeOutValue).toBe(6000);
      expect(authProps.PercentageToIdleTimeout).toBe(80);
      expect(authProps.CustomAuthHeaders).toBeDefined();
      expect(authProps.CustomAuthHeaders.header).toBe('value');
      expect(authProps.customKey1).toBe('customValue1');
      expect(authProps.customKey2).toBe(true);
    });
    it('should validate applicationName is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder(); })
      .toThrow(new Error('Invalid value undefined passed for ApplicationName. A valid string should be passed.'));
    });
    it('should not allow undefined for OAuthAuthorizationGrantType', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests'); })
      .toThrow(new Error('Invalid value undefined passed for OAuthAuthorizationGrantType. A valid string should be passed.'));
    });
    it('should not allow number for OAuthAuthorizationGrantType', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', 111); })
      .toThrow(new Error('Invalid value 111 passed for OAuthAuthorizationGrantType. A valid string should be passed.'));
    });
    it('should not allow number for OAuthAuthorizationGrantType', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', 'abcd'); })
      .toThrow(new Error('OAuthAuthorizationGrantType should be one from IdmAuthFlows.OAuthAuthorizationGrantTypes.'));
    });
    it('should not allow undefined for OpenIDConnectDiscoveryURL is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit); })
      .toThrow(new Error('Invalid value undefined passed for OpenIDConnectDiscoveryURL. A valid string should be passed.'));
    });
    it('should not allow number for OpenIDConnectDiscoveryURL is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 1234); })
      .toThrow(new Error('Invalid value 1234 passed for OpenIDConnectDiscoveryURL. A valid string should be passed.'));
    });
    it('should not allow non URL string for OpenIDConnectDiscoveryURL is passed.',function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'abcd'); })
      .toThrow(new Error('Invalid value abcd passed for OpenIDConnectDiscoveryURL. A valid URL should be passed.'));
    });
    it('should not allow undefined for oAuthClientID', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://discoveryEndPoint'); })
      .toThrow(new Error('Invalid value undefined passed for OAuthClientID. A valid string should be passed.'));
    });
    it('should not allow number for oAuthClientID', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://discoveryEndPoint', 2222); })
      .toThrow(new Error('Invalid value 2222 passed for OAuthClientID. A valid string should be passed.'));
    });
    it('should not allow number for oAuthScope', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://discoveryEndPoint', 'clientId').oAuthScope('scope'); })
      .toThrow(new Error('Invalid value scope passed for OAuthScope. A valid object should be passed.'));
    });
    it('should not allow number for oAuthClientSecret', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://discoveryEndPoint', 'clientId').oAuthClientSecret(2222); })
      .toThrow(new Error('Invalid value 2222 passed for OAuthClientSecret. A valid string should be passed.'));
    });
    it('should not allow number for browserMode', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://discoveryEndPoint', 'clientId').browserMode(1234); })
      .toThrow(new Error('Invalid value 1234 passed for BrowserMode. A valid string should be passed.'));
    });
    it('should not allow random string for browserMode', function() {
      expect(function() { idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('jasmineJsTests', idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthImplicit, 'http://discoveryEndPoint', 'clientId').browserMode('abcd'); })
      .toThrow(new Error('BrowserMode should be one from IdmAuthFlows.BrowserMode.'));
    });
  });
};
