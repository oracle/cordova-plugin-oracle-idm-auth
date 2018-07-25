/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var httpCallResult, defaultJasmineTimeout, oauthHeaders, authFlow, authBeforeLogin, authAfterLogin, authAfterLogout;

  var oauthGoogleAuthCodeProps = new idmAuthFlowPlugin.OAuthPropertiesBuilder()
      .appName('oauthGoogleAuthCodeTest')
      .oAuthAuthorizationGrantType(window.TestConfig.oauthGoogleAuthCode.grantType)
      .oAuthTokenEndpoint(window.TestConfig.oauthGoogleAuthCode.tokenUrl)
      .oAuthClientID(window.TestConfig.oauthGoogleAuthCode.clientId)
      .oAuthAuthorizationEndpoint(window.TestConfig.oauthGoogleAuthCode.authUrl)
      .oAuthRedirectEndpoint(window.TestConfig.oauthGoogleAuthCode.redirectUrl)
      .oAuthScope([window.TestConfig.oauthGoogleAuthCode.scope1,
                    window.TestConfig.oauthGoogleAuthCode.scope2])
      .logoutURL(window.TestConfig.oauthGoogleAuthCode.logoutUrl)
      .browserMode(idmAuthFlowPlugin.OAuthPropertiesBuilder.BrowserMode.External)
      .build();
  var oauthIdcsAuthCodeProps = new idmAuthFlowPlugin.OAuthPropertiesBuilder()
      .appName('oauthIdcsAuthCodeTest')
      .oAuthAuthorizationGrantType(window.TestConfig.oauthIdcsAuthCode.grantType)
      .oAuthTokenEndpoint(window.TestConfig.oauthIdcsAuthCode.tokenUrl)
      .oAuthClientID(window.TestConfig.oauthIdcsAuthCode.clientId)
      .oAuthAuthorizationEndpoint(window.TestConfig.oauthIdcsAuthCode.authUrl)
      .oAuthRedirectEndpoint(window.TestConfig.oauthIdcsAuthCode.redirectUrl)
      .oAuthScope([window.TestConfig.oauthIdcsAuthCode.scope1])
      .logoutURL(window.TestConfig.oauthIdcsAuthCode.logoutUrl)
      .browserMode(idmAuthFlowPlugin.OAuthPropertiesBuilder.BrowserMode.External)
      .build();
  var oauthMcsResOwnerProps = new idmAuthFlowPlugin.OAuthPropertiesBuilder()
      .appName('oauthMcsResOwnerTest')
      .oAuthAuthorizationGrantType(window.TestConfig.oauthMcsResOwner.grantType)
      .oAuthTokenEndpoint(window.TestConfig.oauthMcsResOwner.tokenUrl)
      .oAuthClientID(window.TestConfig.oauthMcsResOwner.clientId)
      .oAuthClientSecret(window.TestConfig.oauthMcsResOwner.secret)
      .challengeCallback(function(fields, proceed) {
        fields.username_key = window.TestConfig.oauthMcsResOwner.userName;
        fields.password_key = window.TestConfig.oauthMcsResOwner.password;
        proceed(fields);
      })
      .customAuthHeaders({'X-User-Identity-Domain-Name': 'yoda'})
      .build();
  var oauthIdcsResOwnerProps = new idmAuthFlowPlugin.OAuthPropertiesBuilder()
      .appName('oauthIdcsResOwnerTest')
      .oAuthAuthorizationGrantType(window.TestConfig.oauthIdcsResOwner.grantType)
      .oAuthTokenEndpoint(window.TestConfig.oauthIdcsResOwner.tokenUrl)
      .oAuthClientID(window.TestConfig.oauthIdcsResOwner.clientId)
      .oAuthClientSecret(window.TestConfig.oauthIdcsResOwner.secret)
      .challengeCallback(function(fields, proceed) {
        fields.username_key = window.TestConfig.oauthIdcsResOwner.userName;
        fields.password_key = window.TestConfig.oauthIdcsResOwner.password;
        proceed(fields);
      })
      .build();

  var oauthIdcsClientCredProps = new idmAuthFlowPlugin.OAuthPropertiesBuilder()
      .appName('oauthIdcsClientCredTest')
      .oAuthAuthorizationGrantType(window.TestConfig.oauthIdcsClientCred.grantType)
      .oAuthTokenEndpoint(window.TestConfig.oauthIdcsClientCred.tokenUrl)
      .oAuthClientID(window.TestConfig.oauthIdcsClientCred.clientId)
      .oAuthClientSecret(window.TestConfig.oauthIdcsClientCred.secret)
      .oAuthScope([window.TestConfig.oauthIdcsClientCred.scope1])
      .build();

  var perform = function(props, securedUrl, done, logout) {
    idmAuthFlowPlugin.init(props)
      .then(function(flow) {
        authFlow = flow;
        return flow.isAuthenticated();
      })
      .then(function(auth) {
        authBeforeLogin = auth;
        return authFlow.login();
      })
      .then(function(flow) {
        return flow.isAuthenticated();
      })
      .then(function(auth) {
        authAfterLogin = auth;
        return authFlow.getHeaders();
      })
      .then(function(headers) {
        oauthHeaders = headers;
        return window.TestUtil.xmlHttpRequestPromise(headers, securedUrl);
      })
      .then(function(result) {
        httpCallResult = result;
        if (logout) {
          authFlow.logout(true)
            .then(function(flow) {
              return flow.isAuthenticated();
            })
            .then(function(auth) {
              authAfterLogout = auth;
            })
            .then(done)
            .catch(done);

        } else {
          done();
        }
      })
      .catch(done);
  };

  var verify = function(resp, logout) {
    expect(authAfterLogin).toBeTruthy();
    expect(authBeforeLogin).not.toBeTruthy();
    expect(httpCallResult).toBeDefined();
    expect(httpCallResult).toContain(resp);
    expect(oauthHeaders).toBeDefined();
    if (logout)
      expect(authAfterLogout).not.toBeTruthy();
  };

  var resetTest = function() {
    authAfterLogin = undefined;
    authBeforeLogin = undefined;
    authAfterLogout = undefined;
    httpCallResult = undefined;
    oauthHeaders = undefined;
  };

  describe('Test OAUTH flows', function() {
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
/*
    // Not working
    describe('idcs client cred', function() {
      beforeEach(function(done) {
        resetTest();
        perform(oauthIdcsClientCredProps, window.TestConfig.oauthIdcsClientCred.securedUrl, done, true);
      });
      it('is able to login and access secured resource.', function(done) {
        verify('admin@oracle.com', true);
        done();
      });
    });
    describe('idcs resource owner', function() {
      beforeEach(function(done) {
        resetTest();
        perform(oauthIdcsResOwnerProps, window.TestConfig.oauthIdcsResOwner.securedUrl, done, true);
      });
      it('is able to login and access secured resource.', function(done) {
        verify('admin@oracle.com', true);
        done();
      });
    });
*/
    describe('idcs auth code', function() {
      beforeEach(function(done) {
        resetTest();
        // TODO: Redirect to app after logout is not happening. Could be a bug.
        perform(oauthIdcsAuthCodeProps, window.TestConfig.oauthIdcsAuthCode.securedUrl, done, false);
      });
      it('is able to login and access secured resource.', function(done) {
        verify('admin@oracle.com', true);
        done();
      });
    });
    describe('google auth code', function() {
      beforeEach(function(done) {
        resetTest();
        perform(oauthGoogleAuthCodeProps, window.TestConfig.oauthGoogleAuthCode.securedUrl, done, false);
      });
      it('is able to login and access secured resource.', function(done) {
        verify('adfview@gmail.com', false);
        done();
      });
    });
    describe('mcs resource owner', function() {
      beforeEach(function(done) {
        resetTest();
        perform(oauthMcsResOwnerProps, window.TestConfig.oauthMcsResOwner.securedUrl, done, true);
      });
      it('is able to login and access secured resource.', function(done) {
        verify('Hello', true);
        done();
      });
    });
  });
};
