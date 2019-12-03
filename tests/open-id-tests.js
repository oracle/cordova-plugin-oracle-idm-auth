/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var results, defaultJasmineTimeout;
  var openIdProps = new idmAuthFlowPlugin.OpenIDConnectPropertiesBuilder()
      .appName('idcsOpenId')
      .oAuthAuthorizationGrantType(window.TestConfig.openid.grantType)
      .discoveryEndpoint(window.TestConfig.openid.discoveryUrl)
      .oAuthClientID(window.TestConfig.openid.clientId)
      .oAuthRedirectEndpoint(window.TestConfig.openid.redirectUrl)
      .oAuthScope([window.TestConfig.openid.scope1, window.TestConfig.openid.scope2]);


  var createTest = function(browserMode, enablePkce) {
    return function() {
      beforeEach(function(done) {
        var authProps = openIdProps.browserMode(browserMode).enablePKCE(enablePkce).build();
        results = {};
        window.TestUtil.loginXhrLogout(authProps, window.TestConfig.openid.securedUrl, results, done);
      });

      it('is able to login and access secured resource.', function(done) {
        var options = {};
        options.securedUrlResult = window.TestConfig.openid.username;
        window.TestUtil.verifyResults(results, options);
        done();
      });

      it('is able to login and accessible secured resource contains required headers.', function(done) {
        var options = {};
        options.securedUrlResult = window.TestConfig.openid.username;
        window.TestUtil.verifyResults(results, options);
        done();
      });
    };
  };

  describe('Test OpenIDConnect', function () {
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 120000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });

    describe('with embedded browser and PKCE off', createTest(idmAuthFlowPlugin.OAuthPropertiesBuilder.BrowserMode.Embedded, false));
    describe('with external browser and PKCE off', createTest(idmAuthFlowPlugin.OAuthPropertiesBuilder.BrowserMode.External, false));
    describe('with embedded browser and PKCE on', createTest(idmAuthFlowPlugin.OAuthPropertiesBuilder.BrowserMode.Embedded, true));
    describe('with external browser and PKCE on', createTest(idmAuthFlowPlugin.OAuthPropertiesBuilder.BrowserMode.External, true));
  });
};
