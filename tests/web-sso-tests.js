/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var httpCallResult, defaultJasmineTimeout, fedHeaders, authFlow, authBeforeLogin, authAfterLogin, authAfterLogout;
  var webSsoProps = new idmAuthFlowPlugin.FedAuthPropertiesBuilder()
      .appName('WebSsoTest')
      .loginUrl(window.TestConfig.websso.loginUrl)
      .logoutUrl(window.TestConfig.websso.logoutUrl)
      .loginSuccessUrl(window.TestConfig.websso.loginSuccessUrl)
      .loginFailureUrl(window.TestConfig.websso.loginFailureUrl)
      .build();
  var samlProps = new idmAuthFlowPlugin.FedAuthPropertiesBuilder()
      .appName('samlTest')
      .loginUrl(window.TestConfig.saml.loginUrl)
      .logoutUrl(window.TestConfig.saml.logoutUrl)
      .loginSuccessUrl(window.TestConfig.saml.loginSuccessUrl)
      .loginFailureUrl(window.TestConfig.saml.loginFailureUrl)
      .parseTokenRelayResponse(true)
      .build();

  var perform = function(props, securedUrl, done) {
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
        var options = {fedAuthSecuredUrl: securedUrl};
        return authFlow.getHeaders(options);
      })
      .then(function(headers) {
        fedHeaders = headers;
        return window.TestUtil.xmlHttpRequestPromise(headers, securedUrl);
      })
      .then(function(result) {
        httpCallResult = result;
        return authFlow.logout(true);
      })
      .then(function(flow) {
        return flow.isAuthenticated();
      })
      .then(function(auth) {
        authAfterLogout = auth;
      })
      .then(done)
      .catch(done);
  };

  var verify = function(resp, checkCookies) {
    expect(authAfterLogin).toBeTruthy();
    expect(authBeforeLogin).not.toBeTruthy();
    expect(authAfterLogout).not.toBeTruthy();
    expect(httpCallResult).toBeDefined();
    expect(httpCallResult).toContain(resp);
    expect(fedHeaders).toBeDefined();

    if (checkCookies)
      expect(fedHeaders.cookies).toBeDefined();
  };

  var resetTest = function() {
    authAfterLogin = undefined;
    authBeforeLogin = undefined;
    authAfterLogout = undefined;
    httpCallResult = undefined;
    fedHeaders = undefined;
  };

  describe('Test Federated authentication', function () {
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });

    describe('simple websso configuration', function() {
      beforeEach(function(done) {
        resetTest();
        perform(webSsoProps, window.TestConfig.websso.securedUrl, done);
      });
      it('is able to login and access secured resource.', function(done) {
        verify(window.TestConfig.websso.securedResponse, true);
        done();
      });
    });

    // @ignore: Fails on iOS because of invalid redirect challenge
    describe('SAML websso configuration', function() {
      beforeEach(function(done) {
        resetTest();
        perform(samlProps, window.TestConfig.saml.securedUrl, done);
      });
      it('is able to login and access secured resource.', function(done) {
        verify(window.TestConfig.saml.securedResponse, false);
        done();
      });
    });
  });
};