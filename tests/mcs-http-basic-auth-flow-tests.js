/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var Builder = idmAuthFlowPlugin.HttpBasicAuthPropertiesBuilder;
  var authFlow, mcsHeaders, securedCallResult;

  var challengeCallback = function (fields, proceedHandler) {
    fields.username_key = window.TestConfig.basicMcs.userName;
    fields.password_key = window.TestConfig.basicMcs.password;
    proceedHandler(fields);
  };

  describe('MCS Http basic test', function() {
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });

    describe('login and verify mcs headers and access', function() {
      beforeEach(function(done) {
        var builder = new Builder()
          .appName("MCSTest")
          .loginUrl(window.TestConfig.basicMcs.loginUrl)
          .logoutUrl(window.TestConfig.basicMcs.logoutUrl)
          .customAuthHeaders({"oracle-mobile-backend-id": window.TestConfig.basicMcs.backendId})
          .challengeCallback(challengeCallback)
          .offlineAuthAllowed(true);

        idmAuthFlowPlugin.init(builder.build())
          .then(function(flow) {
            authFlow = flow;
            return flow.login();
          })
          .then(function(flow) {
            return flow.getHeaders();
          })
          .then(function(headers) {
            mcsHeaders = headers;
            return window.TestUtil.xmlHttpRequestPromise(headers, window.TestConfig.basicMcs.securedUrl, true);
          })
          .then(function(result) {
            securedCallResult = result;
            return authFlow.logout(true);
          })
          .then(done)
          .catch(done);
      });

      it('verify secured resource was accessed.', function(done) {
        expect(mcsHeaders).toBeDefined();
        expect(mcsHeaders.Authorization).toBeDefined();
        expect(mcsHeaders.Authorization).toBe(window.TestConfig.basicMcs.header);
        expect(mcsHeaders['oracle-mobile-backend-id']).toBeDefined();
        expect(securedCallResult).toBeDefined();
        done();
      });
    });
  });
};