/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function () {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('idmAuthFlowPlugin.logout', function () {
    var logoutFlow;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = '{{basic.userName}}';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = '{{basic.password}}';
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          '{{basic.loginUrl}}',
          '{{basic.logoutUrl}}')
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        flow.login(challengeCallback).then(function (loginRespFlow) {
          flow.logout().then(function (logoutRespFlow) {
            logoutFlow = logoutRespFlow;
            done();
          }, done);
        }, done);
      }, done);
    });
    it('login and logout.', function(done) {
      expect(logoutFlow).toBeDefined();
      expect(logoutFlow.login).toBeDefined();
      expect(logoutFlow.logout).toBeDefined();
      expect(logoutFlow.isAuthenticated).toBeDefined();
      expect(logoutFlow.getHeaders).toBeDefined();
      expect(logoutFlow.resetIdleTimeout).toBeDefined();
      done();
    });
  });

  // This test has issues with iOS.
  // Looks like newOMMSS -> Login -> Logout -> newOMMSS -> Logout -> newOMMSS -> Login breaks.
  describe('idmAuthFlowPlugin.logout', function () {
    var logoutResult;
    beforeEach(function(done) {
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          '{{basic.loginUrl}}',
          '{{basic.logoutUrl}}')
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        flow.logout().then(function (logoutRespFlow) {
          // console.log('[logout] Logout succ: ' + logoutRespFlow);
          logoutResult = logoutRespFlow;
          done();
        }, done);
      }, done);
    });
    it('logout without login.', function(done) {
      expect(logoutResult).toBeDefined();
      expect(logoutResult.login).toBeDefined();
      expect(logoutResult.logout).toBeDefined();
      expect(logoutResult.isAuthenticated).toBeDefined();
      expect(logoutResult.getHeaders).toBeDefined();
      expect(logoutResult.resetIdleTimeout).toBeDefined();
      done();
    });
  });
};