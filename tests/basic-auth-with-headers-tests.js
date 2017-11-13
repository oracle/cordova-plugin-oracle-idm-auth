/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  describe('HTTPBasicAuthentication with headers test.', function () {
    var httpCallResult, authFlow, loginRespFlow, logoutRespFlow, defaultJasmineTimeout, headers, isAuth;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var makeBasicHttpRequest = function()
      {
        var request = new XMLHttpRequest();
        request.withCredentials = true;
        request.open('GET', 'http://slc09fdf.us.oracle.com:7777/mobile/custom/Greetings/sayhello');
        for (var key in headers)
        {
          if (headers.hasOwnProperty(key))
          {
            // console.log('[BAMCS] In makeBasicHttpRequest, setting header: ' + key);
            request.setRequestHeader(key, headers[key]);
          }
        }
        request.onload = function()
        {
          // console.log("[BAMCS] makeBasicHttpRequest request.onload invoked.request.readyState: " + request.response);
          if (request.readyState == 4) {
            httpCallResult = request.response;
          } else {
            httpCallResult = request.readyState;
          }
          // console.log("[BAMCS] makeBasicHttpRequest result: " + JSON.stringify(httpCallResult));
          authFlow.logout().then(function(logoutFlow) {
            // console.log("[BAMCS] logout success: " +  JSON.stringify(logoutFlow));
            logoutRespFlow = logoutFlow;
            done();
          }, done);
        };

        // console.log("[BAMCS] makeBasicHttpRequest sending request.");
        request.send();
      };

      var challengeCallback = function (fields, proceedHandler) {
        // console.log('[BAMCS] challengeCallback executed: ' + JSON.stringify(fields));
        startloginRespFlow = fields;
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'hcr';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1*';
        proceedHandler(fields);
      };

      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          'http://slc09fdf.us.oracle.com:7777/mobile/platform/users/login',
          'http://slc09fdf.us.oracle.com:7777/mobile/platform/users/logout')
        .customAuthHeaders({"oracle-mobile-backend-id": "db5f6e86-184e-4b19-8c68-dfd9206dbe98"})
        .offlineAuthAllowed(true)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[BAMCS] init complete: ' + JSON.stringify(flow));
        authFlow = flow;
        flow.login(challengeCallback).then(function (loginR) {
          // console.log('[BAMCS] login complete: ' + JSON.stringify(loginR));
          loginRespFlow = loginR;
          loginRespFlow.isAuthenticated().then(function (authRes) {
            // console.log("[BAMCS] isAuthenticated complete: " + JSON.stringify(authRes));
            isAuth = authRes;
            if (!isAuth) {
              // console.log("[BAMCS] isAuthenticated is false. Failure.");
            }
            loginRespFlow.getHeaders().then(function(heads) {
              // console.log("[BAMCS] getHeaders: " + JSON.stringify(heads));
              headers = heads;
              makeBasicHttpRequest();
            }, done);
          }, done);
        }, done);
      }, done);
    });

    it('Make a request and verify result.', function(done) {
      expect(authFlow).toBeDefined();
      expect(authFlow.login).toBeDefined();
      expect(authFlow.logout).toBeDefined();
      expect(authFlow.getHeaders).toBeDefined();
      expect(authFlow.isAuthenticated).toBeDefined();
      expect(authFlow.resetIdleTimeout).toBeDefined();
      expect(loginRespFlow).toBeDefined();
      expect(loginRespFlow.login).toBeDefined();
      expect(loginRespFlow.logout).toBeDefined();
      expect(loginRespFlow.getHeaders).toBeDefined();
      expect(loginRespFlow.isAuthenticated).toBeDefined();
      expect(loginRespFlow.resetIdleTimeout).toBeDefined();
      expect(isAuth).toBe(true);
      expect(headers).toBeDefined();
      expect(headers.Authorization).toBeDefined();
      expect(headers['oracle-mobile-backend-id']).toBeDefined();
      expect(httpCallResult).toBeDefined();
      expect(logoutRespFlow).toBeDefined();
      expect(logoutRespFlow.login).toBeDefined();
      expect(logoutRespFlow.logout).toBeDefined();
      expect(logoutRespFlow.getHeaders).toBeDefined();
      expect(logoutRespFlow.isAuthenticated).toBeDefined();
      expect(logoutRespFlow.resetIdleTimeout).toBeDefined();
      done();
    });
  });
};