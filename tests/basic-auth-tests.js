/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('HTTPBasicAuthentication test.', function () {
    var httpCallResult, authFlow, loginResFlow, logoutResFlow, defaultJasmineTimeout, basicHeaders;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        // user login page.
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1';
        // console.log('[BA] challengeCallback executed: ' + JSON.stringify(fields));
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .offlineAuthAllowed(true)
        .build();
      // console.log('[BA] auth props: ' + JSON.stringify(authProps));
      idmAuthFlowPlugin.init(authProps).then(function(flow) {
        // console.log('[BA] initCallback executed: ' + JSON.stringify(flow));
        authFlow = flow;
        flow.login(challengeCallback).then(function(logFlow) {
          // console.log('[BA] loginCallback executed: ' + JSON.stringify(logFlow));
          loginResFlow = logFlow;
          flow.getHeaders().then(function(headers) {
            basicHeaders = headers;
            // console.log('[BA] getHeaders executed: ' + JSON.stringify(basicHeaders));
            var request = new XMLHttpRequest();
            request.open('GET', 'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo/invokeEcho/HTTPBasicAuthentication');

            for (var key in basicHeaders)
            {
              if (headers.hasOwnProperty(key))
              {
                request.setRequestHeader(key, headers[key]);
              }
            }

            request.onload = function()
            {
              // console.log('[BA] makeBasicHttpRequest executed.');
              if (request.readyState == 4) {
                httpCallResult = request.response;
              } else {
                httpCallResult = request.readyState;
              }
              // console.log('[BA] makeBasicHttpRequest result: ' + httpCallResult);
              logFlow.logout().then(function(resp) {
                logoutResFlow = resp;
                // console.log('[BA] logout success.');
                done();
              }, done);
            };
            request.send();
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
      expect(loginResFlow).toBeDefined();
      expect(loginResFlow.login).toBeDefined();
      expect(loginResFlow.logout).toBeDefined();
      expect(loginResFlow.getHeaders).toBeDefined();
      expect(loginResFlow.isAuthenticated).toBeDefined();
      expect(loginResFlow.resetIdleTimeout).toBeDefined();
      expect(basicHeaders).toBeDefined();
      expect(basicHeaders.Authorization).toBeDefined();
      expect(httpCallResult).toContain('HTTPBasicAuthentication');
      expect(logoutResFlow).toBeDefined();
      expect(logoutResFlow.login).toBeDefined();
      expect(logoutResFlow.logout).toBeDefined();
      expect(logoutResFlow.getHeaders).toBeDefined();
      expect(logoutResFlow.isAuthenticated).toBeDefined();
      expect(logoutResFlow.resetIdleTimeout).toBeDefined();
      done();
    });
  });
};