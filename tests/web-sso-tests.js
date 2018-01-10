/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('FederatedAuthentication', function () {
    var httpCallResult, defaultJasmineTimeout, headers;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var initCallback = function (flow) {
        // console.log('[SSO] initCallback executed: ' + flow);
        flow.login().then(function(loginRespFlow) {

          // console.log('[SSO]  Login complete.');
          flow.getHeaders('{{websso.securedUrl}}').then(function(h) {
            headers = h;
            // console.log('[SSO] In makeRequest: headers: ' + JSON.stringify(headers));
            var request = new XMLHttpRequest();
            request.onload = function() {
              if (request.readyState == 4) {
                httpCallResult = request.response;
              } else {
                httpCallResult = request.readyState;
              }
              // console.log('[SSO] makeRequest result: ' + httpCallResult);
              flow.logout().then(done, done);
            };

            request.open('GET', '{{websso.securedUrl}}');
            request.send();
          }, done);
        }, done);
      };

      var authProps = idmAuthFlowPlugin.newFedAuthPropertiesBuilder('JasmineJsTests',
            '{{websso.loginUrl}}',
            '{{websso.logoutUrl}}',
            '{{websso.loginSuccessUrl}}',
            '{{websso.loginFailureUrl}}')
        .build();
      idmAuthFlowPlugin.init(authProps).then(initCallback, done);
    });

    it('login, invoke a GET XHR request and logout.', function(done) {
      expect(httpCallResult).toContain('Hello World');
      expect(headers).toBeDefined();
      expect(headers.cookies).toBeDefined();
      done();
    });
  });
};
