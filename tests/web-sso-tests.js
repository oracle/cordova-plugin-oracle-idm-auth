/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
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
          flow.getHeaders('http://den00beu.us.oracle.com:7777/index.html').then(function(h) {
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

            request.open('GET', 'http://den00beu.us.oracle.com:7777/index.html');
            request.send();
          }, done);
        }, done);
      };

      // Credential - weblogic/welcome1
      var authProps = idmAuthFlowPlugin.newFedAuthPropertiesBuilder('JasmineJsTests',
            'http://den00beu.us.oracle.com:7777/fed_auth.html',
            'http://den00beu.us.oracle.com:7777/oam/server/logout',
            'http://den00beu.us.oracle.com:7777/fed_success.html',
            'http://den00beu.us.oracle.com:7777/fed_failure.html')
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