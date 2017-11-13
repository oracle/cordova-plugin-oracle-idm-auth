/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
/*
  // This test is failing because of issue in IDM SDK.
  // Google based 3-legged OAUTH, to be run with external network.
  describe('Google OAUTH 3-legged', function () {
    var httpCallResult, authFlow, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    // Credentials - google login.
    beforeEach(function(done) {
      var authProps = idmAuthFlowPlugin.newOAuthPropertiesBuilder('JasmineJsTests',
          idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthAuthorizationCode,
          'https://accounts.google.com/o/oauth2/token',
          '1065955011866-nmlr61tf2kuj32q6c193enkrn3bvsktv.apps.googleusercontent.com')
        .oAuthAuthorizationEndpoint('https://accounts.google.com/o/oauth2/auth')
        .oAuthRedirectEndpoint('com.oraclecorp.internal.idm.plugin.demo:/')
        .oAuthScope(['https://www.googleapis.com/auth/userinfo.email',
                      'https://www.googleapis.com/auth/userinfo.profile'])
        .logoutURL('https://www.google.com/accounts/Logout')
        .browserMode(idmAuthFlowPlugin.BrowserMode.External)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function(flow) {
        flow.login().then(function(loginFlow) {
          loginFlow.getHeaders().then(function(headers) {
            var request = new XMLHttpRequest();
            request.open('GET', 'https://www.googleapis.com/oauth2/v1/userinfo');
            for (var key in headers)
            {
              if (headers.hasOwnProperty(key))
              {
                // console.log('setting header:: ' + key + ":" + headers[key]);
                request.setRequestHeader(key, headers[key]);
              }
            }
            request.onload = function()
            {
              if (request.readyState == 4)
              {
                httpCallResult = request.response;
              } else {
                httpCallResult = request.readyState;
              }
              // console.log('[OAuth 3-legged] makeRequest result: ' + httpCallResult);
              loginFlow.logout().then(done, done);
            };

            request.send();
          }, done);
        },done);
      }, done);
    });

    it('Login, make GET XHR request, logout and verify.', function(done) {
      expect(httpCallResult).toContain('adfview@gmail.com');
      done();
    });
  });
*/
  describe('OAuthAuthentication 2-legged', function () {
    var httpCallResult, authFlow, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var makeRequest = function()
      {
        authFlow.getHeaders().then(function(headers) {
          // console.log('[OAuth 2-legged] In makeRequest.');
          var request = new XMLHttpRequest();
          request.open('GET', 'http://slc09fdf.us.oracle.com:7777/mobile/custom/Greetings/sayhello');
          for (var key in headers)
          {
            if (headers.hasOwnProperty(key))
            {
              // console.log('setting header:: ' + key + ":" + headers[key]);
              request.setRequestHeader(key, headers[key]);
            }
          }

          request.onload = function()
          {
            if (request.readyState == 4)
            {
              httpCallResult = request.response;
            } else {
              httpCallResult = request.readyState;
            }
            // console.log('[OAuth 2-legged] makeRequest result: ' + httpCallResult);
            authFlow.logout().then(done, done);
          };
          request.send();
        }, done);
      };
      var challengeCallback = function(fields, proceed)
      {
        // console.log('Challenge is: ' + JSON.stringify(fields));
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'hcr';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1*';
        // console.log('Filled challenge is: ' + JSON.stringify(fields));
        proceed(fields);
      };
        var authProps = idmAuthFlowPlugin.newOAuthPropertiesBuilder('JasmineJsTests',
          idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
          'http://den00ozt.us.oracle.com:14100/oam/oauth2/tokens',
          '02775b62-6709-42a8-aea1-58ca86243704')
        .oAuthClientSecret('tvwCbJMkTmNquOQSbnC6')
        .customAuthHeaders({'X-User-Identity-Domain-Name': 'yoda'})
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[OAuth 2-legged] initCallback executed: ' + JSON.stringify(flow));
        authFlow = flow;
        flow.login(challengeCallback).then(function (resp) {
          // console.log('[OAuth 2-legged] loginCallback executed: ' + JSON.stringify(resp));
          makeRequest();
        }, done);
      }, done);
    });

    it('Login, make GET XHR request, logout and verify.', function(done) {
      // console.log('[OAuth 2-legged] verify results.');
      expect(authFlow).toBeDefined();
      expect(httpCallResult).toBeDefined();
      expect(httpCallResult).toContain('Hello');
      done();
    });
  });

};