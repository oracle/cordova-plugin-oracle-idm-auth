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
          '{{oauth3leg.tokenUrl}}',
          '{{oauth3leg.clientId}}')
        .oAuthAuthorizationEndpoint('{{oauth3leg.authEndPoint}}')
        .oAuthRedirectEndpoint('{{oauth3leg.redirectUrl}}')
        .oAuthScope(['{{oauth3leg.scope1}}',
                      '{{oauth3leg.scope2}}'])
        .logoutURL('{{oauth3leg.logoutUrl}')
        .browserMode(idmAuthFlowPlugin.BrowserMode.External)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function(flow) {
        flow.login().then(function(loginFlow) {
          loginFlow.getHeaders().then(function(headers) {
            var request = new XMLHttpRequest();
            request.open('GET', '{{oauth3leg.securedUrl}');
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
          request.open('GET', '{{oauth.securedUrl}}');
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
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = '{{basicMcs.userName}}';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = '{{basicMcs.password}}';
        // console.log('Filled challenge is: ' + JSON.stringify(fields));
        proceed(fields);
      };
        var authProps = idmAuthFlowPlugin.newOAuthPropertiesBuilder('JasmineJsTests',
          idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
          '{{oauth.tokenUrl}}',
          '{{oauth.clientId}}')
        .oAuthClientSecret('{{oauth.secret}}')
        .customAuthHeaders({'X-User-Identity-Domain-Name': '{{oauth.domainName}}'})
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