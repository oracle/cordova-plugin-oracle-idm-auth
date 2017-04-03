/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  /*
  // This test is failing because of issue in IDM SDK.
  // Google based 3-legged OAUTH, to be run with external network.
  describe('OAuthAuthentication 3-legged', function () {
    var httpCallResult, authFlow, defaultJasmineTimeout, isOnline = false;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    // Credentials - google login.
    beforeEach(function(done) {
      if (cordova.platformId == 'ios') {
        var authProps = idmAuthFlowPlugin.newOAuthPropertiesBuilder('JasmineJsTests',
            idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthAuthorizationCode,
            'https://accounts.google.com/o/oauth2/token',
            '85748304627.apps.googleusercontent.com')
          .oAuthAuthorizationEndpoint('https://accounts.google.com/o/oauth2/auth')
          .oAuthRedirectEndpoint('http://localhost')
          .oAuthScope(['https://www.googleapis.com/auth/userinfo.email',
                        'https://www.googleapis.com/auth/userinfo.profile'])
          .logoutURL('https://www.google.com/accounts/Logout')
          .put('BrowserMode', 'Embedded')
          .build();
        idmAuthFlowPlugin.init(authProps).then(function(flow){
          flow.login().then(function(loginFlow) {
            loginFlow.getHeaders().then(function(headers) {
              var request = new XMLHttpRequest();
              request.open('GET', 'https://www.googleapis.com/oauth2/v1/userinfo');
              var tokenValue = headers.oauth_access_token1.value;
              request.setRequestHeader('Authorization', 'Bearer ' + tokenValue);

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
      } else {
        done();
      }
    });
  
    it('Login, make GET XHR request, logout and verify.', function(done) {
      if (cordova.platformId == 'ios') {
        expect(httpCallResult).toContain('adfview@gmail.com');
      }
      done();
    });
  }); 
  // OAUTH setup is not valid now.
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
          request.open('GET', 'http://slc09fdf.us.oracle.com:7201/mobile/custom/Greetings/sayhello');
          var tokenValue = headers.oauth_access_token1.value;
          request.setRequestHeader('Authorization', 'Bearer ' + tokenValue);

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
          'http://slc09kia.us.oracle.com:14100/oam/oauth2/tokens',
          'cbcfad96-2b6e-47ca-b2eb-89cf170f7a2b')
        .oAuthClientSecret('VuRlCGAJXSxJsBaycgh7')
        .customAuthHeaders({'X-User-Identity-Domain-Name': 'bender'})
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
      expect(httpCallResult).toContain('Hello');
      done();
    });
  });
  */
};