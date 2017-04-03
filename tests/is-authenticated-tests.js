/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('idmAuthFlowPlugin.isAuthenticated', function () {
    var isAuth, isAuthAfterLogout, isAuthLoginLogoutLogin;
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1';
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        flow.login(challengeCallback).then(function (loginRespFlow) {
          // console.log('[isAuthenticated] BA Login success.');
          loginRespFlow.isAuthenticated().then(function (resp) {
            // console.log('[isAuthenticated] BA isAuthenticated after login: ' + resp);
            isAuth = resp;
            loginRespFlow.logout().then(function (logoutRespFlow) {
              // console.log('[isAuthenticated] BA logout.');
              logoutRespFlow.isAuthenticated().then(function (resp) {
                // console.log('[isAuthenticated] BA isAuthenticated after logout: ' + resp);
                isAuthAfterLogout = resp;
                logoutRespFlow.login(challengeCallback).then(function(loginRespFlow2) {
                  loginRespFlow2.isAuthenticated().then(function(resp) {
                    isAuthLoginLogoutLogin = resp;
                    loginRespFlow2.logout().then(done, done);
                  }, done);
                }, done);
              }, done);
            }, done);
          }, done);
        }, done);
      }, done);
    });
    it('login using HttpBasicAuthentication and verify is authenticated, logout and verify not authenticated, login again verify authenticated and logout.',
      function(done) {
        expect(isAuth).toBe(true);
        expect(isAuthAfterLogout).toBe(false);
        expect(isAuthLoginLogoutLogin).toBe(true);
        done();
      }
    );
  });
  describe('idmAuthFlowPlugin.isAuthenticated', function () {
    var isAuth, isAuthAfterLogout, headers;
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1';
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .offlineAuthAllowed(true)
        .customAuthHeaders({a: 'b'})
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        flow.login(challengeCallback).then(function (loginRespFlow) {
          // console.log('[isAuthenticated] BAH Login success.');
          loginRespFlow.isAuthenticated().then(function (resp) {
            // console.log('[isAuthenticated] BAH isAuthenticated after login: ' + resp);
            isAuth = resp;
            loginRespFlow.getHeaders().then(function(heads) {
              // console.log('[isAuthenticated] BAH getHeaders success: ' + JSON.stringify(heads));
              headers = heads;
              loginRespFlow.logout().then(function(logoutRespFlow) {
                // console.log('[isAuthenticated] BAH logout.');
                logoutRespFlow.isAuthenticated().then(function(resp) {
                  // console.log('[isAuthenticated] BAH isAuthenticated after logout: ' + resp);
                  isAuthAfterLogout = resp;
                  done();
                }, done);
              }, done);
            }, done);
          }, done);
        }, done);
      }, done);
    });
    it('login using HttpBasicAuthentication with headers and verify is authenticated.', function(done) {
      expect(isAuth).toBe(true);
      expect(isAuthAfterLogout).toBe(false);
      expect(headers).toBeDefined();
      expect(headers.a).toBe('b');
      expect(headers.Authorization).toBeDefined();
      done();
    });
  });
  /*
  // OAUTH setup is invalid now.
  describe('idmAuthFlowPlugin.isAuthenticated', function () {
    var isAuth, isAuthAfterLogout, headers;
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'hcr';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1*';
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newOAuthPropertiesBuilder('JasmineJsTests',
          idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthResourceOwner,
          'http://slc09kia.us.oracle.com:14100/oam/oauth2/tokens',
          'cbcfad96-2b6e-47ca-b2eb-89cf170f7a2b')
        .oAuthClientSecret('VuRlCGAJXSxJsBaycgh7')
        .customAuthHeaders({'X-User-Identity-Domain-Name': 'bender'})
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        flow.login(challengeCallback).then(function (loginFlow) {
          // console.log('[isAuthenticated] OAUTH Login success.');
          loginFlow.isAuthenticated().then(function (resp) {
            // console.log('[isAuthenticated] OAUTH isAuthenticated after Login: ' + resp);
            isAuth = resp;
            loginFlow.getHeaders().then(function(heads) {
              // console.log('[isAuthenticated] OAUTH getHeaders: ' + JSON.stringify(heads));
              headers = heads;
              loginFlow.logout().then(function(logoutRespFlow) {
                // console.log('[isAuthenticated] OAUTH logout.');
                logoutRespFlow.isAuthenticated().then(function(resp) {
                  // console.log('[isAuthenticated] OAUTH isAuthenticated after logout: ' + resp);
                  isAuthAfterLogout = resp;
                  done();
                }, done);
              }, done);
            }, done);
          }, done);
        }, done);
      }, done);
    });
    it('login using OAuth and verify is authenticated, headers.', function(done) {
      expect(isAuth).toBe(true);
      expect(isAuthAfterLogout).toBe(false);
      expect(headers).toBeDefined();
      expect(headers.oauth_access_token1).toBeDefined();

      // TODO: Android returns expires, iOS returns expiryDate.
      // expect(headers.oauth_access_token1.expiryDate).toBeDefined();
      // expect(headers.oauth_access_token1.expires).toBeDefined();

      expect(headers.oauth_access_token1.value).toBeDefined();
      expect(headers.oauth_access_token1.name).toBeDefined();
      done();
    });
  });
  */
};