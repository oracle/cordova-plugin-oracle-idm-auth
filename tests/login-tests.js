/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('idmAuthFlowPlugin.login', function () {
    var loginResult, challengeCount = 0, loginErr;
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        challengeCount++;
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu1';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1';
        loginErr = fields[idmAuthFlowPlugin.AuthChallenge.ErrorCode];
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .maxLoginAttempts(2)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[Login] init callback: ' + JSON.stringify(flow));
        flow.login(challengeCallback).then(function(resp) {
          loginResult = resp;
          done();
        }).catch(function(err) {
          loginResult = err;
          done();
        });
      }, done);
    });
    it('with wrong user name.', function(done) {
      expect(loginResult).toBeDefined();
      expect(loginResult).toBe('10418');
      expect(loginErr).toBeDefined();
      expect(loginErr).toBe('10003');
      expect(challengeCount).toBe(2);
      done();
    });
  });
  describe('idmAuthFlowPlugin.login', function () {
    var loginResult, challengeCount = 0, loginErr;
    beforeEach(function(done) {
      var errCallback = function (resp) {
       // console.log('[Login] wrong pwd err: ' + JSON.stringify(resp));
       loginResult = resp;
        done();
      };
      var loginCallback = function (resp) {
        done();
      };
      var challengeCallback = function (fields, proceedHandler) {
        challengeCount++;
        // console.log('[Login] wrong pwd challenge: ' + JSON.stringify(fields));
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcom';
        loginErr = fields[idmAuthFlowPlugin.AuthChallenge.ErrorCode];
        // console.log('[Login] wrong pwd challenge filled and proceed: ' + JSON.stringify(fields));
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .maxLoginAttempts(2)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[Login] init callback: ' + JSON.stringify(flow));
        flow.login(challengeCallback).then(function(resp) {
          loginResult = resp;
          done();
        }).catch(function(err) {
          loginResult = err;
          done();
        });
      }, done);
    });
    it('with wrong password.', function(done) {
      // console.log('[Login] wrong pwd before compare: ' + JSON.stringify(loginResult));
      expect(loginResult).toBeDefined();
      expect(loginResult).toBe('10418');
      expect(loginErr).toBeDefined();
      expect(loginErr).toBe('10003');
      expect(challengeCount).toBe(2);
      done();
    });
  });
  describe('idmAuthFlowPlugin.login', function () {
    var loginResult, logoutResult, attempt = 0;
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        if (attempt === 0)
        {
          // console.log('[Login] First login with wrong cred.' + JSON.stringify(fields))
          attempt++;
          fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu';
          fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcom';
          proceedHandler(fields);
        }
        else
        {
          // console.log('[Login] Second login with right cred: ' + JSON.stringify(fields));
          fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu';
          fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1';
          proceedHandler(fields);
        }
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .maxLoginAttempts(2)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[Login] init callback: ' + JSON.stringify(flow));
        flow.login(challengeCallback).then(function (resp) {
          // console.log('[Login] Valid login login callback: ' + JSON.stringify(resp));
          loginResult = resp;
          flow.logout().then(function (res) {
            logoutResult = res;
            done();
          }, done);
        }, done);
      }, done);
    });
    it('with wrong credentials and then upon challenge provide correct credentials.', function(done) {
      expect(loginResult).toBeDefined();
      expect(loginResult.login).toBeDefined();
      expect(loginResult.logout).toBeDefined();
      expect(loginResult.isAuthenticated).toBeDefined();
      expect(loginResult.getHeaders).toBeDefined();
      expect(loginResult.resetIdleTimeout).toBeDefined();
      expect(attempt).toBe(1);
      expect(logoutResult).toBeDefined();
      expect(logoutResult.login).toBeDefined();
      expect(logoutResult.logout).toBeDefined();
      expect(logoutResult.isAuthenticated).toBeDefined();
      expect(logoutResult.getHeaders).toBeDefined();
      expect(logoutResult.resetIdleTimeout).toBeDefined();
      done();
    });
  });

  describe('idmAuthFlowPlugin.login', function () {
    var loginResp, loginLogoutLoginResp;
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
          loginResp = loginRespFlow;
          loginRespFlow.logout().then(function(logoutFlow){
            logoutFlow.login(challengeCallback).then(function(loginFlow2){
              loginLogoutLoginResp = loginFlow2;
              loginFlow2.logout().then(done, done);
            }, done);
          }, done);
        }, done);
      }, done);
    });
    it('login using HttpBasicAuthentication, logout, login again and logout.',
      function(done) {
        expect(loginResp).toBeDefined();
        expect(loginResp.login).toBeDefined();
        expect(loginResp.logout).toBeDefined();
        expect(loginResp.isAuthenticated).toBeDefined();
        expect(loginResp.getHeaders).toBeDefined();
        expect(loginResp.resetIdleTimeout).toBeDefined();
        expect(loginLogoutLoginResp).toBeDefined();
        expect(loginLogoutLoginResp.login).toBeDefined();
        expect(loginLogoutLoginResp.logout).toBeDefined();
        expect(loginLogoutLoginResp.isAuthenticated).toBeDefined();
        expect(loginLogoutLoginResp.getHeaders).toBeDefined();
        expect(loginLogoutLoginResp.resetIdleTimeout).toBeDefined();
        done();
      }
    );
  });
  describe('idmAuthFlowPlugin.login', function () {
    var loginResp, loginLoginResp;
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
          loginResp = loginRespFlow;
          loginRespFlow.login(challengeCallback).then(function(loginFlow2){
            loginLoginResp = loginFlow2;
            loginFlow2.logout().then(done, done);
          }, done);
        }, done);
      }, done);
    });
    it('login using HttpBasicAuthentication, and again login.',
      function(done) {
        expect(loginResp).toBeDefined();
        expect(loginResp.login).toBeDefined();
        expect(loginResp.logout).toBeDefined();
        expect(loginResp.isAuthenticated).toBeDefined();
        expect(loginResp.getHeaders).toBeDefined();
        expect(loginResp.resetIdleTimeout).toBeDefined();
        expect(loginLoginResp).toBeDefined();
        expect(loginLoginResp.login).toBeDefined();
        expect(loginLoginResp.logout).toBeDefined();
        expect(loginLoginResp.isAuthenticated).toBeDefined();
        expect(loginLoginResp.getHeaders).toBeDefined();
        expect(loginLoginResp.resetIdleTimeout).toBeDefined();
        done();
      }
    );
  });
};
