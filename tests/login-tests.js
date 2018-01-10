/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('idmAuthFlowPlugin.login', function () {
    var challengeCount = 0, loginErr, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        if (challengeCount++ == 2) {
          done();
          return;
        }
        // console.log('[Login] Challenge count: ' + challengeCount);
        loginErr = fields[idmAuthFlowPlugin.AuthChallenge.Error];
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          '{{basic.loginUrl}}',
          '{{basic.logoutUrl}}')
        .maxLoginAttempts(2)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[Login] init callback: ' + JSON.stringify(flow));
        flow.login(challengeCallback).then(function(resp) {
          loginResult = resp;
          done();
        }, done);
      }, done);
    });
    it('without user name and password', function(done) {
      // console.log('[Login] Login challenge error: ' + JSON.stringify(loginErr));
      expect(loginErr).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10003");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);
      done();
    });
  });
  describe('idmAuthFlowPlugin.login', function () {
    var challengeCount = 0, loginErr, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        if (challengeCount++ == 2) {
          done();
          return;
        }
        // console.log('[Login] Challenge count: ' + challengeCount);
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = '';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = '';
        loginErr = fields[idmAuthFlowPlugin.AuthChallenge.Error];
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          '{{basic.loginUrl}}',
          '{{basic.logoutUrl}}')
        .maxLoginAttempts(2)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[Login] init callback: ' + JSON.stringify(flow));
        flow.login(challengeCallback).then(function(resp) {
          loginResult = resp;
          done();
        }, done);
      }, done);
    });
    it('without blank user name and password', function(done) {
      // console.log('[Login] Login error: ' + JSON.stringify(loginResult));
      // console.log('[Login] Login challenge error: ' + JSON.stringify(loginErr));
      expect(loginErr).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10003");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);
      done();
    });
  });
  describe('idmAuthFlowPlugin.login', function () {
    var loginResult, challengeCount = 0, loginErr, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        challengeCount++;
        // console.log('[Login] Challenge count: ' + challengeCount);
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'Wrong';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = '{{basic.password}}';
        loginErr = fields[idmAuthFlowPlugin.AuthChallenge.Error];
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          '{{basic.loginUrl}}',
          '{{basic.logoutUrl}}')
        .maxLoginAttempts(2)
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[Login] init callback: ' + JSON.stringify(flow));
        flow.login(challengeCallback).then(function(resp) {
          loginResult = resp;
          done();
        }).catch(function(err) {
          // console.log('[Login] err: ' + JSON.stringify(err));
          loginResult = err;
          done();
        });
      }, done);
    });
    it('with wrong user name.', function(done) {
      // console.log('[Login] Login error: ' + JSON.stringify(loginResult));
      // console.log('[Login] Login challenge error: ' + JSON.stringify(loginErr));
      expect(loginResult).toBeDefined();
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(loginResult[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10418");
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);

      expect(loginErr).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10003");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);

      expect(challengeCount).toBe(2);
      done();
    });
  });
  describe('idmAuthFlowPlugin.login', function () {
    var loginResult, challengeCount = 0, loginErr, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
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
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = '{{basic.userName}}';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Wrong';
        loginErr = fields[idmAuthFlowPlugin.AuthChallenge.Error];
        // console.log('[Login] wrong pwd challenge filled and proceed: ' + JSON.stringify(fields));
        proceedHandler(fields);
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          '{{basic.loginUrl}}',
          '{{basic.logoutUrl}}')
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
      // console.log('[Login] wrong pwd Login error: ' + JSON.stringify(loginResult));
      // console.log('[Login] wrong pwd Login challenge error: ' + JSON.stringify(loginErr));
      expect(loginResult).toBeDefined();
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(loginResult[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10418");
      expect(loginResult[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);

      expect(loginErr).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(loginErr[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10003");
      expect(loginErr[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);

      expect(challengeCount).toBe(2);
      done();
    });
  });
  describe('idmAuthFlowPlugin.login', function () {
    var loginResult, logoutResult, attempt = 0, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        if (attempt === 0)
        {
          // console.log('[Login] First login with wrong cred.' + JSON.stringify(fields))
          attempt++;
          fields[idmAuthFlowPlugin.AuthChallenge.UserName] = '{{basic.userName}}';
          fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Wrong';
          proceedHandler(fields);
        }
        else
        {
          // console.log('[Login] Second login with right cred: ' + JSON.stringify(fields));
          fields[idmAuthFlowPlugin.AuthChallenge.UserName] = '{{basic.userName}}';
          fields[idmAuthFlowPlugin.AuthChallenge.Password] = '{{basic.password}}';
          proceedHandler(fields);
        }
      };
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
          '{{basic.loginUrl}}',
          '{{basic.logoutUrl}}')
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
    var loginResp, loginLogoutLoginResp, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
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
    var loginResp, loginLoginResp, defaultJasmineTimeout;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
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
