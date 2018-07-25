/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var doneRef, challenges, loginErr, defaultJasmineTimeout, authFlow, userName, password, error;

  var getBuilder = function() {
    return new idmAuthFlowPlugin.HttpBasicAuthPropertiesBuilder()
       .appName('JasmineJsTests')
       .loginUrl(window.TestConfig.basic.loginUrl)
       .logoutUrl(window.TestConfig.basic.logoutUrl)
       .challengeCallback(challengeCallback)
       .maxLoginAttempts(2)
       .offlineAuthAllowed(true);
  };

  var initFlow = function(authProps, done) {
    idmAuthFlowPlugin.init(authProps)
      .then(function(flow) {
        authFlow = flow;
        done();
      })
      .catch(done);
  };

  var resetTestCase = function() {
    challenges = [];
    userName = undefined;
    password = undefined;
  };

  var challengeCallback = function (fields, proceedHandler) {
    if (challenges.length == 4) {
      proceedHandler.cancel();
      return;
    }
    challenges.push(JSON.parse(JSON.stringify(fields)));
    fields.username_key = userName;
    fields.password_key = password;
    proceedHandler.submit(fields);
  };

  var login = function(done) {
    authFlow.login()
      .catch(function(er){
        loginErr = er;
        done();
      });
  };

  var verifyFlow = function(flow) {
    expect(flow).toBeDefined();
    expect(flow.login).toBeDefined();
    expect(flow.logout).toBeDefined();
    expect(flow.isAuthenticated).toBeDefined();
    expect(flow.getHeaders).toBeDefined();
    expect(flow.resetIdleTimeout).toBeDefined();
  };

  describe('Test HTTPBasicAuthentication flow', function() {
    beforeAll(function(done) {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
      initFlow(getBuilder().build(), done);
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });

    beforeEach(function(done){
      resetTestCase();
      done();
    });
    describe('init with no props', function() {
      beforeEach(function(done){
        idmAuthFlowPlugin.init()
          .catch(function(err) {
            error = err;
          })
          .then(done)
          .catch(done);
      });

      it('throws error.', function(done){
        window.TestUtil.verifyPluginError(error, 'P1005');
        done();
      });
    });

    describe('init with empty props', function() {
      beforeEach(function(done) {
        idmAuthFlowPlugin.init({})
          .catch(function(err) {
            error = err;
          })
          .then(done)
          .catch(done);
      });

      it('throws error.', function(done) {
        window.TestUtil.verifyPluginError(error, 'P1005');
        done();
      });
    });

    describe('init with incorrect props', function() {
      beforeEach(function(done){
        idmAuthFlowPlugin.init({a:'b'})
          .catch(function(err) {
            error = err;
          })
          .then(done)
          .catch(done);
      });

      it('throws error.', function(done) {
        window.TestUtil.verifyPluginError(error, 'P1005');
        done();
      });
    });

    describe('submit challenge without fields', function() {
      beforeEach(function(done) {
        var builder = getBuilder().challengeCallback(function(fields, proceedHandler) {
          proceedHandler();
        });
        idmAuthFlowPlugin.init(builder.build())
          .then(function(flow) {
            return flow.login();
          })
          .catch(function(err) {
            error = err;
          })
          .then(done)
          .catch(done);
      });

      it('throws error.', function(done) {
        window.TestUtil.verifyPluginError(error, 'P1006');
        done();
      });
    });
    describe('login with unset username and password', function() {
      beforeEach(function(done){
        userName = undefined;
        password = undefined;
        doneRef = done;
        login(done);
      });

      it('ignores max retrys and keeps throwing invalid username error until login is cancelled.', function(done){
        expect(challenges.length).toBe(4);
        // @ignore: Fails on iOS, Bug 28000459
        window.TestUtil.verifyPluginError(challenges[1].error, "10036");
        window.TestUtil.verifyPluginError(challenges[2].error, "10036");
        window.TestUtil.verifyPluginError(challenges[3].error, "10036");
        window.TestUtil.verifyPluginError(loginErr, "10029");
        done();
      });
    });
    describe('login with blank username and password', function() {
      beforeEach(function(done){
        userName = '';
        password = '';
        doneRef = done;
        login(done);
      });

      it('ignores max retrys and keeps throwing invalid username error until login is cancelled.', function(done){
        expect(challenges.length).toBe(4);
        // @ignore: Fails on iOS, Bug 28000459
        window.TestUtil.verifyPluginError(challenges[1].error, "10036");
        window.TestUtil.verifyPluginError(challenges[2].error, "10036");
        window.TestUtil.verifyPluginError(challenges[3].error, "10036");
        window.TestUtil.verifyPluginError(loginErr, "10029");
        done();
      });
    });
    describe('login with wrong username and password', function() {
      beforeEach(function(done){
        userName = 'invalid';
        password = 'invalid';
        login(done);
      });

      it('failed after max challenges', function(done){
        expect(challenges.length).toBe(2);
        // @ignore: Fails on iOS, Bug 28000459
        window.TestUtil.verifyPluginError(challenges[1].error, "10003");
        window.TestUtil.verifyPluginError(loginErr, "10418");
        done();
      });
    });

    describe('login with wrong cred and after max attempts, login again with correct cred',function() {
      var firstRoundChallenges, firstRoundChallengeErrors, firstRoundLoginErr;
      beforeEach(function(done) {
        userName = 'invalid';
        password = 'invalid';
        authFlow.login()
          .catch(function(er) {
            firstRoundLoginErr = er;
            firstRoundChallenges = challenges.slice();
            resetTestCase();
          })
          .then(function() {
            userName = window.TestConfig.basic.userName;
            password = window.TestConfig.basic.password;
            return authFlow.login();
          })
          .then(function(flow) {
            return flow.logout(true);
          })
          .then(done)
          .catch(done);
      });
      it('has all authenticated states correct and returns flows correctly.', function(done) {
        expect(firstRoundChallenges.length).toBe(2);
        window.TestUtil.verifyPluginError(firstRoundChallenges[1].error, "10003");
        window.TestUtil.verifyPluginError(firstRoundLoginErr, "10418");
        expect(challenges.length).toBe(1);
        done();
      });
    });


    describe('login, logout again login, logout',function() {
      var authBeforeLogin, authAfterLogin, authAfterLogout, authAfterRelogin, authAfterRelogout, flows = [];

      beforeEach(function(done) {
        userName = window.TestConfig.basic.userName;
        password = window.TestConfig.basic.password;
        authFlow.isAuthenticated()
          .then(function(auth) {
            authBeforeLogin = auth;
            return authFlow.login();
          })
          .then(function(flow) {
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth){
            authAfterLogin = auth;
            return authFlow.logout(true);
          })
          .then(function(flow){
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth) {
            authAfterLogout = auth;
            return authFlow.login();
          })
          .then(function(flow) {
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth){
            authAfterRelogin = auth;
            return authFlow.logout(true);
          })
          .then(function(flow){
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth) {
            authAfterRelogout = auth;
          })
          .then(done)
          .catch(done);
      });
      it('is allowed and has all authenticated states correct and returns flows correctly.', function(done) {
        expect(flows.length).toBe(4);
        for (var f in flows)
          verifyFlow(flows[f]);

        expect(authBeforeLogin).not.toBeTruthy();
        expect(authAfterLogin).toBeTruthy();
        expect(authAfterRelogin).toBeTruthy();
        expect(authAfterLogout).not.toBeTruthy();
        expect(authAfterRelogout).not.toBeTruthy();
        done();
      });
    });

    describe('login and again login',function() {
      var authBeforeLogin, authAfterLogin, authAfterRelogin, authAfterLogout, flows = [];
      beforeEach(function(done) {
        userName = window.TestConfig.basic.userName;
        password = window.TestConfig.basic.password;
        authFlow.isAuthenticated()
          .then(function(auth) {
            authBeforeLogin = auth;
            return authFlow.login();
          })
          .then(function(flow) {
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth){
            authAfterLogin = auth;
            return authFlow.login();
          })
          .then(function(flow){
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth) {
            authAfterRelogin = auth;
            return authFlow.logout(true);
          })
          .then(function(flow) {
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth){
            authAfterLogout = auth;
          })
          .then(done)
          .catch(done);
      });
      it('is allowed and has all authenticated states correct and returns flows correctly.', function(done) {
        expect(flows.length).toBe(3);
        for (var f in flows)
          verifyFlow(flows[f]);

        expect(authBeforeLogin).not.toBeTruthy();
        expect(authAfterLogin).toBeTruthy();
        expect(authAfterRelogin).toBeTruthy();
        expect(authAfterLogout).not.toBeTruthy();
        done();
      });
    });

    describe('login and logout and again logout',function() {
      var authBeforeLogin, authAfterLogin, authAfterLogout, authAfterRelogout, flows = [];
      beforeEach(function(done) {
        userName = window.TestConfig.basic.userName;
        password = window.TestConfig.basic.password;
        authFlow.isAuthenticated()
          .then(function(auth) {
            authBeforeLogin = auth;
            return authFlow.login();
          })
          .then(function(flow) {
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth){
            authAfterLogin = auth;
            return authFlow.logout();
          })
          .then(function(flow){
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth) {
            authAfterLogout = auth;
            return authFlow.logout(true);
          })
          .then(function(flow) {
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth){
            authAfterRelogout = auth;
          })
          .then(done)
          .catch(done);
      });
      it('is allowed and has all authenticated states correct and returns flows correctly.', function(done) {
        expect(flows.length).toBe(3);
        for (var f in flows)
          verifyFlow(flows[f]);

        expect(authBeforeLogin).not.toBeTruthy();
        expect(authAfterLogin).toBeTruthy();
        expect(authAfterLogout).not.toBeTruthy();
        expect(authAfterRelogout).not.toBeTruthy();
        done();
      });
    });

    describe('logout without login',function() {
      var authBeforeLogout, authAfterLogout, flows = [];
      beforeEach(function(done) {
        userName = window.TestConfig.basic.userName;
        password = window.TestConfig.basic.password;
        authFlow.isAuthenticated()
          .then(function(auth) {
            authBeforeLogout = auth;
            return authFlow.logout();
          })
          .then(function(flow) {
            flows.push(flow);
            return flow.isAuthenticated();
          })
          .then(function(auth){
            authAfterLogout = auth;
          })
          .then(done)
          .catch(done);
      });
      it('is allowed and has all authenticated states correct and returns flows correctly.', function(done) {
        expect(flows.length).toBe(1);
        for (var f in flows)
          verifyFlow(flows[f]);

        expect(authBeforeLogout).not.toBeTruthy();
        expect(authAfterLogout).not.toBeTruthy();
        done();
      });
    });

    describe('getHeaders without login and then with login and then after logout',function() {
      var errNoLogin, headersAfterLogin, errAfterLogout;
      beforeEach(function(done) {
        userName = window.TestConfig.basic.userName;
        password = window.TestConfig.basic.password;
        authFlow.getHeaders()
          .catch(function(er) {
            errNoLogin = er;
            return authFlow.login();
          })
          .then(function(flow) {
            return flow.getHeaders();
          })
          .then(function(headers){
            headersAfterLogin = headers;
            return authFlow.logout(true);
          })
          .then(function(flow) {
            return flow.getHeaders();
          })
          .catch(function(er) {
            errAfterLogout = er;
          })
          .then(done)
          .catch(done);
      });
      it('is not allowed and returns errors correctly.', function(done) {
        window.TestUtil.verifyPluginError(errNoLogin, 'P1010');
        expect(headersAfterLogin).toBeDefined();
        expect(headersAfterLogin.Authorization).toBeDefined();
        window.TestUtil.verifyPluginError(errAfterLogout, 'P1010');
        done();
      });
    });
  });
};
