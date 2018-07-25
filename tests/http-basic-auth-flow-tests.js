/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var Builder = idmAuthFlowPlugin.HttpBasicAuthPropertiesBuilder;
  var TimeoutTypeEnum = idmAuthFlowPlugin.RemoteAuthPropertiesBuilder.TimeoutType;
  var defaultJasmineTimeout, authFlow, rememberedUser, rememberedPass, logoutTry = 0;
  var timeoutResps, challenges;
  var isAuthBeforeLogin, isAuthAfterLogin, isAuthAfterLogout;
  var validUserName = window.TestConfig.basic.userName;
  var validPassword = window.TestConfig.basic.password;
  var rememberedPassword = "********";
  var securedResource = window.TestConfig.basic.securedUrl;

  var challengeCallback = function (fields, proceedHandler) {
    challenges.push(JSON.parse(JSON.stringify(fields)));
    rememberedUser = fields.username_key;
    rememberedPass = fields.password_key;
    if (!rememberedUser)
      fields.username_key = validUserName;
    if (!rememberedPass)
      fields.password_key = validPassword;
    proceedHandler(fields);
  };

  var timeoutCallback = function(timeoutResp) {
    timeoutResps.push(timeoutResp);
    if (Number(timeoutResp.TimeLeftToTimeout) === 0)
      loginXhrAndLogoutWithPurging(true);
  };

  var getBuilder = function() {
    return new Builder()
      .appName('JasmineJsTests')
      .loginUrl(window.TestConfig.basic.loginUrl)
      .logoutUrl(window.TestConfig.basic.logoutUrl)
      .challengeCallback(challengeCallback)
      .offlineAuthAllowed(true);
  };

  var resetTestCase = function() {
    basicHeaders = undefined;
    httpCallResult = undefined;
    rememberedUser = undefined;
    rememberedPass = undefined;
    isAuthBeforeLogin = undefined;
    isAuthAfterLogin = undefined;
    isAuthAfterLogout = undefined;
    timeoutInvoked = undefined;
    timeoutType = undefined;
    timeoutResps = [];
  };

  var resetTestSuite = function() {
    logoutTry = 0;
    challenges = [];
  };

  var initFlow = function(authProps) {
    idmAuthFlowPlugin.init(authProps).then(function(flow) {
      authFlow = flow;
      doneRef();
    }).catch(doneRef);
  };

  var loginXhrAndLogout = function() {
    loginXhrAndLogoutWithPurging(++logoutTry >= 2);
  };

  var loginXhrAndLogoutWithPurging = function(purge) {
    // No parameter call will default to purging.
    if (purge === undefined)
      purge = true;

    authFlow.isAuthenticated()
      .then(function(auth){
        isAuthBeforeLogin = auth;
        return authFlow.login();
      })
      .then(function(flow) {
        return authFlow.isAuthenticated();
      })
      .then(function(auth){
        isAuthAfterLogin = auth;
        return  authFlow.getHeaders();
      })
      .then(function(headers){
         basicHeaders = headers;
         return window.TestUtil.xmlHttpRequestPromise(headers, securedResource);
      })
      .then(function(result) {
        httpCallResult = result;
        return authFlow.logout(purge);
      })
      .then(function(flow) {
        return authFlow.isAuthenticated();
      })
      .then(function(auth){
        isAuthAfterLogout = auth;
      })
      .then(doneRef)
      .catch(doneRef);
  };

  var loginAndWaitForTimeout = function() {
    authFlow.login().catch(doneRef);
  };

  var resetIdleTimeoutOnce = (function(resp) {
    var executed = false;
    return function(resp) {
      if (!executed &&
            resp.TimeoutType === TimeoutTypeEnum.IdleTimeout &&
            Number(resp.TimeLeftToTimeout) > 0) {
        executed = true;
        authFlow.resetIdleTimeout();
      }
    };
  })();

  var verifyResultForNormalLogin = function(numChallenges) {
    if (numChallenges === undefined)
      numChallenges = 1;
    expect(basicHeaders).toBeDefined();
    expect(basicHeaders.Authorization).toBeDefined();
    expect(basicHeaders.Authorization).toBe(window.TestConfig.basic.header);
    expect(httpCallResult).toContain(window.TestConfig.basic.securedResponse);
    expect(isAuthBeforeLogin).not.toBeTruthy();
    expect(isAuthAfterLogin).toBeTruthy();
    expect(isAuthAfterLogout).not.toBeTruthy();
    expect(challenges.length).toEqual(numChallenges);
  };

  var verifyNormal = function() {
    it('verify headers and XHR result and logout.', function(done) {
      verifyResultForNormalLogin(1);
      done();
    });
    it('login again and verify XHR.', function(done) {
      verifyResultForNormalLogin(2);
      done();
    });
  };

  var verifyChallenge = function(remUser, remPass, auto) {
    for (var ch in challenges) {
      if (remUser) {
        expect(challenges[ch].RememberUsernameAllowed).toBeTruthy();
        expect(challenges[ch].remember_username_ui_preference_key).toBeTruthy();
      } else {
        expect(challenges[ch].RememberUsernameAllowed).not.toBeTruthy();
        expect(challenges[ch].remember_username_ui_preference_key).not.toBeTruthy();
      }
      if (remPass) {
        expect(challenges[ch].RememberCredentialsAllowed).toBeTruthy();
        expect(challenges[ch].remember_credentials_ui_preference_key).toBeTruthy();
      } else {
        expect(challenges[ch].RememberCredentialsAllowed).not.toBeTruthy();
        expect(challenges[ch].remember_credentials_ui_preference_key).not.toBeTruthy();
      }
      if (auto) {
        expect(challenges[ch].AutoLoginAllowed).toBeTruthy();
        expect(challenges[ch].autoLogin_ui_preference_key).toBeTruthy();
      } else {
        expect(challenges[ch].AutoLoginAllowed).not.toBeTruthy();
        expect(challenges[ch].autoLogin_ui_preference_key).not.toBeTruthy();
      }
    }
  };

  var verifyRememberUser = function() {
    it('verify user is NOT remembered.', function(done) {
      verifyResultForNormalLogin(1);
      verifyChallenge(true, false, false);
      expect(rememberedUser).toBeNull();
      expect(rememberedPass).toBeNull();
      done();
    });
    it('verify user IS remembered.', function(done) {
      verifyResultForNormalLogin(2);
      verifyChallenge(true, false, false);
      expect(rememberedUser).toBeDefined();
      expect(rememberedUser).toBe(validUserName);
      expect(rememberedPass).toBeNull();
      done();
    });
  };

  var verifyRememberCred = function() {
    it('verify credential IS remembered.', function(done) {
      verifyResultForNormalLogin(2);
      verifyChallenge(false, true, false);
      expect(rememberedUser).toBeDefined();
      expect(rememberedUser).toBe(validUserName);
      expect(rememberedPass).toBeDefined();
      expect(rememberedPass).toBe(rememberedPass);
      done();
    });
  };

  var verifyRememberUserAndCred = function() {
    it('verify username and credential ARE remembered.', function(done) {
      verifyResultForNormalLogin(2);
      verifyChallenge(true, true, false);
      expect(rememberedUser).toBeDefined();
      expect(rememberedUser).toBe(validUserName);
      expect(rememberedPass).toBeDefined();
      expect(rememberedPass).toBe(rememberedPass);
      done();
    });
  };

  var verifyAutoLoginWithIdleTimeout = function() {
    it('verify auto login worked.', function(done) {
      verifyResultForNormalLogin(1);
      expect(timeoutResps.length).toBe(2);
      expect(timeoutResps[0].TimeoutType).toBe(TimeoutTypeEnum.IdleTimeout);
      expect(Number(timeoutResps[0].TimeLeftToTimeout)).toBeGreaterThan(0);
      expect(timeoutResps[1].TimeoutType).toBe(TimeoutTypeEnum.IdleTimeout);
      expect(Number(timeoutResps[1].TimeLeftToTimeout)).toEqual(0);
      done();
    });
  };

  var verifyAutoLoginWithSessionTimeout = function() {
    it('verify auto login worked.', function(done) {
      verifyResultForNormalLogin(2);
      verifyChallenge(false, false, true);
      expect(timeoutResps.length).toBe(1);
      expect(timeoutResps[0].TimeoutType).toBe(TimeoutTypeEnum.SessionTimeout);
      expect(Number(timeoutResps[0].TimeLeftToTimeout)).toEqual(0);
      done();
    });
  };

  var createTestWith = function (builder, loginMethod, verifyMethod) {
    return function() {
      beforeAll(function(done) {
        resetTestSuite();
        doneRef = done;
        initFlow(builder.build());
      });
      beforeEach(function(done) {
        resetTestCase();
        doneRef = done;
        loginMethod.call();
      });
      verifyMethod.call();
    };
  };

  describe('Test HTTPBasicAuthentication flow', function() {
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    describe('login with connectivity mode Auto and access secured resource',
      createTestWith(getBuilder().connectivityMode(Builder.ConnectivityMode.Auto), loginXhrAndLogout, verifyNormal));
    describe('login with connectivity mode Online and access secured resource',
      createTestWith(getBuilder().connectivityMode(Builder.ConnectivityMode.Online), loginXhrAndLogout, verifyNormal));
    describe('login with connectivity mode Offline and access secured resource',
      createTestWith(getBuilder().connectivityMode(Builder.ConnectivityMode.Offline), loginXhrAndLogout, verifyNormal));
    describe('login with connectivity mode Auto with remember user',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true), loginXhrAndLogout, verifyRememberUser));
    describe('login with connectivity mode Online with remember user',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true), loginXhrAndLogout, verifyRememberUser));
    describe('login with connectivity mode Offline with remember user',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true), loginXhrAndLogout, verifyRememberUser));
    describe('login with connectivity mode Auto with remember credentials in idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberCred));

    describe('login with connectivity mode Online with remember credentials in idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberCred));
    describe('login with connectivity mode Offline with remember credentials in idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberCred));
    describe('login with connectivity mode Auto with remember user and credentials in idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberUserAndCred));
    describe('login with connectivity mode Online with remember user and credentials in idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberUserAndCred));
    describe('login with connectivity mode Offline with remember user and credentials in idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberUserAndCred));
    describe('login with connectivity mode Auto with remember credentials in session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberCred));

    describe('login with connectivity mode Online with remember credentials in session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberCred));
    describe('login with connectivity mode Offline with remember credentials in session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberCred));
    describe('login with connectivity mode Auto with remember user and credentials in session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberUserAndCred));
    describe('login with connectivity mode Online with remember user and credentials in session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberUserAndCred));
    describe('login with connectivity mode Offline with remember user and credentials in session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .rememberUsernameAllowed(true)
                      .rememberUsernameDefault(true)
                      .rememberCredentialsAllowed(true)
                      .rememberCredentialDefault(true), loginAndWaitForTimeout, verifyRememberUserAndCred));
    describe('login with connectivity mode Auto with auto login and idle timeout  with default percentage idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithIdleTimeout));
    describe('login with connectivity mode Online with auto login and idle timeout with default percentage idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithIdleTimeout));
    describe('login with connectivity mode Offline with auto login and idle timeout  with default percentage idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithIdleTimeout));
    describe('login with connectivity mode Auto with auto login and idle timeout  with percentage idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .percentageToIdleTimeout(50)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithIdleTimeout));
    describe('login with connectivity mode Online with auto login and idle timeout with percentage idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .percentageToIdleTimeout(50)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithIdleTimeout));
    describe('login with connectivity mode Offline with auto login and idle timeout  with percentage idle timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .timeoutCallback(timeoutCallback)
                      .idleTimeOutInSeconds(10)
                      .percentageToIdleTimeout(50)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithIdleTimeout));
    describe('login with connectivity mode Auto with auto login and session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Auto)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithSessionTimeout));
    describe('login with connectivity mode Online with auto login and session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Online)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithSessionTimeout));
    describe('login with connectivity mode Offline with auto login and session timeout',
      createTestWith(getBuilder()
                      .connectivityMode(Builder.ConnectivityMode.Offline)
                      .timeoutCallback(timeoutCallback)
                      .sessionTimeOutInSeconds(10)
                      .autoLoginAllowed(true)
                      .autoLoginDefault(true), loginAndWaitForTimeout, verifyAutoLoginWithSessionTimeout));
    describe('timeout test without resetIdleTimeout',
      createTestWith(getBuilder()
        .timeoutCallback(function(resp) {
          timeoutResps.push(resp);
          if (resp.TimeoutType === TimeoutTypeEnum.SessionTimeout)
            loginXhrAndLogoutWithPurging();
        })
        .idleTimeOutInSeconds(10)
        .percentageToIdleTimeout(50)
        .sessionTimeOutInSeconds(20),
        loginAndWaitForTimeout,
        function() {
          it('timeouts happened correctly.', function(done) {
            verifyResultForNormalLogin(2);
            expect(timeoutResps.length).toBe(3);
            expect(timeoutResps[0].TimeoutType).toBe(TimeoutTypeEnum.IdleTimeout);
            expect(Number(timeoutResps[0].TimeLeftToTimeout)).toBeGreaterThan(0);
            expect(timeoutResps[1].TimeoutType).toBe(TimeoutTypeEnum.IdleTimeout);
            expect(Number(timeoutResps[1].TimeLeftToTimeout)).toEqual(0);
            expect(timeoutResps[2].TimeoutType).toBe(TimeoutTypeEnum.SessionTimeout);
            expect(Number(timeoutResps[2].TimeLeftToTimeout)).toEqual(0);
            done();
          }
        );
      })
    );
    describe('timeout test with resetIdleTimeout',
      createTestWith(getBuilder()
        .timeoutCallback(function(resp) {
          timeoutResps.push(resp);
          resetIdleTimeoutOnce(resp);
          if (resp.TimeoutType === TimeoutTypeEnum.SessionTimeout)
            loginXhrAndLogoutWithPurging();
        })
        .idleTimeOutInSeconds(10)
        .percentageToIdleTimeout(50)
        .sessionTimeOutInSeconds(20),
        loginAndWaitForTimeout,
        function() {
          it('timeouts happened correctly.', function(done) {
            verifyResultForNormalLogin(2);
            expect(timeoutResps.length).toBe(4);
            expect(timeoutResps[0].TimeoutType).toBe(TimeoutTypeEnum.IdleTimeout);
            expect(Number(timeoutResps[0].TimeLeftToTimeout)).toBeGreaterThan(0);
            expect(timeoutResps[1].TimeoutType).toBe(TimeoutTypeEnum.IdleTimeout);
            expect(Number(timeoutResps[1].TimeLeftToTimeout)).toBeGreaterThan(0);
            expect(timeoutResps[2].TimeoutType).toBe(TimeoutTypeEnum.IdleTimeout);
            expect(Number(timeoutResps[2].TimeLeftToTimeout)).toEqual(0);
            expect(timeoutResps[3].TimeoutType).toBe(TimeoutTypeEnum.SessionTimeout);
            expect(Number(timeoutResps[3].TimeLeftToTimeout)).toEqual(0);
            done();
          });
        }
      )
    );
    describe('login and verify custom headers',
      createTestWith(getBuilder().customAuthHeaders({myHeader: 'myValue'}), loginXhrAndLogoutWithPurging,
        function() {
          it('verify custom headers are returned.', function(done) {
            expect(basicHeaders).toBeDefined();
            expect(basicHeaders.Authorization).toBeDefined();
            expect(basicHeaders.myHeader).toBeDefined();
            done();
          });
        }
      )
    );
  });
};