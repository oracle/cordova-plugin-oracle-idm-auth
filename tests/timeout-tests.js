/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('Timeout', function () {
    var authFlow, challengeCount = 0, timeoutType = [], timeLeft = [], defaultJasmineTimeout, firstCall = true;
    var isAuthAfterIdleReset, isAuthIdleExp, isAuthSessExp;
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 90000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var challengeCallback = function (fields, proceedHandler) {
        challengeCount++;
        fields[idmAuthFlowPlugin.AuthChallenge.UserName] = 'neelu';
        fields[idmAuthFlowPlugin.AuthChallenge.Password] = 'Welcome1';
        // console.log('[Timeout] challengeCallback executed: ' + JSON.stringify(fields));
        proceedHandler(fields);
      };

      //
      // Note that calling isAuthenticated before the idle timeout has expired has the effect of resetting idle timeout.
      // This is as per design in IDM.
      //
      var timeoutCallback = function(resp)
      {
        // console.log('[Timeout] timeoutCallback: ' + JSON.stringify(resp));
        timeoutType.push(resp[idmAuthFlowPlugin.TimeoutResponse.TimeoutType]);
        timeLeft.push(resp[idmAuthFlowPlugin.TimeoutResponse.TimeLeftToTimeout]);

        if (resp[idmAuthFlowPlugin.TimeoutResponse.TimeoutType] == idmAuthFlowPlugin.TimeoutType.SessionTimeout)
        {
          authFlow.isAuthenticated().then(function (resp) {
            // console.log('[Timeout] isAuthenticated session expiry: ' + resp);
            isAuthSessExp = resp;
            authFlow.logout().then(function (logoutResFlow) {
              // console.log('[Timeout] Second login: attempt after session timeout.');
              logoutResFlow.login(challengeCallback).then(function(loginFlow2) {
                // console.log('[Timeout] Second login: challengeCount: ' + challengeCount);
                loginFlow2.logout().then(function (resp) {
                  // console.log('[Timeout] Second login: logout success.');
                  done();
                }, done);
              }, done);
            }, done);
          });
          return;
        }

        if (resp[idmAuthFlowPlugin.TimeoutResponse.TimeoutType] == idmAuthFlowPlugin.TimeoutType.IdleTimeout &&
            resp[idmAuthFlowPlugin.TimeoutResponse.TimeLeftToTimeout] == '0')
        {
          authFlow.isAuthenticated().then(function (resp) {
            // console.log('[Timeout] isAuthenticated second idleTimeout: ' + resp);
            isAuthIdleExp = resp;
          });
        }

        if (firstCall)
        {
          firstCall = false;
          authFlow.resetIdleTimeout().then(function(resp) {
            authFlow.isAuthenticated().then(function (resp) {
              // console.log('[Timeout] isAuthenticated first idleTimeout: ' + resp);
              isAuthAfterIdleReset = resp;
            }, done);
          }, done);
        }
      };
      
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('JasmineJsTests',
            'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
            'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .maxLoginAttempts(2)
        .sessionTimeOutInSeconds(30)
        .idleTimeOutInSeconds(10)
        .percentageToIdleTimeout(50)
        .offlineAuthAllowed(true)
        .autoLoginDefault(true)
        .build();
      idmAuthFlowPlugin.init(authProps, timeoutCallback)
        .then(function (flow) {
            // console.log('[Timeout] initCallback executed: ' + JSON.stringify(flow));
            authFlow = flow;
            flow.login(challengeCallback).then(function (resp) {
              // console.log('[Timeout] loginCallback executed: ' + JSON.stringify(loginResult));
            }, done);
        }, done);
    });
  
    it('idle timeout triggers, reset, idle timeout again, dont reset and then session timeout.', function(done) {
      expect(authFlow).toBeDefined();
      expect(timeoutType[0]).toBe(idmAuthFlowPlugin.TimeoutType.IdleTimeout);
      expect(timeoutType[1]).toBe(idmAuthFlowPlugin.TimeoutType.IdleTimeout);
      expect(timeoutType[2]).toBe(idmAuthFlowPlugin.TimeoutType.IdleTimeout);
      expect(timeoutType[3]).toBe(idmAuthFlowPlugin.TimeoutType.SessionTimeout);
      expect(Number(timeLeft[0]) <= 5).toBeTruthy();
      expect(Number(timeLeft[1]) <= 5).toBeTruthy();
      expect(Number(timeLeft[2])).toBe(0);
      expect(Number(timeLeft[3])).toBe(0);
      expect(isAuthAfterIdleReset).toBe(true);
      expect(isAuthIdleExp).toBe(false);
      expect(isAuthSessExp).toBe(false);
      done();
    });
  });
};