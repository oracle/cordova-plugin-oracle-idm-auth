/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var Builder = idmAuthFlowPlugin.FedAuthPropertiesBuilder;
  var goodLoginUrl = window.TestConfig.websso.loginUrl;
  var goodLogoutUrl = window.TestConfig.websso.logoutUrl;
  var goodLoginSuccessUrl = window.TestConfig.websso.loginSuccessUrl;
  var goodLoginFailureUrl = window.TestConfig.websso.loginFailureUrl;

  describe('Test Fed auth builder', function () {
    describe('Mandatory parameters', function() {
      describe('validate appName', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder().build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder(undefined, goodLoginUrl, goodLogoutUrl, goodLoginSuccessUrl, goodLoginFailureUrl).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'appName', 'string');
      });
      describe('validate loginUrl', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('App').build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('App', undefined, goodLogoutUrl, goodLoginSuccessUrl, goodLoginFailureUrl).build();
          }).toThrow();
        });
        it('passed as non URL in constructor.',function() {
          expect(function() {
            new Builder('App', 'nonUrl', goodLogoutUrl, goodLoginSuccessUrl, goodLoginFailureUrl).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'loginUrl', 'url');
      });
      describe('validate logoutUrl', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl).build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, undefined, goodLoginSuccessUrl, goodLoginFailureUrl).build();
          }).toThrow();
        });
        it('passed as non URL in constructor.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, 'nonUrl', goodLoginSuccessUrl, goodLoginFailureUrl).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'logoutUrl', 'url');
      });
      describe('validate loginSuccessUrl', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, goodLogoutUrl).build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, goodLogoutUrl, undefined, goodLoginFailureUrl).build();
          }).toThrow();
        });
        it('passed as non URL in constructor.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, goodLogoutUrl, 'nonUrl', goodLoginFailureUrl).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'loginSuccessUrl', 'url');
      });
      describe('validate loginFailureUrl', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, goodLogoutUrl, goodLoginSuccessUrl).build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, goodLogoutUrl, goodLoginSuccessUrl, undefined).build();
          }).toThrow();
        });
        it('passed as non URL in constructor.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, goodLogoutUrl, goodLoginSuccessUrl, 'nonUrl').build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'loginFailureUrl', 'url');
      });
    });
    describe('confirmLogoutAutomatically', window.TestUtil.validator(Builder, 'confirmLogoutAutomatically', 'boolean'));
    describe('confirmLogoutButtonId', window.TestUtil.validator(Builder, 'confirmLogoutButtonId', 'string'));
    describe('customAuthHeaders', window.TestUtil.validator(Builder, 'customAuthHeaders', 'object'));
    describe('enableWkWebView', window.TestUtil.validator(Builder, 'enableWkWebView', 'boolean'));
    describe('idleTimeOutInSeconds', window.TestUtil.validator(Builder, 'idleTimeOutInSeconds', 'number'));
    describe('sessionTimeOutInSeconds', window.TestUtil.validator(Builder, 'sessionTimeOutInSeconds', 'number'));
    describe('logoutFailureUrl', window.TestUtil.validator(Builder, 'logoutFailureUrl', 'url'));
    describe('logoutSuccessUrl', window.TestUtil.validator(Builder, 'logoutSuccessUrl', 'url'));
    describe('logoutTimeOutInSeconds', window.TestUtil.validator(Builder, 'logoutTimeOutInSeconds', 'number'));
    describe('parseTokenRelayResponse', window.TestUtil.validator(Builder, 'parseTokenRelayResponse', 'boolean'));
    describe('timeoutCallback', window.TestUtil.validator(Builder, 'timeoutCallback', 'function'));
    describe('sessionActiveOnRestart', window.TestUtil.validator(Builder, 'sessionActiveOnRestart', 'boolean'));

    describe('Timeouts with sessionActiveOnRestart', function() {
      it ('removes idle timeout when sessionActiveOnRestart is true', function() {
        var props = new Builder()
          .appName('App')
          .loginUrl(goodLoginUrl)
          .logoutUrl(goodLogoutUrl)
          .loginSuccessUrl(goodLoginSuccessUrl)
          .loginFailureUrl(goodLoginFailureUrl)
          .idleTimeOutInSeconds(300)
          .sessionActiveOnRestart(true)
          .build();
        expect(props.IdleTimeOutInSeconds).not.toBeDefined();
        expect(props.SessionTimeOutValue).not.toBeDefined();
      });

      it ('removes session timeout when sessionActiveOnRestart is true', function() {
        var props = new Builder()
          .appName('App')
          .loginUrl(goodLoginUrl)
          .logoutUrl(goodLogoutUrl)
          .loginSuccessUrl(goodLoginSuccessUrl)
          .loginFailureUrl(goodLoginFailureUrl)
          .sessionTimeOutInSeconds(6000)
          .sessionActiveOnRestart(true)
          .build();
        expect(props.IdleTimeOutValue).not.toBeDefined();
        expect(props.SessionTimeOutValue).not.toBeDefined();
      });

      it ('removes session and idle timeouts when sessionActiveOnRestart is true', function() {
        var props = new Builder()
          .appName('App')
          .loginUrl(goodLoginUrl)
          .logoutUrl(goodLogoutUrl)
          .loginSuccessUrl(goodLoginSuccessUrl)
          .loginFailureUrl(goodLoginFailureUrl)
          .sessionTimeOutInSeconds(6000)
          .idleTimeOutInSeconds(300)
          .sessionActiveOnRestart(true)
          .build();
        expect(props.IdleTimeOutValue).not.toBeDefined();
        expect(props.SessionTimeOutValue).not.toBeDefined();
      });

      it ('retains session and idle timeouts when sessionActiveOnRestart is false', function() {
        var props = new Builder()
          .appName('App')
          .loginUrl(goodLoginUrl)
          .logoutUrl(goodLogoutUrl)
          .loginSuccessUrl(goodLoginSuccessUrl)
          .loginFailureUrl(goodLoginFailureUrl)
          .sessionTimeOutInSeconds(6000)
          .idleTimeOutInSeconds(300)
          .sessionActiveOnRestart(false)
          .build();
        expect(props.IdleTimeOutValue).toBe(300);
        expect(props.SessionTimeOutValue).toBe(6000);
      });

      it ('retains session and idle timeouts when sessionActiveOnRestart is not set', function() {
        var props = new Builder()
          .appName('App')
          .loginUrl(goodLoginUrl)
          .logoutUrl(goodLogoutUrl)
          .loginSuccessUrl(goodLoginSuccessUrl)
          .loginFailureUrl(goodLoginFailureUrl)
          .sessionTimeOutInSeconds(6000)
          .idleTimeOutInSeconds(300)
          .build();
        expect(props.IdleTimeOutValue).toBe(300);
        expect(props.SessionTimeOutValue).toBe(6000);
      });
    });
  });
};
