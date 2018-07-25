/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var Builder = idmAuthFlowPlugin.HttpBasicAuthPropertiesBuilder;
  var goodLoginUrl = window.TestConfig.basic.loginUrl;
  var goodLogoutUrl = window.TestConfig.basic.logoutUrl;

  describe('Test HTTP basic auth builder', function () {
    describe('Mandatory parameters', function() {
      describe('validate appName', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder().build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder(undefined, goodLoginUrl, goodLogoutUrl).build();
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
            new Builder('App', undefined, goodLogoutUrl).build();
          }).toThrow();
        });
        it('passed as non URL in constructor.',function() {
          expect(function() {
            new Builder('App', 'nonUrl', goodLogoutUrl).build();
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
            new Builder('App', goodLoginUrl, undefined).build();
          }).toThrow();
        });
        it('passed as non URL in constructor.',function() {
          expect(function() {
            new Builder('App', goodLoginUrl, 'nonUrl').build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'logoutUrl', 'url');
      });
    });

    describe('idleTimeOutInSeconds', window.TestUtil.validator(Builder, 'idleTimeOutInSeconds', 'number'));
    describe('sessionTimeOutInSeconds', window.TestUtil.validator(Builder, 'sessionTimeOutInSeconds', 'number'));
    describe('percentageToIdleTimeout', function() {
      window.TestUtil.validator(Builder, 'percentageToIdleTimeout', 'number').call();
      it('should be less than or equal to 100', function() {
        expect(function() {
          new Builder().percentageToIdleTimeout(200);
        }).toThrow();
      });
    });

    describe('maxLoginAttempts', window.TestUtil.validator(Builder, 'maxLoginAttempts', 'number'));
    describe('offlineAuthAllowed', window.TestUtil.validator(Builder, 'offlineAuthAllowed', 'boolean'));
    describe('rememberUsernameAllowed', window.TestUtil.validator(Builder, 'rememberUsernameAllowed', 'boolean'));
    describe('rememberCredentialsAllowed', window.TestUtil.validator(Builder, 'rememberCredentialsAllowed', 'boolean'));
    describe('autoLoginAllowed', window.TestUtil.validator(Builder, 'autoLoginAllowed', 'boolean'));
    describe('rememberUsernameDefault', window.TestUtil.validator(Builder, 'rememberUsernameDefault', 'boolean'));
    describe('rememberCredentialDefault', window.TestUtil.validator(Builder, 'rememberCredentialDefault', 'boolean'));
    describe('autoLoginDefault', window.TestUtil.validator(Builder, 'autoLoginDefault', 'boolean'));
    describe('collectIdentityDomain', window.TestUtil.validator(Builder, 'collectIdentityDomain', 'boolean'));
    describe('passIdentityDomainNameInHeader', window.TestUtil.validator(Builder, 'passIdentityDomainNameInHeader', 'boolean'));
    describe('identityDomainHeaderName', window.TestUtil.validator(Builder, 'identityDomainHeaderName', 'string'));
    describe('connectivityMode', window.TestUtil.validator(Builder, 'connectivityMode', 'enum', Builder.ConnectivityMode));
    describe('customAuthHeaders', window.TestUtil.validator(Builder, 'customAuthHeaders', 'object'));
    describe('challengeCallback', window.TestUtil.validator(Builder, 'challengeCallback', 'function'));
    describe('timeoutCallback', window.TestUtil.validator(Builder, 'timeoutCallback', 'function'));
  });
};
