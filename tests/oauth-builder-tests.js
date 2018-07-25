/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var Builder = idmAuthFlowPlugin.OAuthPropertiesBuilder;
  var goodTokenEndpoint = window.TestConfig.oauthMcsResOwner.tokenUrl;
  var goodGrant = window.TestConfig.oauthMcsResOwner.grantType;
  var goodClientId = window.TestConfig.oauthMcsResOwner.clientId;

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
            new Builder(undefined, goodGrant, goodTokenEndpoint, goodClientId).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'appName', 'string');
      });
      describe('validate oAuthAuthorizationGrantType', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('App').build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('App', undefined, goodTokenEndpoint, goodClientId).build();
          }).toThrow();
        });
        it('passed as non enum in constructor.',function() {
          expect(function() {
            new Builder(undefined, 'invalid', goodTokenEndpoint, goodClientId).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'oAuthAuthorizationGrantType', 'enum', Builder.OAuthAuthorizationGrantType);
      });
      describe('validate oAuthTokenEndpoint', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('App', goodGrant).build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('App', goodGrant, undefined, goodClientId).build();
          }).toThrow();
        });
        it('passed as non URL in constructor.',function() {
          expect(function() {
            new Builder('App', goodGrant, 'nonUrl', goodClientId).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'oAuthTokenEndpoint', 'url');
      });
      describe('validate oAuthClientID', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('App', goodGrant, goodTokenEndpoint).build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('App', goodGrant, goodTokenEndpoint, undefined).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'oAuthClientID', 'string');
      });
    });
    describe('browserMode', window.TestUtil.validator(Builder, 'browserMode', 'enum', Builder.BrowserMode));
    describe('challengeCallback', window.TestUtil.validator(Builder, 'challengeCallback', 'function'));
    describe('customAuthHeaders', window.TestUtil.validator(Builder, 'customAuthHeaders', 'object'));
    describe('logoutTimeOutInSeconds', window.TestUtil.validator(Builder, 'logoutTimeOutInSeconds', 'number'));
    describe('logoutURL', window.TestUtil.validator(Builder, 'logoutURL', 'url'));
    describe('oAuthAuthorizationEndpoint', window.TestUtil.validator(Builder, 'oAuthAuthorizationEndpoint', 'url'));
    describe('oAuthClientSecret', window.TestUtil.validator(Builder, 'oAuthClientSecret', 'string'));
    describe('oAuthRedirectEndpoint', window.TestUtil.validator(Builder, 'oAuthRedirectEndpoint', 'url'));
    describe('oAuthScope', window.TestUtil.validator(Builder, 'oAuthScope', 'object'));
  });
};
