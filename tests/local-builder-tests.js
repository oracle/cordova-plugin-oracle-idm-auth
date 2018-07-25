/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var Builder = idmAuthFlowPlugin.LocalAuthPropertiesBuilder;
  var goodCallback = function() {};

  describe('Test Fed auth builder', function () {
    describe('Mandatory parameters', function() {
      describe('validate id', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder().build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder(undefined, goodCallback).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'appName', 'string');
      });
      describe('validate pinChallengeCallback', function(){
        it('from an empty builder.',function() {
          expect(function() {
            new Builder('MyLocalAuth').build();
          }).toThrow();
        });
        it('passed as undefined in constructor.',function() {
          expect(function() {
            new Builder('MyLocalAuth', undefined).build();
          }).toThrow();
        });
        window.TestUtil.validator(Builder, 'pinChallengeCallback', 'function');
      });
    });
    describe('translations', window.TestUtil.validator(Builder, 'translations', 'object'));
  });
};
