/**
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('Test IdmAuthFlow API', function () {
    it('plugin is defined.', function() {
      expect(idmAuthFlowPlugin).toBeDefined();
    });
    it('init is defined.', function() {
      expect(idmAuthFlowPlugin.init).toBeDefined();
    });
    it('HttpBasicAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.HttpBasicAuthPropertiesBuilder).toBeDefined();
    });
    it('FedAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.FedAuthPropertiesBuilder).toBeDefined();
    });
    it('OAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.OAuthPropertiesBuilder).toBeDefined();
    });
    it('OpenIDConnectPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.OpenIDConnectPropertiesBuilder).toBeDefined();
    });
    it('LocalAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.LocalAuthPropertiesBuilder).toBeDefined();
    });
    it('ErrorSource is defined.', function() {
      expect(idmAuthFlowPlugin.ErrorSource).toBeDefined();
    });
  });
};