/**
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  /*
   * Deprecated APIs test. Keep these for backward compatibility for couple of releases.
   */
  describe('Test IdmAuthFlow API', function () {
    it('newHttpBasicAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder).toBeDefined();
    });
    it('newFedAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.newFedAuthPropertiesBuilder).toBeDefined();
    });
    it('newOpenIDConnectPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder).toBeDefined();
    });
    it('newOAuthPropertiesBuilder is defined.', function() {
      expect(idmAuthFlowPlugin.newOAuthPropertiesBuilder).toBeDefined();
    });
    it('ConnectivityModes is defined.', function() {
      expect(idmAuthFlowPlugin.ConnectivityModes).toBeDefined();
    });
    it('OAuthAuthorizationGrantTypes is defined.', function() {
      expect(idmAuthFlowPlugin.OAuthAuthorizationGrantTypes).toBeDefined();
    });
    it('AuthChallenge is defined.', function() {
      expect(idmAuthFlowPlugin.AuthChallenge).toBeDefined();
    });
    it('TimeoutResponse is defined.', function() {
      expect(idmAuthFlowPlugin.TimeoutResponse).toBeDefined();
    });
    it('TimeoutType is defined.', function() {
      expect(idmAuthFlowPlugin.TimeoutType).toBeDefined();
    });
    it('BrowserMode is defined.', function() {
      expect(idmAuthFlowPlugin.BrowserMode).toBeDefined();
    });
    it('Error is defined.', function() {
      expect(idmAuthFlowPlugin.Error).toBeDefined();
    });
    it('ErrorSources is defined.', function() {
      expect(idmAuthFlowPlugin.ErrorSources).toBeDefined();
    });
  });
};