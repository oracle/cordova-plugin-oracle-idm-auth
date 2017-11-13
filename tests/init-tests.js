/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;

  describe('idmAuthFlowPlugin.init', function () {
    var result;
    beforeEach(function(done) {
      var failureCallback = function (resp) {
        result = resp;
        done();
      };
      idmAuthFlowPlugin.init().catch(failureCallback);
    });

    it('with no auth properties.', function(done) {
      expect(result).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(result[idmAuthFlowPlugin.Error.ErrorCode]).toBe("P1005");
      expect(result[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);
      done();
    });
  });
  describe('idmAuthFlowPlugin.init', function () {
    var result;
    beforeEach(function(done) {
      var failureCallback = function (resp) {
        result = resp;
        done();
      };
      idmAuthFlowPlugin.init({}).catch(failureCallback);
    });

    it('with empty auth properties.', function(done) {
      expect(result).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(result[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10115");
      expect(result[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);
      done();
    });
  });
  describe('idmAuthFlowPlugin.init', function () {
    var result;
    beforeEach(function(done) {
      var failureCallback = function (resp) {
        result = resp;
        done();
      };
      idmAuthFlowPlugin.init({'a':'b'}).catch(failureCallback);
    });

    it('with invalid auth properties.', function(done) {
      expect(result).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.ErrorCode]).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.ErrorSource]).toBeDefined();
      expect(result[idmAuthFlowPlugin.Error.TranslatedErrorMessage]).toBe("");
      expect(result[idmAuthFlowPlugin.Error.ErrorCode]).toBe("10115");
      expect(result[idmAuthFlowPlugin.Error.ErrorSource]).toBe(idmAuthFlowPlugin.ErrorSources.Plugin);
      done();
    });
  });
  describe('idmAuthFlowPlugin.init', function () {
    var flow;
    beforeEach(function(done) {
      var authProps = idmAuthFlowPlugin.newHttpBasicAuthPropertiesBuilder('jasmineJsTests',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo',
          'http://slc05zpo.us.oracle.com:7101/SecureRESTWebService1/Echo')
        .build();
      idmAuthFlowPlugin.init(authProps).then(function (resp) {
        flow = resp;
        done();
      });
    });

    it('with valid auth properties.', function(done) {
      expect(flow).toBeDefined();
      expect(flow.login).toBeDefined();
      expect(flow.logout).toBeDefined();
      expect(flow.isAuthenticated).toBeDefined();
      expect(flow.getHeaders).toBeDefined();
      expect(flow.resetIdleTimeout).toBeDefined();
      done();
    });
  });
};
