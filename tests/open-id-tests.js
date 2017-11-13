/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/* jshint esversion: 6 */
exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var httpCallResult, authFlow, defaultJasmineTimeout;
  var authPropsBuilder = idmAuthFlowPlugin.newOpenIDConnectPropertiesBuilder('JasmineJsTests',
      idmAuthFlowPlugin.OAuthAuthorizationGrantTypes.OAuthAuthorizationCode,
      'https://maf-tenant.identity.c9dev0.oc9qadev.com/.well-known/idcs-configuration',
      '0c66088af56f44488eaf2b8af03f5714')
    .oAuthRedirectEndpoint('idcsmobileapp://nodata')
    .oAuthScope(['openid', 'urn:opc:idm:t.user.me']);
  var makeRequest = function(done)
  {
    // console.log('[OpenId] In makeRequest.');
    authFlow.getHeaders().then(function(headers) {
      // console.log('[OpenId] In getHeaders success response.');
      var request = new XMLHttpRequest();
      request.open('GET', 'https://maf-tenant.identity.c9dev0.oc9qadev.com:443/oauth2/v1/userinfo');
      for (var key in headers)
      {
        if (headers.hasOwnProperty(key))
        {
          // console.log('[OpenId] setting header:: ' + key + ":" + headers[key]);
          request.setRequestHeader(key, headers[key]);
        }
      }

      request.onload = function()
      {
        if (request.readyState == 4)
        {
          httpCallResult = request.response;
        } else {
          httpCallResult = request.readyState;
        }
        // console.log('[OpenId] makeRequest result: ' + httpCallResult);
        // console.log('[OpenId] Logging out.');
        authFlow.logout().then(done, done);
      };
      request.send();
    }, done);
  };

  describe('OpenIdConnect with Embedded browser', function () {
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 120000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var authProps = authPropsBuilder.browserMode(idmAuthFlowPlugin.BrowserMode.Embedded).build();
      // console.log('[OpenId] initing with authProps.');
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[OpenId] initCallback executed.');
        authFlow = flow;
        flow.login().then(function (resp) {
          // console.log('[OpenId] loginCallback executed.');
          makeRequest(done);
        }, done);
      }, done);
    });

    it('Login, make GET XHR request, logout and verify.', function(done) {
      // console.log('[OpenId] verify results.');
      expect(authFlow).toBeDefined();
      expect(httpCallResult).toBeDefined();
      expect(httpCallResult).toContain('admin@oracle.com');
      done();
    });
  });

  describe('OpenIdConnect with External browser', function () {
    beforeAll(function() {
      defaultJasmineTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 180000;
    });
    afterAll(function() {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = defaultJasmineTimeout;
    });
    beforeEach(function(done) {
      var authProps = authPropsBuilder.browserMode(idmAuthFlowPlugin.BrowserMode.External).build();
      // console.log('[OpenId] initing with authProps.');
      idmAuthFlowPlugin.init(authProps).then(function (flow) {
        // console.log('[OpenId] initCallback executed.');
        authFlow = flow;
        flow.login().then(function (resp) {
          // console.log('[OpenId] loginCallback executed.');
          makeRequest(done);
        }, done);
      }, done);
    });

    it('Login, make GET XHR request, logout and verify.', function(done) {
      // console.log('[OpenId] verify results.');
      expect(authFlow).toBeDefined();
      expect(httpCallResult).toBeDefined();
      expect(httpCallResult).toContain('admin@oracle.com');
      done();
    });
  });
};