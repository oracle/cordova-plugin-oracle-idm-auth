exports.defineAutoTests = function() {
  var idmAuthFlowPlugin = cordova.plugins.IdmAuthFlows;
  var nullValidator = function(Builder, property) {
    it('should not allow undefined', function() {
      expect(function() {
        var b = new Builder();
        b[property].call(b, undefined);
      }).toThrow();
    });
    it('should not allow null', function() {
      expect(function() {
        var b = new Builder();
        b[property].call(b, null);
      }).toThrow();
    });
    it('should not allow empty string', function() {
      expect(function() {
        var b = new Builder();
        b[property].call(b, '');
      }).toThrow();
      expect(function() {
        var b = new Builder();
        b[property].call(b, "");
      }).toThrow();
    });
  };

  var numberValidator = function(Builder, property, allow) {
    if (allow) {
      it('should allow number', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, 200);
        }).not.toThrow();
      });
    } else {
      it('should not allow number', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, 200);
        }).toThrow();
      });
    }
  };

  var objectValidator = function(Builder, property, allow) {
    if (allow) {
      it('should allow object', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, {a:'a'});
        }).not.toThrow();
      });
    } else {
      it('should not allow object', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, {a:'a'});
        }).toThrow();
      });
    }
  };

  var boolValidator = function(Builder, property, allow) {
    if (allow) {
      it('should allow boolean', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, true);
        }).not.toThrow();
        expect(function() {
          var b = new Builder();
          b[property].call(b, false);
        }).not.toThrow();
      });
    } else {
      it('should not allow boolean', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, true);
        }).toThrow();
        expect(function() {
          var b = new Builder();
          b[property].call(b, false);
        }).toThrow();
      });
    }
  };

  var fnValidator = function(Builder, property, allow) {
    if (allow) {
      it('should allow function', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, function() {});
        }).not.toThrow();
      });
    } else {
      it('should not allow function', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, function() {});
        }).toThrow();
      });
    }
  };

  var randomStringValidator = function(Builder, property, allow) {
    if (allow) {
      it('should allow random string', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, 'something');
        }).not.toThrow();
      });
    } else {
      it('should not allow random string', function() {
        expect(function() {
          var b = new Builder();
          b[property].call(b, 'something');
        }).toThrow();
      });
    }
  };

  var enumStringValidator = function(Builder, property, enumObj) {
    for (var e in enumObj) {
      if (enumObj.hasOwnProperty(e)) {
        it('should allow ' + enumObj[e], function() {
          expect(function() {
            var b = new Builder();
            b[property].call(b, enumObj[e]);
          }).not.toThrow();
        });
      }
    }
  };

  var urlValidator = function(Builder, property) {
    it('should allow url strings', function() {
      expect(function() {
        var b = new Builder();
        b[property].call(b, 'http://my/url');
      }).not.toThrow();
    });
  };


  window.TestUtil = {
    validator: function(Builder, property, type, enumObj) {
      return function() {
        nullValidator(Builder, property);
        boolValidator(Builder, property, type === 'boolean');
        randomStringValidator(Builder, property, type === 'string');
        if (type === 'enum')
          enumStringValidator(Builder, property, enumObj);
        if (type === 'url')
          urlValidator(Builder, property);
        fnValidator(Builder, property, type === 'function');
        objectValidator(Builder, property, type === 'object');
        numberValidator(Builder, property, type === 'number');
      };
    },
    xmlHttpRequestPromise: function(headers, securedUrl, withCred) {
      return new Promise(function(resolve, reject){
        var request = new XMLHttpRequest();
        var result;
        request.open('GET', securedUrl);

        if (withCred)
          request.withCredentials = true;

        for (var key in headers)
          if (headers.hasOwnProperty(key))
            request.setRequestHeader(key, headers[key]);

        request.addEventListener("load", function() {
          if (request.readyState == 4)
            resolve(request.response);
          else
            resolve();
        });
        request.addEventListener("error", resolve);
        request.addEventListener("abort", resolve);

        request.send();
      });
    },
    /**
     * @typedef {object} LoginXhrLogoutOptions
     * @property {boolean} purgeOnLogout
     * @property {object} headerOptions
     * @property {boolean} noLogout
     */
    loginXhrLogout: function(props, securedUrl, results, done, options) {
      var authFlow;

      if (!options)
        options = {};

      if (!options.purgeOnLogout)
        options.purgeOnLogout = true;

      idmAuthFlowPlugin.init(props)
        .then(function(flow) {
          authFlow = flow;
          return flow.isAuthenticated();
        })
        .then(function(auth) {
          results.authBeforeLogin = auth;
          return authFlow.login();
        })
        .then(function(flow) {
          return flow.isAuthenticated();
        })
        .then(function(auth) {
          results.authAfterLogin = auth;
          if (options.headerOptions)
            return authFlow.getHeaders(options.headerOptions);
          else
            return authFlow.getHeaders();
        })
        .then(function(headers) {
          results.headers = headers;
          return window.TestUtil.xmlHttpRequestPromise(headers, securedUrl);
        })
        .then(function(result) {
          results.securedUrlResult = result;
          if (options.noLogout) {
            done();
            return;
          }

          authFlow.logout(options.purgeOnLogout)
            .then(function(flow) {
              return flow.isAuthenticated();
            })
            .then(function(auth) {
              results.authAfterLogout = auth;
            })
            .then(done)
            .catch(done);
        })
        .catch(done);
    },
    /**
     * @typedef {object} VerifyOptions
     * @property {string} securedUrlResult
     * @property {string} authHeader
     * @property {object} additionalHeader
     * @property {boolean} noLogout
     */
    verifyResults: function(results, options) {
      if (!options)
        options = {};

      expect(results.authAfterLogin).toBeTruthy();
      expect(results.authBeforeLogin).not.toBeTruthy();
      expect(results.securedUrlResult).toBeDefined();
      expect(results.headers).toBeDefined();

      if (options.securedUrlResult)
        expect(results.securedUrlResult).toContain(options.securedUrlResult);

      if (options.authHeader)
        expect(result.headers.Authorization).toBe(options.authHeader);

      if (!options.noLogout)
        expect(results.authAfterLogout).not.toBeTruthy();

    },
    verifyPluginError: function(err, code) {
      expect(err).toBeDefined();
      expect(err.errorCode).toBeDefined();
      expect(err.errorSource).toBeDefined();
      expect(err.translatedErrorMessage).toBe("");
      expect(err.errorCode).toBe(code);
      expect(err.errorSource).toBe(idmAuthFlowPlugin.ErrorSource.Plugin);
    }
  };
};
