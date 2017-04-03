# cordova-plugin-oracle-idm-auth 1.0.0

## About the cordova-plugin-oracle-idm-auth
This cordova plugin lets you perform authentication and access secured resources from cordova applications. 
The plugin is designed to handle multiple authentication flows in parallel.
Android 5.0 or later with WebView v39.0.0.0 is required for this plugin. 

This is an open source project maintained by Oracle Corp.

### Installation
Execute this command to install cordova-plugin-oracle-idm-auth from your cordova application. 

```bash
cordova plugin add cordova-plugin-oracle-idm-auth
```

### Usage
```js
// Preserve this authentication flow object to interact with the particular flow.
var authFlow;

// The plugin will be available in onDeviceReady or an equivalent callback which is executed after the application is loaded by the device.

document.addEventListener("deviceready", onDeviceReady);
function onDeviceReady() {
  // Create the authentication properties
  var authProperties = cordova.plugins.IdmAuthFlows.newHttpBasicAuthPropertiesBuilder(...).build();
  
  var authPromise = cordova.plugins.IdmAuthFlows.init(authProperties);
  authPromise.then(function(flow) {
    authFlow = flow;
  });
}

// Do login.
var loginPromise = authFlow.login(challengeCallback);
loginPromise.then(function(resp) {
  // Perform after login tasks.
})

// Retrieve headers
var getHeadersPromise = authFlow.getHeaders();
getHeadersPromise.then(function(headers) {
  // Use headers for setting appropriate headers for performing an XHR request.
});

// Find our use's authentication status.
var isAuthenticatedPromise = authFlow.isAuthenticated();
isAuthenticatedPromise.then(function(authenticated) {
  // Use headers for setting appropriate headers for performing an XHR request.
});

// Logout from a particular authentication flow.
var logoutPromise = authFlow.logout();
logoutPromise.then(function(resp) {
  // Do after logout tasks
});
```

#### Typical challenge handling usecase
```
var challengeFields, challengeProceedHandler;
var authFlow;

// Auth props to init with.
var basicAuthProps = cordova.plugins.IdmAuthFlows.newHttpBasicAuthPropertiesBuilder(...)
...
...
.build();

// Init the auth flow on load.
cordova.plugins.IdmAuthFlows.init(basicAuthProps, timeoutCallback).then(function (flow) {
    authFlow = flow;
    startLogin();
}).catch(errorHandler);

var startLogin = function() {
    basicAuthFlow.login(challengeCallback).then(function (flow) {
        // Do after login stuff.
    });
}

var challengeCallback = function (fields, proceedHandler) {
    challengeFields = fields;
    challengeProceedHandler = proceedHandler;
    ... 
    // Present the login page to the user.
}

// Login button handler 
var loginBasicAuth = function() {
    // Fill up challengeFields with user inputs.
    challengeProceedHandler(challengeFields);
};

// Logout button handler
var logoutBasicAuth = function() {
    authFlow.logout().then(function(resp) {
        // Do after logout stuff.
        // If presenting the user with a login screen, get ready for next login
        startLogin();
    });
}    
```

### Extra step for Android
Add org.slf4j dependency to cordova application's build.gradle file.

```
<app>/hybrid/platforms/android/build.gradle
```

Add this line inside the dependency section:

```
dependencies {
  ...
  compile group: 'org.slf4j', name:'slf4j-api', version: '1.7.13'
  ...
}
```

### Common gotchas
#### Ensure that the server accesses and redirects are secured using HTTPS. 
During authentication, if there are redirects from secured to non-secured, the plugin will throw P1001 error. 
The authentication servers are expected to be configured using secured HTTP.
#### gap://ready javascript error with iOS 10
The following javascript error can occur while using this plugin on iOS 10:
```
[Error] Refused to load gap://ready because it appears in neither the child-src directive nor the default-src directive of the Content Security Policy. (x5)
```
Solution is to add gap://ready to CSP meta tag, similar to the following in your html page:
```
<meta http-equiv="Content-Security-Policy" content="img-src 'self' data:; default-src * gap://ready; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdvfile://*">
```
#### WkWebView support
Applications can use WkWebView for iOS 10+ by installing [cordova-plugin-wkwebview-engine](https://github.com/apache/cordova-plugin-wkwebview-engine/) cordova plugin. 
This impacts usecases where server login page is used to login, such as FederatedAuthentication or OAUTH2 3-legged. In this case application should set `enableWkWebView` to `true`
while initializing the authentication flow.

### Documentation
See detailed [documentation](docs/plugin.md) for the plugin.
[Error codes](docs/error-codes.md) for the plugin are documented.

### Known Issues

### [Contributing](CONTRIBUTING.md)
This is an open source project maintained by Oracle Corp. Pull Requests are currently not being accepted. See [CONTRIBUTING](CONTRIBUTING.md) for details.

### [License](LICENSE.md)
Copyright (c) 2017 Oracle and/or its affiliates
The Universal Permissive License (UPL), Version 1.0
