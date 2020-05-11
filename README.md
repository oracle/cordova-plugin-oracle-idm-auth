# cordova-plugin-oracle-idm-auth 1.5.0

## About the cordova-plugin-oracle-idm-auth
The plugin provides authentication and authorization functionality for cordova based mobile applications,
supporting standard protocols like Basic Auth, OAUTH, OpenID Connect and webSSO.
The plugin abstracts all aspects of authentication and authorization and enforces security best practices for mobile application developers.
The plugin is designed to handle multiple authentication flows in parallel.

## Supported platforms
* Android 5.0 or later with Android System WebView v39.0.0.0.0 minimum.
  * Compatible with compile and target SDK versions of 27 and min SDK version of 21
* iOS 10.3 and above.

### Installation
Execute this command to install cordova-plugin-oracle-idm-auth into your cordova application.

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
var loginPromise = authFlow.login();
loginPromise.then(function(resp) {
  // Perform after login tasks.
})

// Retrieve headers
var getHeadersPromise = authFlow.getHeaders(options);
getHeadersPromise.then(function(headers) {
  // Use headers for setting appropriate headers for performing an XHR request.
});

// Find our use's authentication status.
var isAuthenticatedPromise = authFlow.isAuthenticated(options);
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
```js
var challengeFields, challengeProceedHandler;
var authFlow;

// Define challenge callback
var callback = function (fields, proceedHandler) {
  challengeFields = fields;
  challengeProceedHandler = proceedHandler;
  ...
  // Present the login page to the user.
}

// Define timeout callback
var timeoutCallback = function (timeoutResponse) {
  // Handle timeout
}

// Auth props to init with.
var basicAuthProps = new cordova.plugins.IdmAuthFlows.HttpBasicAuthPropertiesBuilder(...)
                          .challengeCallback(callback)
                          .timeoutCallback(timeoutCallback)
                          ...
                          ...
                          .build();

// Init the auth flow on load.
cordova.plugins.IdmAuthFlows.init(basicAuthProps).then(function (flow) {
    authFlow = flow;
    startLogin();
}).catch(errorHandler);

var startLogin = function() {
    basicAuthFlow.login().then(function (flow) {
        // Do after login stuff.
    });
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

### Documentation
* Details of JavaScript API can be found in the [JSDocs](https://oracle.github.io/cordova-plugin-oracle-idm-auth/ "JSDocs").
* Error codes are documented in the [error codes](md/error-codes.md).
* Frequently asked questions are answered in the [FAQ](md/faq.md).

### Known Issues
1. OpenID does not support implicit flow.
1. iOS simulator only issue - Crashes with ```Assertion failure in -[KeychainItemWrapper writeToKeychain]```.
This is an apple issue discussed [here](https://stackoverflow.com/questions/39561041/keychainitemwrapper-crash-on-ios10)
and [here](https://forums.developer.apple.com/thread/51071). Work around for this issue is to [enable keychain sharing from xcode]
(https://developer.apple.com/library/content/documentation/IDEs/Conceptual/AppDistributionGuide/AddingCapabilities/AddingCapabilities.html).

### [Contributing](CONTRIBUTING.md)
This is an open source project maintained by Oracle Corp. Pull Requests are currently not being accepted. See [CONTRIBUTING](CONTRIBUTING.md) for details.

### [License](LICENSE.md)
Copyright (c) 2017 Oracle and/or its affiliates
The Universal Permissive License (UPL), Version 1.0

### [Release Notes](RELEASENOTES.md)
