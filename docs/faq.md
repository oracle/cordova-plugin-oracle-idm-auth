# Frequently Asked Questions
* [How to solve gap://ready javascript error with iOS 10?](#how-to-solve-gapready-javascript-error-with-ios-10)
* [How to solve P1001 error?](#how-to-solve-p1001-error)
* [How to configure a SAML flow?](#how-to-configure-a-saml-flow)
* [Does the plugin support WkWebView?](#does-the-plugin-support-wkwebview)
* [How to handle logout confirmation screen in case of Federated Authentication?](#how-to-handle-logout-confirmation-screen-in-case-of-federated-authentication)
* [How to configure a Google OAUTH flow?](#how-to-configure-a-google-oauth-flow)
* [How to handle logout for Google OAUTH flow?](#how-to-handle-logout-for-google-oauth-flow)
* [How to setup OAUTH and OpenId with 'External' BrowserMode?](#how-to-setup-oauth-and-openid-with-external-browsermode)
* [How to setup custom URL scheme to handle redirects from external browser to mobile app?](#how-to-setup-custom-url-scheme-to-handle-redirects-from-external-browser-to-mobile-app)
* [How to solve error while logging out when device is offline?](#how-to-solve-error-while-logging-out-when-device-is-offline)
* [How to handle logout errors?](#how-to-handle-logout-errors)

## How to solve gap://ready javascript error with iOS 10?
The following javascript error can occur while using this plugin on iOS 10:
```
[Error] Refused to load gap://ready because it appears in neither the child-src directive nor the default-src directive of the Content Security Policy. (x5)
```
Solution is to add gap://ready to CSP meta tag, similar to the following in your html page:
```
<meta http-equiv="Content-Security-Policy" content="img-src 'self' data:; default-src * gap://ready; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval' cdvfile://*">
```

## How to solve P1001 error?
During authentication, if there are redirects from secured to non-secured, the plugin will throw P1001 error.
The authentication servers are expected to be configured using secured HTTP.

## How to configure a SAML flow?
SAML flow has to be created using a FederatedAuthentication flow.
In order to indicate the difference and to ask the plugin to parse the SAML token response, add parseTokenRelayResponse(true) in the builder.
```js
var authProps = IdmAuthFlows.newFedAuthPropertiesBuilder('appName',
                                                         'http://login/url',
                                                         'http://logout/url',
                                                         'http://login/success',
                                                         'http://logout/failed')
    .parseTokenRelayResponse(true)
    ...
    ...
    .build();
```

Note: After successful login, server should return the token response in JSON format.
Some environments such as Oracle MCS, need the login URL to be suffixed with `format=json` query parameter.

## Does the plugin support WkWebView?
Applications can use WkWebView for iOS 10+ by installing [cordova-plugin-wkwebview-engine](https://github.com/apache/cordova-plugin-wkwebview-engine/) cordova plugin.
This can be used for FederatedAuthentication login only. In this case application should set `enableWkWebView` to `true`
while initializing the authentication flow.

## How to handle logout confirmation screen in case of Federated Authentication?
Some federated authentication servers provide a logout confirmation screen where the user is expected to provide his consent for logout.
There are two ways to handle this situation. First by having the confirmation screen dismissed automatically, without user interaction.
This can be achieved by setting `confirmLogoutAutomatically` to `true` and providing`confirmLogoutButtonId` if needed.
The other way is to wait for user to provide his consent. This can be done by specifying `logoutSuccessURL` and `logoutFailureUrl`.
*Note:Irrespective of whether user cancels the logout or accepts the logout in the confirmation screen, the user is logged out.*

## How to configure a Google OAUTH flow?
For google OAUTH, create a credential of type `OAUTH client ID` from [google developer console](https://console.developers.google.com/apis/credentials) for iOS.
Provide your app's bundle Id and save. Copy the client ID this need to be passed in the OAUTH configuration (`google-client-id` in the example).
A sample configuration for Google OAUTH will look like this:
```js
var authProps = cordova.plugins.IdmAuthFlows.newOAuthPropertiesBuilder('JasmineJsTests',
    cordova.plugins.IdmAuthFlows.OAuthAuthorizationGrantTypes.OAuthAuthorizationCode,
    'https://accounts.google.com/o/oauth2/token',
    'google-client-id')
  .oAuthAuthorizationEndpoint('https://accounts.google.com/o/oauth2/auth')
  .oAuthRedirectEndpoint('app-url-scheme://')
  .oAuthScope(['https://www.googleapis.com/auth/userinfo.email',
               'https://www.googleapis.com/auth/userinfo.profile'])
  .logoutURL('https://www.google.com/accounts/Logout')
  .browserMode(cordova.plugins.IdmAuthFlows.BrowserMode.External)
  .build();
```

`app-url-scheme` can be one of:
1. URL scheme that google provides while creating the google credential.
2. App's bundle id that was registered while creating the google credential.

URL scheme [should contain at least one period](https://developers.google.com/identity/protocols/OAuth2InstalledApp#step-1-send-a-request-to-googles-oauth-20-server).
App should [setup custom URL Scheme](#urlScheme) to handle redirects from External browser.

## How to handle logout for Google OAUTH flow?
It is recommended that app does not logout the user while using Google OAUTH (and similar social OAUTH login).
This is because user may have already logged on to the browser for other purposes.
The app can however notify the user that the logout is performed only for the app and the user is still logged in to Google.

## How to setup OAUTH and OpenId with 'External' BrowserMode?
External browser use cases requires redirects from the app to the browser and back.
Once the external browser is launched and login page is loaded, app does not have any control.
The authentication server should be able to redirect to the app after successful authentication or logout.
For IDCS OpenId, `Redirect URL` and `Post Logout Redirect URL` should be configured from the admin console to point to the app URL scheme.
App should [setup custom URL Scheme](#urlScheme) to handle this redirect.

## How to setup custom URL scheme to handle redirects from external browser to mobile app?
While redirecting from external browser, the authentication server should redirect to an app URL scheme (say `appName://`).
A custom URL scheme can be added to the app using the `cordova-plugin-customurlscheme` plugin.

```
cordova plugin add cordova-plugin-customurlscheme --variable URL_SCHEME=<<appName>> --save
```

## How to solve error while logging out when device is offline?
Application needs to handle the logout behavior when the device is offline.
In this case, logout will throw an error because logout URL loading will fail when device is offline. But device local logout will be successful.
Application should handle this error in its logout callback, check for the device status (offline / online) and then decide
to show the error message to the user.

## How to handle logout errors?
Even if there is an error while logging out, the user is essentially logged out.
The app can decide not to show the logout error to the end user as there is no action associated with it.

