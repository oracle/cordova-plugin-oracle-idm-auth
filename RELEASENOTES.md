# Release Notes

## 1.1.7 (10 Apr, 2019)
* Added max retry for PIN authentication. This kicks in for login attempts using PIN, directly or as fallback from Fingerprint. It also kicks in for PIN change.
* For SAML based WebSSO, with parseTokenRelayResponse turned on, getHeaders can return cookies as headers in addition to the access tokens when header options specify fedAuthSecuredUrl.

## 1.1.6 (22 Mar, 2019)
* Fix regression - isAuthenticated not returning correct value for basic auth.
* Improve the way isAuthenticated is determined for local authentication.

## 1.1.5 (12 Mar, 2019)
* Bug fix in Android with OpenId usecase where user was considered logged in even after access token expired.
* Fix to refresh access token when checking for isAuthenticated.
* Doc improvements.

## 1.1.4 (21 Feb, 2019)
* Bug fixes for local authentication.
* Temporary fix for basic auth to fall back to successful login irrespective of status returned by server.
This is because plugin did not check for 2xx status in 1.0.4 for basic auth. Someone relying on that will fail while upgrading.
So this is a stop gap arrangement for those.
Note that with next release, plugin will insist on 2xx status code from server for successful authentication for basic auth.

## 1.1.3 (27 Sep, 2018)
* Bug fixes in android related to error codes returned and authentication before changing PIN.

## 1.1.2 (24 Sep, 2018)
* Bug fix on cancel behavior for iOS local authentication.
* Added API to fetch device supported local authentication types.

## 1.1.1 (30 Jul, 2018)
* Removed android SDK version dependencies so that apps can freely change the versions. Recommended versions are documented.


## 1.1.0 (25 Jul, 2018)
* Added local authentication support using PIN and Fingerprint.
* Deprecated getHeaders(fedAuthSecuredUrl, oauthScopes) and replaced it with getHeaders(options).
* Deprecated login(challengeCallback) and replaced it with login(). Challenge callback can be set in authentication properties builder.
* Deprecated init(authProps, timeoutCallback) and replaced it with init(authProps). Timeout callback can be set in authentication properties builder.

## 1.0.4 (May 18, 2018)
* Upgrade min SDK from 16 to 19

## 1.0.3 (Mar 20, 2018)
* Fixed issue with OpenId where an error page is displayed momentarily after login.

## 1.0.2 (Feb 8, 2018)
* Fix open id auth issue with android
* Fix issues with cordova-android 6.0

## 1.0.1 (Dec 5, 2017)
* Fix basic auth crash in ios when username and password is blank or null.

## 1.0.0 (Nov 13, 2017)
