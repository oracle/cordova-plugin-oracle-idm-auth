# Release Notes

## 1.1.0
- Added local authentication support using PIN and Fingerprint.
- Deprecated getHeaders(fedAuthSecuredUrl, oauthScopes) and replaced it with getHeaders(options).
- Deprecated login(challengeCallback) and replaced it with login(). Challenge callback can be set in authentication properties builder.
- Deprecated init(authProps, timeoutCallback) and replaced it with init(authProps). Timeout callback can be set in authentication properties builder.

## 1.0.4
- Upgrade min SDK from 16 to 19

## 1.0.3
- Fixed issue with OpenId where an error page is displayed momentarily after login.

## 1.0.2 (Feb 8, 2018)
- Fix open id auth issue with android
- Fix issues with cordova-android 6.0

## 1.0.1 (Dec 5, 2017)
- Fix basic auth crash in ios when username and password is blank or null.

## 1.0.0 (Nov 13, 2017)
