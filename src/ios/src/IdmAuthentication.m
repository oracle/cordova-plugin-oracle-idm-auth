/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import "IdmAuthentication.h"
#import "AuthViewController.h"
#import "IDMMobileSDKv2Library.h"
#import <SafariServices/SafariServices.h>

NS_ASSUME_NONNULL_BEGIN

#define NO_AUTH_CONTEXT_ERR_CODE @"P1010"
#define UNSUPPORTED_CHALLENGE_ERR_CODE @"P1003"
#define UNTRUSTED_SERVER_ERR_CODE @"P1002"
#define INVALID_REDIRECT_ERR_CODE @"P1001"
#define EXTERNAL_BROWSER_LAUNCH_FAILED @"P1012"
#define AUTHENTICATION_FAILED @"10408" // Reuse existing code from IDM SDK
#define SESSION_TIMEOUT @"SESSION_TIMEOUT"
#define IDLE_TIMEOUT @"IDLE_TIMEOUT"
#define OK @"OK"
#define TIMEOUT_TYPE_KEY @"TimeoutType"
#define TIME_LEFT_TO_TIMEOUT_KEY @"TimeLeftToTimeout"
#define AUTH_VIEW @"AuthView"
#define AUTH_WEB_VIEW @"AuthWebView"
#define CHALLENGE_ERROR @"error"
#define PROP_ENABLE_WEB_VIEW_BUTTONS @"EnableWebViewButtons"
#define LOGIN_DIALOG_TITLE @"Please provide credentials"
#define USERNAME_PLACEHOLDER @"Enter Username"
#define PASSWORD_PLACEHOLDER @"Enter Password"


#ifdef DEBUG
#  define IdmLog(...) NSLog(__VA_ARGS__)
#else
#  define IdmLog(...)
#endif

@interface IdmAuthentication()<SFSafariViewControllerDelegate>

/**
 * Authentication properties used for creating the OMMSS instance.
 */
@property (nonatomic, copy) NSDictionary<NSString *, NSObject *>*  properties;

/**
 * OMMSS instance.
 */
@property (nonatomic, strong, nullable) OMMobileSecurityService*   ommss;

/**
 * Callback details for returning the result for login or logout to javascript layer.
 */
@property (nonatomic, strong, nullable) id<CDVCommandDelegate>    loginLogoutCommandDelegate;
@property (nonatomic, copy, nullable) NSString*                    loginLogoutCallbackId;

/**
 * Callback details for returning the result for timeout to javascript layer.
 */
@property (nonatomic, strong, nullable) id<CDVCommandDelegate>    timeoutCommandDelegate;
@property (nonatomic, copy, nullable) NSString*                    timeoutCallbackId;

/**
 * Base view controller used for launching the webview view controller
 * for webview based authentications.
 */
@property (nonatomic, weak, nullable) UIViewController*            baseViewController;

/**
 * Webview view controller used for webview based authentications.
 */
@property (nonatomic, weak, nullable) AuthViewController*          authViewController;

/**
 * The login or logout challenge object.
 */
@property (nonatomic, strong, nullable) OMAuthenticationChallenge* challenge;

/**
 * If the current challenge being processed is a webview based challenge or not.
 */
@property (atomic, assign) BOOL                                    isWebViewLaunched;

/**
 * Boolean to indicate if app wants to use WkWebView.
 */
@property (nonatomic, assign) BOOL                                 isWkWebViewEnabled;

/**
 * Error when setup is completed.
 */
@property (nonatomic, nullable) NSError*                           setupError;

/**
 * List of buttons to be displayed.
 */
@property (nonatomic, strong, nullable) NSMutableArray*            availableButtons;

/**
 * Callback method reference to proceed when setup is completed.
 */
@property (nonatomic, weak, nullable) void (^setupCompletionCallback)(IdmAuthentication*, NSError*);

@end

@implementation IdmAuthentication

BOOL _isExpectingExternalBrowserResponse;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpartial-availability"
SFSafariViewController *_safariVC;
#pragma clang diagnostic pop

/**
 * Create a new instance of IdmAuthentication using the specified configuration properties.
 * Throws and error if the specified configuration properties are not valid
 * or if there was an error while creating the OMMSS instance
 *
 * @param properties: the configuration properties to use
 * @param baseVc: the base view controller.
 */
-(nullable instancetype) initWithProperties:(NSDictionary<NSString *, NSObject *> *) properties
                         baseViewController:(nonnull UIViewController *)baseVc
                                   callback:(void(^)(IdmAuthentication* authFlow, NSError* error)) setupCompletion {
  if (self = [super init]) {
    self.setupCompletionCallback = setupCompletion;
    self.properties = properties;
    self.baseViewController = baseVc;

    self.availableButtons = (NSMutableArray*) [properties valueForKey:PROP_ENABLE_WEB_VIEW_BUTTONS];

    NSMutableDictionary* authProps = [NSMutableDictionary dictionaryWithDictionary:properties];
    NSSet* scopeSet = [self extractScopeSet:properties];

    if (scopeSet) {
      authProps[OM_PROP_OAUTH_SCOPE] = scopeSet;
    }

    self.isWkWebViewEnabled = (BOOL) authProps[OM_PROP_ENABLE_WKWEBVIEW];
    self.isWebViewLaunched = NO;
    _isExpectingExternalBrowserResponse = NO;
    NSError* error;
    self.ommss = [[OMMobileSecurityService alloc] initWithProperties:authProps delegate:self error:&error];

    if (error != nil) {
      setupCompletion(self, error);
    } else {
      [self.ommss setup];
    }
  }
  return self;
}

/**
 * Starts the login process on the OMMSS instance.
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 */
-(void) startLogin:(id<CDVCommandDelegate>) commandDelegate
        withCallbackId: (NSString*) callbackId {
  IdmLog(@"startLogin invoked");
  NSError* error = [self.ommss startAuthenticationProcess:nil];

  // Ignore error code 10534. It denotes that one login is already in progress.
  if (error != nil && error.code == 10534) {
    IdmLog(@"Login is already in progress. Current login attempt will be aborted.");
    return;
  }

  self.loginLogoutCommandDelegate = commandDelegate;
  self.loginLogoutCallbackId = callbackId;

  if (error != nil) {
    IdmLog(@"startLogin error invoking ommss startAuthenticationProcess %@", error);
    [self throwErrorToLoginCallback:error];
  }

  IdmLog(@"startLogin completed");
}

/**
 * Cancel the login process on the OMMSS instance.
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 */
-(void) cancelLogin:(id<CDVCommandDelegate>) commandDelegate
        withCallbackId: (NSString*) callbackId {
  IdmLog(@"cancelLogin invoked");
  self.loginLogoutCommandDelegate = commandDelegate;
  self.loginLogoutCallbackId = callbackId;
  self.challenge.authChallengeHandler(nil, OMCancel);
  IdmLog(@"cancelLogin invoked completed.");
}
/**
 * Finish the login process on the OMMSS instance. This method is invoked after
 * collecting required credentials from the user at the javascript layer.
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 * @param challengeFields: The filled up challenge fields map.
 */
-(void) finishLogin:(id<CDVCommandDelegate>)commandDelegate
        withCallbackId:(NSString *)callbackId
        challengeResult: (NSDictionary*) challengeFields {
  IdmLog(@"Finish login received %@", challengeFields);

  if (challengeFields[CHALLENGE_ERROR] != nil) {
    NSMutableDictionary* fields = [NSMutableDictionary dictionaryWithDictionary:challengeFields];
    [fields removeObjectForKey:CHALLENGE_ERROR];
    challengeFields = fields;
  }

  self.loginLogoutCommandDelegate = commandDelegate;
  self.loginLogoutCallbackId = callbackId;
  self.challenge.authChallengeHandler(challengeFields, OMProceed);
  IdmLog(@"Finish login completed.");
}

/**
 * Query OMMSS instance to find out if the user is currently authenticated or not.
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 * @param properties: extra properties if any
 */
- (void) isAuthenticated: (id<CDVCommandDelegate>) commandDelegate
         withCallbackId: (NSString*) callbackId
         withProperties: (NSDictionary*) properties {
  IdmLog(@"isAuthenticated invoked");
  if ([properties isKindOfClass:[NSNull class]]) {
    properties = nil;
  }

  OMAuthenticationContext* context = [self.ommss authenticationContext];
  BOOL isValid;
  NSString* authType = (NSString*) self.properties[OM_PROP_AUTHSERVER_TYPE];

  if (context == nil) {
    isValid = NO;
  } else if ([OM_PROP_OAUTH_OAUTH20_SERVER isEqualToString:authType] ||
        [OM_PROP_OPENID_CONNECT_SERVER isEqualToString:authType]) {
    isValid = [self checkIsValidForOauth: context props:properties];
  } else {
    isValid = [context isValid];
  }

  CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                          messageAsDictionary: @{@"isAuthenticated" : [NSNumber numberWithBool:isValid]}];
  [commandDelegate sendPluginResult:result callbackId:callbackId];
  IdmLog(@"isAuthenticated completed: %d", isValid);
}

- (BOOL) checkIsValidForOauth: (OMAuthenticationContext*) context
                        props:(NSDictionary*) properties {
  // There is no reason why we should not refresh the expired token if we can.
  BOOL refreshExpiredTokens = YES;
  NSSet* scopeSet = [[NSSet alloc] init];

  if (properties) {
    scopeSet = [self extractScopeSet:properties];
    refreshExpiredTokens = [(NSNumber*) properties[@"refreshExpiredTokens"] boolValue];
  }

  return [[self.ommss authenticationContext] isValidForScopes:scopeSet refreshExpiredToken:refreshExpiredTokens];
}

/**
 * Query OMMSS instance for authentication headers (if any).
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 * @param fedAuthSecuredUrl: The secured URL for which cookies and headers have to be retrieved. Applicable only for Federated Auth usecase.
 */
- (void) getHeaders: (id<CDVCommandDelegate>) commandDelegate
     withCallbackId: (NSString*) callbackId
withFedAuthSecuredUrl: (NSString*) fedAuthSecuredUrl
    withOauthScopes: (NSSet*) scopes{
  IdmLog(@"getHeaders invoked");
  OMAuthenticationContext* context = [self.ommss authenticationContext];

  if (context == nil) {
    CDVPluginResult* result = [IdmAuthenticationPlugin errorCodeToPluginResult:NO_AUTH_CONTEXT_ERR_CODE];
    [commandDelegate sendPluginResult:result callbackId:callbackId];
    return;
  }

  NSMutableDictionary* returnHeaders  = [[NSMutableDictionary alloc] init];
  NSString* authType = (NSString*) self.properties[OM_PROP_AUTHSERVER_TYPE];

  if ([OM_PROP_AUTHSERVER_HTTPBASIC isEqualToString:authType]) {
    returnHeaders = [self headersForBasicAuth:context];
  } else if ([OM_PROP_AUTHSERVER_FED_AUTH isEqualToString:authType]) {
    // SAML case, return OAUTH tokens as well
    if ([(NSNumber*) self.properties[OM_PROP_PARSE_TOKEN_RELAY_RESPONSE] boolValue] == YES)
      [returnHeaders addEntriesFromDictionary:[self headersForOAuth:scopes context:context]];
    if (fedAuthSecuredUrl != nil)
      [returnHeaders addEntriesFromDictionary:[self headersForFedAuth:fedAuthSecuredUrl context:context]];
  } else if ([OM_PROP_OAUTH_OAUTH20_SERVER isEqualToString:authType] || [OM_PROP_OPENID_CONNECT_SERVER isEqualToString:authType]) {
    returnHeaders = [self headersForOAuth:scopes context:context];
  }

  [returnHeaders addEntriesFromDictionary:[context customHeaders]];
  CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnHeaders];
  [commandDelegate sendPluginResult:result callbackId:callbackId];
  IdmLog(@"getHeaders completed headers");
}

/**
 * Logout.
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 */
-(void) logout:(id<CDVCommandDelegate>)commandDelegate
withCallbackId:(NSString *)callbackId
withForgetOption:(BOOL) forget {
  IdmLog(@"logout invoked with forget %@", forget ? @"YES": @"NO");
  self.loginLogoutCommandDelegate = commandDelegate;
  self.loginLogoutCallbackId = callbackId;
  [_ommss logout:forget];
  IdmLog(@"logout completed");
}

/**
 * This method is used to set a timeout callback during the OMMSS instance creation.
 * If this timeout callback is set, OMMSS callbacks during session timeout and idle timeout
 * will be passed along to this to the javascript layer.
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 */
- (void) addTimeoutCallback: (id<CDVCommandDelegate>) commandDelegate
         withCallbackId: (NSString*) callbackId {
  IdmLog(@"addTimeoutCallback invoked");
  self.timeoutCommandDelegate = commandDelegate;
  self.timeoutCallbackId = callbackId;
  IdmLog(@"addTimeoutCallback completed");
}

/**
 * This method is used to reset the idle timeout.
 * If an error occurs, the error code is communicated back to the javascript layer.
 *
 * @param commandDelegate: callback
 * @param callbackId: callback id
 */
- (void) resetIdleTimeout: (id<CDVCommandDelegate>) commandDelegate
         withCallbackId: (NSString*) callbackId {
  IdmLog(@"resetIdleTimeout invoked");
  OMAuthenticationContext* context = [self.ommss authenticationContext];
  if (context == nil) {
    CDVPluginResult* result = [IdmAuthenticationPlugin errorCodeToPluginResult:NO_AUTH_CONTEXT_ERR_CODE];
    [commandDelegate sendPluginResult:result callbackId:callbackId];
    return;
  }

  [context resetTimer:OMIdleTimer];
  CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:OK];
  [commandDelegate sendPluginResult:result callbackId:callbackId];
  IdmLog(@"resetIdleTimeout completed");
}

- (void) submitExternalBrowserChallengeResponse: (NSURL*) incomingUrl {
  if (_isExpectingExternalBrowserResponse) {
    // Reset the value of _isExpectingExternalBrowserResponse after didFinishAuthentication or didFinishLogout
    // in the cleanup activity.
    NSMutableDictionary* fields = [[NSMutableDictionary alloc] init];
    fields[@"frontChannelResponse"] = incomingUrl;
    self.challenge.authChallengeHandler(fields, OMProceed);
  } else {
    IdmLog(@"Not expecting a external browser challenge response, ignoring.");
  }
}

-(void) mobileSecurityService:(OMMobileSecurityService *)mss
completedSetupWithConfiguration:(OMMobileSecurityConfiguration *)configuration
                        error:(NSError *)error;
{
  IdmLog(@"completedSetupWithConfiguration");
  self.setupCompletionCallback(self, error);
  IdmLog(@"completedSetupWithConfiguration done with Error %@", error);
}

/**
 * Method to show login dialog.
 */
- (void) showLoginDialog: (NSDictionary*) fields{
  UIAlertController* loginAlert = [UIAlertController alertControllerWithTitle:LOGIN_DIALOG_TITLE message:nil preferredStyle:UIAlertControllerStyleAlert];
  
  [loginAlert addTextFieldWithConfigurationHandler:^(UITextField* usernameField) {
    usernameField.placeholder = USERNAME_PLACEHOLDER;
    usernameField.clearButtonMode = UITextFieldViewModeWhileEditing;
    usernameField.borderStyle = UITextBorderStyleRoundedRect;
  }];

  [loginAlert addTextFieldWithConfigurationHandler:^(UITextField* passwordField) {
    passwordField.placeholder = PASSWORD_PLACEHOLDER;
    passwordField.clearButtonMode = UITextFieldViewModeWhileEditing;
    passwordField.borderStyle = UITextBorderStyleRoundedRect;
    passwordField.secureTextEntry = YES;
  }];
  
  
  UIAlertAction* submitAction = [UIAlertAction actionWithTitle: @ "Submit"
                            style: UIAlertActionStyleDefault handler: ^ (UIAlertAction * _Nonnull action) {

    [fields setValue:loginAlert.textFields[0].text forKey:OM_USERNAME];
    [fields setValue:loginAlert.textFields[1].text forKey:OM_PASSWORD];
    
    self.challenge.authChallengeHandler(fields, OMProceed);
    NSLog(@ "Submit Tapped");
  }];
  
  UIAlertAction* cancelAction = [UIAlertAction actionWithTitle: @ "Cancel"
                            style: UIAlertActionStyleDefault handler: ^ (UIAlertAction * _Nonnull action) {
    [self dismissAuthView];
    self.challenge.authChallengeHandler(nil, OMCancel);
    NSLog(@ "Cancel Tapped");
  }];
  
  [loginAlert addAction: submitAction];
  [loginAlert addAction: cancelAction];

  [self.authViewController presentViewController:loginAlert animated: true completion: nil];
}

/**
 * OMMobileSecurityServiceDelegate protocol implementation
 */
-(void) mobileSecurityService:(OMMobileSecurityService *)mss
        didReceiveAuthenticationChallenge:(OMAuthenticationChallenge *)challenge {
  IdmLog(@"didReceiveAuthenticationChallenge received %@", challenge.authData);
  self.challenge = challenge;
  NSMutableDictionary *fields = [NSMutableDictionary dictionaryWithDictionary:self.challenge.authData];
  NSError* error = fields[@"mobileSecurityException"];

  if (error) {
    fields[CHALLENGE_ERROR] = [IdmAuthenticationPlugin errorToMap:error];
    [fields removeObjectForKey:OM_MOBILESECURITY_EXCEPTION];
  }

  if (challenge.challengeType == OMChallengeUsernamePassword) {
    if([fields objectForKey:@"webview_key"]) {
      [self showLoginDialog:fields];
    }
    else {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:@{@"challengeFields": fields}];
      [self.loginLogoutCommandDelegate sendPluginResult:result callbackId:self.loginLogoutCallbackId];
      IdmLog(@"Sending challenge back to user to fill up.");
        
      return;
    }
  } else if (challenge.challengeType == OMChallengeEmbeddedBrowser) {
    self.challenge = challenge;
    IdmLog(@"Launching webview and redirecting user to login web page.");
    [self launchAndGetWebView:^(NSObject* webView) {
      [fields setValue:webView forKey:OM_PROP_AUTH_WEBVIEW];
      challenge.authChallengeHandler(fields, OMProceed);
    }
               loginChallenge:YES];
  } else if (challenge.challengeType == OMChallengeInvalidRedirect) {
    NSString* authType = (NSString*) self.properties[OM_PROP_AUTHSERVER_TYPE];
    if ([OM_PROP_OAUTH_OAUTH20_SERVER isEqualToString:authType]) {
      NSString* redirectEndPoint = (NSString*) self.properties[OM_PROP_OAUTH_REDIRECT_ENDPOINT];
      if ([@"http://localhost" isEqualToString:redirectEndPoint]) {
        IdmLog(@"Invalid redirect challenge for redirect end point http://localhost. The challenge will be accepted transparently.");
        challenge.authChallengeHandler(nil, OMProceed);
      } else {
        IdmLog(@"Invalid redirect challenge received. Throwing error to callback");
        [self throwErrorCodeToLoginCallback:INVALID_REDIRECT_ERR_CODE];
      }
    } else {
      IdmLog(@"Invalid redirect challenge received. Throwing error to callback");
      [self dismissAuthView];
      [self throwErrorCodeToLoginCallback:INVALID_REDIRECT_ERR_CODE];
    }
  } else if (challenge.challengeType == OMChallengeExternalBrowser) {
    [self handleExternalBrowserChallenge: [fields valueForKey:@"frontChannelURL"]];
  } else if (challenge.challengeType == OMChallengeServerTrust) {
    IdmLog(@"Untrusted server challenge received. Throwing error to callback");
    [self dismissAuthView];
    [self throwErrorCodeToLoginCallback:UNTRUSTED_SERVER_ERR_CODE];
  } else {
    IdmLog(@"Unsupported challenge %lu.", (unsigned long)challenge.challengeType);
    [self dismissAuthView];
    [self throwErrorCodeToLoginCallback:UNSUPPORTED_CHALLENGE_ERR_CODE];
  }
}

/**
 * OMMobileSecurityServiceDelegate protocol implementation
 */
-(void) mobileSecurityService:(OMMobileSecurityService *)mss
        didFinishAuthentication:(OMAuthenticationContext *)context
        error:(NSError *)error {
  [self dismissAuthView];

  if (error) {
    IdmLog(@"didFinishAuthentication error %@", error);
    [self throwErrorToLoginCallback:error];
  } else {
    // In case of iOS the context delegate has to be assigned after login.
    // In case of Android context delegate is assigned before login.
    // The plugin lifecycle is designed with timeout callback registration during init.
    // Retain that and for iOS assign the context delegate after login.
    if (self.timeoutCallbackId != nil) {
      context.delegate = self;
    }
    IdmLog(@"didFinishAuthentication success");
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:OK];
    [self.loginLogoutCommandDelegate sendPluginResult:result callbackId:self.loginLogoutCallbackId];
  }
  [self clearCallbackState];
}

/**
 * OMMobileSecurityServiceDelegate protocol implementation
 */
-(void) mobileSecurityService:(OMMobileSecurityService *)mss
        didReceiveLogoutAuthenticationChallenge:(OMAuthenticationChallenge *)challenge {
  IdmLog(@"didReceiveLogoutAuthenticationChallenge received %@", challenge.authData);
  self.challenge = challenge;
  NSMutableDictionary *fields = [NSMutableDictionary dictionaryWithDictionary:self.challenge.authData];
  if (challenge.challengeType == OMChallengeEmbeddedBrowser) {
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithDictionary:challenge.authData];
    [self launchAndGetWebView:^(NSObject* webView) {
      [dictionary setValue:webView forKey:OM_PROP_AUTH_WEBVIEW];
      challenge.authChallengeHandler(dictionary, OMProceed);
    }
               loginChallenge:NO];
  } else if (challenge.challengeType == OMChallengeExternalBrowser) {
    [self handleExternalBrowserChallenge: [fields valueForKey:@"LogoutURL"]];
  }
  IdmLog(@"didReceiveLogoutAuthenticationChallenge complete..");
}

/**
 * OMMobileSecurityServiceDelegate protocol implementation
 */
-(void) mobileSecurityService:(OMMobileSecurityService *)mss
        didFinishLogout:(NSError *)error {
  [self dismissAuthView];

  if (error) {
    IdmLog(@"didFinishLogout error %@", error);
    [self throwErrorToLoginCallback:error];
  } else {
    IdmLog(@"didFinishLogout success");
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:OK];
    [self.loginLogoutCommandDelegate sendPluginResult:result callbackId:self.loginLogoutCallbackId];
  }
  [self clearCallbackState];
}

/**
 * OMAuthenticationContextDelegate protocol implementation
 */
- (void) authContext:(OMAuthenticationContext *)context
         timeoutOccuredForTimer:(OMTimerType)timerType
         remainingTime:(NSTimeInterval)duration {
  IdmLog(@"timeoutOccuredForTimer invoked");
  NSString* timerTypeStr;
  if (timerType == OMIdleTimer) {
    timerTypeStr = IDLE_TIMEOUT;
  } else if (timerType == OMSessionTimer) {
    timerTypeStr = SESSION_TIMEOUT;
  }
  CDVPluginResult* result = [CDVPluginResult  resultWithStatus:CDVCommandStatus_OK messageAsDictionary:@{TIMEOUT_TYPE_KEY: timerTypeStr, TIME_LEFT_TO_TIMEOUT_KEY: [@(duration) stringValue] }];
  [result setKeepCallback:[NSNumber numberWithBool:YES]];
  [self.timeoutCommandDelegate sendPluginResult:result callbackId:self.timeoutCallbackId];
}

/**
 * Method to add error sting as result of the loginLogoutCommandDelegate.
 */
- (void) throwErrorCodeToLoginCallback:(NSString *) err {
  CDVPluginResult* result = [IdmAuthenticationPlugin errorCodeToPluginResult:err];
  [self.loginLogoutCommandDelegate sendPluginResult:result callbackId:self.loginLogoutCallbackId];
}

/**
 * Method to add error sting as result of the loginLogoutCommandDelegate.
 */
- (void) throwErrorToLoginCallback:(NSError *) err {
  CDVPluginResult* result =  [IdmAuthenticationPlugin errorToPluginResult:err];
  [self.loginLogoutCommandDelegate sendPluginResult:result callbackId:self.loginLogoutCallbackId];
}

/**
 * Method to launch the webview view controller.
 */
- (void) launchAndGetWebView:(void(^)(NSObject* webView)) completionCallback
              loginChallenge:(BOOL) isLogin {
  IdmLog(@"launchAndGetWebView invoked");

  if ([NSThread currentThread] != [NSThread mainThread]) {
    IdmLog(@"Attempt to launch webview from non main thread...");
  }

  dispatch_async(dispatch_get_main_queue(), ^{
    UIStoryboard *mainStoryboard = [UIStoryboard storyboardWithName:AUTH_WEB_VIEW bundle:nil];
    self.authViewController = (AuthViewController*) [mainStoryboard instantiateViewControllerWithIdentifier:AUTH_VIEW];
    [self.authViewController setAuthenticationInstance:self.ommss];
    [self.authViewController setAvailableWebButtonList:self.availableButtons];
    [self.authViewController isWkWebViewEnabled:self.isWkWebViewEnabled];
    [self.authViewController setIsLoginChallenge:isLogin];
    [self.baseViewController presentViewController:self.authViewController animated:YES completion:^{
      NSObject* webView __unused = nil;
      if ([OMMobileSecurityConfiguration isWKWebViewAvailable]) {
        webView = self.authViewController.wkWebView;
      }

      if (webView == nil) {
        IdmLog(@"Launching webview has failed.");
      } else {
        IdmLog(@"launchAndGetWebView completed");
        self.isWebViewLaunched = YES;
      }

      completionCallback(webView);
    }];
  });
}

/**
 * Method to handle case when app is using EXTERNAL browser.
 * Uses SFSafariViewController for iOS9 and later, Safari browser for older
 * Official support for the plugin is only from iOS 10.3, but this is a cheap
 * fallback for older devices.
 */
- (void) handleExternalBrowserChallenge:(NSURL *) url {
  IdmLog(@"Handling external browser challenge");
  BOOL urlLaunched = NO;
  if (@available(iOS 9.0, *)) {
    SFSafariViewController *safariVC =
    [[SFSafariViewController alloc] initWithURL:url];
    safariVC.delegate = self;
    _safariVC = safariVC;
    [self.baseViewController presentViewController:safariVC animated:YES completion:nil];
    urlLaunched = YES;
  } else {
    // Older iOS, use mobile Safari
    urlLaunched = [[UIApplication sharedApplication] openURL:url];
  }

  if (!urlLaunched) {
    [self cleanUpExternalAuthViewState];
    [self throwErrorCodeToLoginCallback:EXTERNAL_BROWSER_LAUNCH_FAILED];
  } else {
    _isExpectingExternalBrowserResponse = YES;
  }
}

/**
 * Method to dismiss any auth view that is open.
 */
- (void) dismissAuthView {
  [self dismissInAppBrowser];
  [self dismissAuthWebView];
}

/**
 * Method to dismiss auth web view used in case of EMBEDDED browser.
 */
- (void) dismissAuthWebView {
  if (!self.isWebViewLaunched)
    return;

  IdmLog(@"dismissAuthWebView invoked");

  dispatch_async(dispatch_get_main_queue(), ^{
    [self.authViewController dismissViewControllerAnimated:YES completion:nil];
    self.authViewController = nil;
    self.isWebViewLaunched = NO;
  });

  IdmLog(@"dismissAuthWebView completed");
}

/**
 * Dismisses the appropriate external view that was launched in case of EXTERNAL browser.
 */
- (void)dismissInAppBrowser {
  if (!_isExpectingExternalBrowserResponse)
    return;

  IdmLog(@"dismissInAppBrowser invoked");

  dispatch_async(dispatch_get_main_queue(), ^{
    if (@available(iOS 9.0, *)) {
      if (_safariVC)
        [_safariVC dismissViewControllerAnimated:YES completion:nil];
    }

    [self cleanUpExternalAuthViewState];
  });

  IdmLog(@"dismissInAppBrowser completed");
}

/**
 * Cleans up external view state.
 */
- (void) cleanUpExternalAuthViewState {
  _safariVC = nil;
  _isExpectingExternalBrowserResponse = NO;
}


/**
 * Method used to clear the login / logout callback and the challenge references.
 */
- (void) clearCallbackState {
  self.loginLogoutCommandDelegate = nil;
  self.loginLogoutCallbackId = nil;
  self.challenge = nil;
}

/**
 * Extract scope set from authentication properties dictionary.
 * @param authProps: authentication properties - not null
 * @return NSSet* of scope set.
 */
- (NSSet*) extractScopeSet:(NSDictionary*) authProps {
  NSSet* scopeSet = nil;
  NSArray* scope = authProps[OM_PROP_OAUTH_SCOPE];
  if (scope) {
    scopeSet = [NSSet setWithArray:scope];
  }
  return scopeSet;
}

- (NSMutableDictionary*) headersForOAuth: (NSSet*) scopes
                                 context: (OMAuthenticationContext*) context {
  NSMutableDictionary* headers = [[NSMutableDictionary alloc] init];
  // Ideally this is not needed. Because of iOS SDK bug, we need to pass "*" when scope is nil
  if (!scopes) {
    scopes = [NSSet setWithObject:@"*"];
  }
  NSArray* tokens = [context tokensForScopes:scopes];
  NSString* tokenValue;
  NSDate* sessionExpiryDate;

  if ([tokens count] > 0) {
    tokenValue = ((OMToken*) [tokens objectAtIndex:0]).tokenValue;
    sessionExpiryDate = ((OMToken*) [tokens objectAtIndex:0]).sessionExpiryDate;

    headers[@"Authorization"] = [NSString stringWithFormat:@"Bearer %@", tokenValue];
    headers[@"ExpiryTime"] = [NSString stringWithFormat:@"%@", sessionExpiryDate];
  }

  return headers;
}

- (NSMutableDictionary*) headersForFedAuth: (NSString*) fedAuthSecuredUrl
                                   context: (OMAuthenticationContext*) context {
  NSDictionary* cookiesAndHeader = [context requestParametersForURL:fedAuthSecuredUrl includeHeaders:NO];
  return [NSMutableDictionary dictionaryWithDictionary:cookiesAndHeader];
}

- (NSMutableDictionary*) headersForBasicAuth: (OMAuthenticationContext*) context {
  NSMutableDictionary* headers = [[NSMutableDictionary alloc] init];
  NSDictionary* credentials = [context credentialInformationForKeys:@[OM_PROP_CREDENTIALS]];
  NSString* userName = credentials[OM_PROP_CREDENTIALS_USERNAME];
  NSString* password = credentials[OM_PROP_CREDENTIALS_PASSWORD];

  if (userName != nil && password != nil) {
    NSString *authorization = [NSString stringWithFormat:@"%@:%@", userName, password];
    NSData *nsdata = [authorization dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
    NSString *base64EncodedAuthHeader = [nsdata base64EncodedStringWithOptions:0];
    NSString *authHeader = [NSString stringWithFormat:@"Basic %@", base64EncodedAuthHeader];
    headers[OM_AUTHORIZATION] = authHeader;
  }

  return headers;
}


#pragma mark - SFSafariViewControllerDelegate

- (void)safariViewControllerDidFinish:(SFSafariViewController *)controller NS_AVAILABLE_IOS(9.0) {
  // Ignore this call if the safari view controller do not match.
  if (controller != _safariVC)
    return;

  // Ignore this call if there is no authorization flow in progress.
  if (!_isExpectingExternalBrowserResponse)
    return;

  [self cleanUpExternalAuthViewState];
}

@end
NS_ASSUME_NONNULL_END
