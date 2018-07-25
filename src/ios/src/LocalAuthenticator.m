/**
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import "LocalAuthenticator.h"
#import "IdmAuthenticationPlugin.h"
#import "IDMMobileSDKv2Library.h"

#define LOCAL_AUTH_FINGERPRINT @"cordova.plugins.IdmAuthFlows.Fingerprint"
#define LOCAL_AUTH_PIN @"cordova.plugins.IdmAuthFlows.PIN"

#define LOCAL_AUTHENTICATOR_NOT_FOUND @"70001" // Reuse existing code from IDM SDK
#define AUTHENTICATION_FAILED @"10408" // Reuse existing code from IDM SDK
#define FINGERPRINT_CANCELLED @"10029" // Reuse existing code from IDM SDK
#define PIN_AUTHENTICATOR_NOT_ENABLED @"P1016"
#define DISABLE_PIN_FINGERPRINT_ENABLED @"P1017"
#define ERROR_ENABLING_AUTHENTICATOR @"P1018"
#define FINGERPRINT_NOT_ENABLED @"P1019"

#ifdef DEBUG
#  define IdmLog(...) NSLog(__VA_ARGS__)
#else
#  define IdmLog(...)
#endif

static LocalAuthenticator *shared = nil;
static OMLocalAuthenticationManager *sharedManager = nil;

@interface LocalAuthenticator()<OMTouchIDFallbackDelgate>

@property (nonatomic, assign) Boolean authenticatedViaPin;
@property (nonatomic, strong) OMFallbackAuthenticationCompletionBlock fallbackHandler;

@property (nonatomic, strong, nullable) CDVCommandDelegateImpl* touchAuthDelegate;
@property (nonatomic, copy, nullable) NSString* touchAuthCallbackId;

@end

@implementation LocalAuthenticator

+(LocalAuthenticator*) sharedInstance {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedManager = [OMLocalAuthenticationManager sharedManager];
    shared = [[LocalAuthenticator alloc] init];
  });

  return shared;
}

-(void) enabledLocalAuthsPrimaryFirst:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate {
  NSString* authId = command.arguments[0];
  [self getEnabled:authId];
  CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                               messageAsArray:[self getEnabled:authId]];
  [commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

-(void) enable:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate {
  NSError* enableError = nil;
  NSString* authId = command.arguments[0];
  NSString* authenticatorName = command.arguments[1];
  NSString* pin = command.arguments[2];

  OMAuthenticator* authenticator = [self getAuthenticator:authId authenticatorName:authenticatorName];

  if (authenticator != nil) {
    IdmLog(@"Authenticator is already enabled for type %@", authenticatorName);
    [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK] callbackId:command.callbackId];
    return;
  }

  OMPinAuthenticator* pinAuthenticator = [self getPinAuthenticator:authId];
  if ([authenticatorName isEqualToString:LOCAL_AUTH_FINGERPRINT]) {
    if (pinAuthenticator == nil) {
      IdmLog(@"PIN authenticator should be enabled before fingerprint can be enabled.");
      [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:PIN_AUTHENTICATOR_NOT_ENABLED]
                             callbackId:command.callbackId];
      return;
    }
    if (![OMTouchIDAuthenticator canEnableTouchID:nil]) {
      IdmLog(@"Fingerprint cannot be enabled. Either the device does not support it or fingerprint is not enrolled.");
      [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:FINGERPRINT_NOT_ENABLED]
                             callbackId:command.callbackId];
      return;
    }
  }
  NSString* instanceId = [self getInstanceId:authId authenticatorName:authenticatorName];
  [self registerAuthenticatorIfNeeded:authenticatorName error:&enableError];

  if (!enableError) {
    if ([sharedManager enableAuthentication:authenticatorName
                                 instanceId:instanceId
                                      error:&enableError]) {
      OMAuthenticator* authenticator = [self getAuthenticator:authId authenticatorName:authenticatorName];

      if (authenticator == nil) {
        IdmLog(@"Something went wrong while enabling authentication.");
        [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:ERROR_ENABLING_AUTHENTICATOR]
                               callbackId:command.callbackId];
        return;
      }
      [authenticator setAuthData:[self getAuthDataForPIN:pin] error:&enableError];

      if ([LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName])
        [authenticator copyKeysFromKeyStore:[pinAuthenticator keyStore]];
    }
  }

  if (enableError) {
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorToPluginResult:enableError]
                           callbackId:command.callbackId];
    return;
  }

  [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK] callbackId:command.callbackId];
}

-(void) disable:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate {
  NSError* disableError = nil;
  NSString* authId = command.arguments[0];
  NSString* authenticatorName = command.arguments[1];

  OMAuthenticator* authenticator = [self getAuthenticator:authId authenticatorName:authenticatorName];

  if (authenticator == nil) {
    IdmLog(@"Authenticator is not enabled for type %@", authenticatorName);
    [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                        messageAsString:[self getEnabledPrimary:authId]]
                           callbackId:command.callbackId];
    return;
  }

  OMTouchIDAuthenticator* touchAuthenticator =  [self getTouchIdAuthenticator:authId];
  if ([authenticatorName isEqualToString:LOCAL_AUTH_PIN] && touchAuthenticator != nil) {
    IdmLog(@"Cannot disable PIN when fingerprint is enabled.");
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:DISABLE_PIN_FINGERPRINT_ENABLED]
                           callbackId:command.callbackId];
    return;
  }

  if ([authenticatorName isEqualToString:LOCAL_AUTH_FINGERPRINT])
    [[self getPinAuthenticator:authId] copyKeysFromKeyStore: [touchAuthenticator keyStore]];

  NSString* instanceId = [self getInstanceId:authId authenticatorName:authenticatorName];
  [sharedManager disableAuthentication:instanceId error:&disableError];

  if (disableError) {
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorToPluginResult:disableError]
                           callbackId:command.callbackId];
    return;
  }

  [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                                      messageAsString:[self getEnabledPrimary:authId]]
                         callbackId:command.callbackId];
}

-(void) authenticateFingerPrint:(CDVInvokedUrlCommand*)command
            delegate:(CDVCommandDelegateImpl*)commandDelegate {
  NSString* authId = command.arguments[0];
  NSDictionary* localizedStrings = command.arguments[1];

  OMTouchIDAuthenticator* touchIdAuthenticator = [self getTouchIdAuthenticator:authId];

  if (touchIdAuthenticator == nil) {
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:LOCAL_AUTHENTICATOR_NOT_FOUND]
                           callbackId:command.callbackId];
    return;
  }

  // The thread on which authenticate is called is blocked by SDK.
  // Because if this we need to get a new thread here. Blocking main thread will be fatal.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    NSError* authError = nil;
    BOOL isAuthenticated = NO;
    self.touchAuthDelegate = commandDelegate;
    self.touchAuthCallbackId = command.callbackId;
    self.authenticatedViaPin = NO;
    [touchIdAuthenticator setDelegate:self];

    if (localizedStrings[@"promptMessage"])
      touchIdAuthenticator.localizedTouchIdUsingReason = localizedStrings[@"promptMessage"];
    if (localizedStrings[@"pinFallbackButtonLabel"])
      touchIdAuthenticator.localizedFallbackTitle = localizedStrings[@"pinFallbackButtonLabel"];

    isAuthenticated = [touchIdAuthenticator authenticate:nil error:&authError];

    if (!self.authenticatedViaPin) {
      CDVPluginResult* result;
      if (isAuthenticated)
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
      else if (authError)
        result = [IdmAuthenticationPlugin errorToPluginResult: authError];
      else
        result = [IdmAuthenticationPlugin errorCodeToPluginResult:AUTHENTICATION_FAILED];

      [commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }
  });
}

-(void) authenticatePin:(CDVInvokedUrlCommand*)command
            delegate:(CDVCommandDelegateImpl*)commandDelegate {
  NSError *authError = nil;
  NSString* authId = command.arguments[0];
  NSString* pin = command.arguments[1];
  OMPinAuthenticator* pinAuthenticator = [self getPinAuthenticator:authId];
  BOOL isAuthenticated = NO;
  if (pinAuthenticator == nil) {
    if (self.fallbackHandler != nil) {
      self.fallbackHandler(NO);
      self.fallbackHandler = nil;
    }
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:LOCAL_AUTHENTICATOR_NOT_FOUND]
                           callbackId:command.callbackId];
    return;
  }

  isAuthenticated = [pinAuthenticator authenticate:[self getAuthDataForPIN:pin]
                                             error:&authError];
  if (self.fallbackHandler != nil) {
    self.fallbackHandler(isAuthenticated);
    self.fallbackHandler = nil;
    self.authenticatedViaPin = YES;
  }

  CDVPluginResult* result;
  if (isAuthenticated) {
    result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
  } else if (authError)
    result = [IdmAuthenticationPlugin errorToPluginResult: authError];
  else
    result = [IdmAuthenticationPlugin errorCodeToPluginResult:AUTHENTICATION_FAILED];

  [commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

-(void) changePin:(CDVInvokedUrlCommand*)command
         delegate:(CDVCommandDelegateImpl*)commandDelegate {
  NSError* changePinError;
  NSString* authId = command.arguments[0];
  OMPinAuthenticator* pinAuthenticator = [self getPinAuthenticator:authId];

  if (pinAuthenticator == nil) {
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:LOCAL_AUTHENTICATOR_NOT_FOUND]
                           callbackId:command.callbackId];
    return;
  }

  [pinAuthenticator updateAuthData:[self getAuthDataForPIN:command.arguments[1]]
                       newAuthData:[self getAuthDataForPIN:command.arguments[2]]
                             error:&changePinError];

  if (!changePinError) {
    OMAuthenticator* touchAuthenticator = [self getTouchIdAuthenticator:authId];
    if (touchAuthenticator) {
      [touchAuthenticator updateAuthData:[self getAuthDataForPIN:command.arguments[1]]
                             newAuthData:[self getAuthDataForPIN:command.arguments[2]]
                                   error:&changePinError];
    }
  }

  if (changePinError) {
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorToPluginResult:changePinError]
                           callbackId:command.callbackId];
    return;
  }

  [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK] callbackId:command.callbackId];
}

// OMTouchIDFallbackDelgate touch ID fallback to PIN implementation
- (void)didSelectFallbackAuthentication:(NSError *)fallBackReason
                      completionHandler:(OMFallbackAuthenticationCompletionBlock)handler;
{
  self.fallbackHandler = handler;
  CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"fallback"];
  [self.touchAuthDelegate sendPluginResult:result callbackId:self.touchAuthCallbackId];
  self.touchAuthDelegate = nil;
  self.touchAuthCallbackId = nil;
}

// Utility methods

- (void)registerAuthenticatorIfNeeded:(NSString*)authenticatorName error:(NSError**)error;
{
  if ([sharedManager isAuthenticatorRegistered:authenticatorName])
    return;

  NSString *authenticatorClassName = [self authenticatorClassForType:authenticatorName];
  [sharedManager registerAuthenticator:authenticatorName
                             className:authenticatorClassName
                                 error:error];
}

- (NSString *)authenticatorClassForType:(NSString*)authenticatorName
{
  if ([LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName])
    return NSStringFromClass([OMTouchIDAuthenticator class]);
  if ([LOCAL_AUTH_PIN isEqualToString:authenticatorName])
    return NSStringFromClass([OMPinAuthenticator class]);
  return nil;
}

-(OMAuthenticator*) getAuthenticator:(NSString*) authId authenticatorName:(NSString*) authenticatorName {
  if ([LOCAL_AUTH_PIN isEqualToString:authenticatorName])
    return [self getPinAuthenticator:authId];
  else if ([LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName])
    return [self getTouchIdAuthenticator:authId];
  return nil;
}

-(OMPinAuthenticator*) getPinAuthenticator:(NSString*) authId {
  NSString* instanceId = [self getInstanceId:authId authenticatorName:LOCAL_AUTH_PIN];
  if (![sharedManager isAuthenticatorRegistered:LOCAL_AUTH_PIN])
    return nil;

  OMAuthenticator* auth = [sharedManager authenticatorForInstanceId:instanceId error:nil];
  if (auth && [auth isKindOfClass:[OMPinAuthenticator class]]) {
    return (OMPinAuthenticator*) auth;
  }
  return nil;
}

-(OMTouchIDAuthenticator*) getTouchIdAuthenticator:(NSString*) authId {
  NSString* instanceId = [self getInstanceId:authId authenticatorName:LOCAL_AUTH_FINGERPRINT];
  if (![sharedManager isAuthenticatorRegistered:LOCAL_AUTH_FINGERPRINT])
    return nil;

  OMAuthenticator* auth = [sharedManager authenticatorForInstanceId:instanceId error:nil];
  if (auth && [auth isKindOfClass:[OMTouchIDAuthenticator class]]) {
    return (OMTouchIDAuthenticator*) auth;
  }
  return nil;
}

- (NSString*) getInstanceId: (NSString*) instanceId authenticatorName:(NSString*) authenticatorName {
  return [NSString stringWithFormat:@"%@.%@", instanceId, authenticatorName];
}

- (OMAuthData*) getAuthDataForPIN: (NSString*) pin {
  return [[OMAuthData alloc] initWithData:[pin dataUsingEncoding:NSUTF8StringEncoding]];
}

- (NSString*) getEnabledPrimary: (NSString*) authId {
  NSArray* enabled = [self getEnabled:authId];

  if ([enabled count] != 0)
    return enabled[0];

  return @"";
}

- (NSArray*) getEnabled: (NSString*) authId {
  NSMutableArray* auths = [[NSMutableArray alloc] init];

  NSObject* touchIdAuthenticator = [self getTouchIdAuthenticator:authId];
  NSObject* pinAuthenticator = [self getPinAuthenticator:authId];

  if (touchIdAuthenticator != nil)
    [auths addObject:LOCAL_AUTH_FINGERPRINT];
  if (pinAuthenticator != nil)
    [auths addObject:LOCAL_AUTH_PIN];

  IdmLog(@"Enabled authenticators: %@", auths);
  return auths;
}
@end
