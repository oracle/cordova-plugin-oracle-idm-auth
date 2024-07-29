/**
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import "LocalAuthenticator.h"
#import "IdmAuthenticationPlugin.h"
#import "IDMMobileSDKv2Library.h"
#import "OMSecureStorage.h"

@import LocalAuthentication;

#define LOCAL_AUTH_BIOMETRIC @"cordova.plugins.IdmAuthFlows.Biometric"
#define LOCAL_AUTH_FINGERPRINT @"cordova.plugins.IdmAuthFlows.Fingerprint"
#define LOCAL_AUTH_PIN @"cordova.plugins.IdmAuthFlows.PIN"
#define LOCAL_AUTH_DEFAULT @"cordova.plugins.IdmAuthFlows.Default"
#define DEFAULT_AUTH_ID @"DefaultAuthInstance"
#define FALLBACK_RESULT @"fallback"
#define PROMPT_MESSAGE @"promptMessage"
#define PIN_FALLBACK_BUTTON_LABEL @"pinFallbackButtonLabel"

// Local auth availability states
#define ENROLLED @"Enrolled";
#define NOT_ENROLLED @"NotEnrolled";
#define LOCKED_OUT @"LockedOut";
#define NOT_AVAILABLE @"NotAvailable";

// Error codes
#define LOCAL_AUTHENTICATOR_NOT_FOUND @"70001" // Reuse existing code from IDM SDK
#define AUTHENTICATION_FAILED @"10408" // Reuse existing code from IDM SDK
#define AUTHENTICATION_CANCELLED @"10029" // Reuse existing code from IDM SDK
#define PIN_AUTHENTICATOR_NOT_ENABLED @"P1016"
#define DISABLE_PIN_BIOMETRIC_ENABLED @"P1017"
#define ERROR_ENABLING_AUTHENTICATOR @"P1018"
#define BIOMETRIC_NOT_ENABLED @"P1019"
#define SAVING_VALUE_TO_SECURED_STORAGE_FAILED @"P1022"
#define SAVING_VALUE_TO_DEFAULT_STORAGE_FAILED @"P1023"
#define GETTING_VALUE_FROM_SECURED_STORAGE_FAILED @"P1024"
#define GETTING_VALUE_FROM_DEFAULT_STORAGE_FAILED @"P1025"

#ifdef DEBUG
#  define IdmLog(...) NSLog(__VA_ARGS__)
#else
#  define IdmLog(...)
#endif

static LocalAuthenticator *shared = nil;
static OMLocalAuthenticationManager *sharedManager = nil;

@interface LocalAuthenticator()<OMBiometricFallbackDelegate>

@property (nonatomic, assign) Boolean authenticatedViaPin;
@property (nonatomic, assign) Boolean defaultAuthenticationEnabled;

@property (nonatomic, strong) OMFallbackAuthenticationCompletionBlock fallbackHandler;

@property (nonatomic, strong, nullable) id<CDVCommandDelegate> biometricAuthDelegate;
@property (nonatomic, copy, nullable) NSString* biometricAuthCallbackId;

@end

@implementation LocalAuthenticator

+(LocalAuthenticator*) sharedInstance {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedManager = [OMLocalAuthenticationManager sharedManager];
    [sharedManager useBiometricInsteadOfTouchID:YES];
    shared = [[LocalAuthenticator alloc] init];
    shared.defaultAuthenticationEnabled = [shared enableDefaultAuthenticator];
  });

  return shared;
}

-(void) enabledLocalAuthsPrimaryFirst:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate {
  NSString* authId = command.arguments[0];
  CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                               messageAsArray:[self getEnabled:authId]];
  [commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (BOOL) enableDefaultAuthenticator {
  NSString* authId = DEFAULT_AUTH_ID;
  NSError* enableError = nil;
  NSString* authenticatorName = LOCAL_AUTH_DEFAULT;
    
  OMAuthenticator* authenticator = [self getAuthenticator:authId authenticatorName:authenticatorName];
  if (authenticator != nil) {
    IdmLog(@"Authenticator is already enabled for type %@", authenticatorName);
    return YES;
  }
  
  NSString* instanceId = [self getInstanceId:authId authenticatorName:authenticatorName];
  [self registerAuthenticatorIfNeeded:authenticatorName error:&enableError];

  if (!enableError) {
    if ([sharedManager enableAuthentication:authenticatorName instanceId:instanceId error:&enableError]) {
      OMAuthenticator* authenticator = [self getAuthenticator:authId authenticatorName:authenticatorName];
      [authenticator authenticate:nil error:&enableError];
      if (authenticator == nil) {
        IdmLog(@"Something went wrong while enabling Default Authenticator.");
        return NO;
      }
    }
  }
  if (enableError) {
    IdmLog(@"Error Registering Default Authenticator");
    return NO;
  }
  return YES;
}

-(void) enable:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate {
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

  if ([authenticatorName isEqualToString:LOCAL_AUTH_FINGERPRINT] && [OMBiometricAuthenticator biometricType] != BiometryTypeTouchID) {
    IdmLog(@"Fingerprint cannot be enabled. Either the device does not support it or is not enrolled.");
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:BIOMETRIC_NOT_ENABLED]
                           callbackId:command.callbackId];
    return;
  }

  if ([authenticatorName isEqualToString:LOCAL_AUTH_BIOMETRIC] && [OMBiometricAuthenticator biometricType] == BiometryTypeNone) {
    IdmLog(@"Biometric cannot be enabled. Either the device does not support it or is not enrolled.");
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:BIOMETRIC_NOT_ENABLED]
                           callbackId:command.callbackId];
    return;
  }

  OMPinAuthenticator* pinAuthenticator = [self getPinAuthenticator:authId];
  if ([LOCAL_AUTH_BIOMETRIC isEqualToString:authenticatorName] || [LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName]) {
    if (pinAuthenticator == nil) {
      IdmLog(@"PIN authenticator should be enabled before biometric can be enabled.");
      [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:PIN_AUTHENTICATOR_NOT_ENABLED]
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

      if ([LOCAL_AUTH_BIOMETRIC isEqualToString:authenticatorName] || [LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName])
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

-(void) disable:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate {
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

  OMBiometricAuthenticator* biometricAuthenticator =  [self getBiometricAuthenticator:authId];
  if ([authenticatorName isEqualToString:LOCAL_AUTH_PIN] && biometricAuthenticator != nil) {
    IdmLog(@"Cannot disable PIN when biometric is enabled.");
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:DISABLE_PIN_BIOMETRIC_ENABLED]
                           callbackId:command.callbackId];
    return;
  }

  if ([LOCAL_AUTH_BIOMETRIC isEqualToString:authenticatorName] || [LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName])
    [[self getPinAuthenticator:authId] copyKeysFromKeyStore: [biometricAuthenticator keyStore]];

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

-(void) getPreference:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate {
    NSString* authId = command.arguments[0];
    NSString* key = command.arguments[1];
    NSString* result;
    NSError* getDefaultPreferenceError = nil;
    NSError* getSecuredPreferenceError = nil;

    //Attempt fetching data
    OMPinAuthenticator* pinAuthenticator = [self getPinAuthenticator:authId];
    if (pinAuthenticator == nil) {
      OMDefaultAuthenticator *defAuth = [self getDefaultAuthenticator:DEFAULT_AUTH_ID];
      result = [defAuth.secureStorage dataForId:key error:&getDefaultPreferenceError];
    }
    else {
      result = [pinAuthenticator.secureStorage dataForId:key error:&getSecuredPreferenceError];
      if(result == nil) {
        OMDefaultAuthenticator *defAuth = [self getDefaultAuthenticator:DEFAULT_AUTH_ID];
        result = [defAuth.secureStorage dataForId:key error:&getDefaultPreferenceError];
      }
    }
    [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:result] callbackId:command.callbackId];
}

-(void) setPreference:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate {
    NSString* authId = command.arguments[0];
    NSString* key = command.arguments[1];
    NSString* value = command.arguments[2];
    Boolean secure = [command.arguments[3] boolValue];
    NSError* setPreferenceError = nil;

    if(!secure) {
      //Check if Default Authenticator is Enabled
      if(!self.defaultAuthenticationEnabled) {
          [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:ERROR_ENABLING_AUTHENTICATOR]
                                 callbackId:command.callbackId];
      }

      //Attempt storing in default storage
      IdmLog(@"Storing in default storage");
      OMDefaultAuthenticator *defAuth = [self getDefaultAuthenticator:DEFAULT_AUTH_ID];
      if(value == nil)
        [defAuth.secureStorage deleteDataForId:key error:&setPreferenceError];
      else
        [defAuth.secureStorage saveDataForId:key data:value error:&setPreferenceError];

      //Verify error and send result to plugin
      if(setPreferenceError) {
        [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:SAVING_VALUE_TO_DEFAULT_STORAGE_FAILED]
                              callbackId:command.callbackId];
      }
      else {
        [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"Default Storage operation Successfull!!"] callbackId:command.callbackId];
      }

      return;
    }
    //Check if PIN Authenticator is Enabled
    OMPinAuthenticator* pinAuthenticator = [self getPinAuthenticator:authId];
    if (pinAuthenticator == nil) {
      IdmLog(@"No enabled authenticators");
      [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:PIN_AUTHENTICATOR_NOT_ENABLED]
                              callbackId:command.callbackId];
      return;
    }
    //Attempt storing in secured storage
    if (value == nil) 
      [pinAuthenticator.secureStorage deleteDataForId:key error:&setPreferenceError];
    else
      [pinAuthenticator.secureStorage saveDataForId:key data:value error:&setPreferenceError];

    //Verify error and send result to plugin
    if(setPreferenceError) {
      [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:SAVING_VALUE_TO_SECURED_STORAGE_FAILED]
                            callbackId:command.callbackId];
    }
    else {
      [commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:@"Secure Storage operation Successfull!!"] callbackId:command.callbackId];
    }
}

-(void) authenticateBiometric:(CDVInvokedUrlCommand*)command
            delegate:(id<CDVCommandDelegate>)commandDelegate {
  NSString* authId = command.arguments[0];
  NSString* authType = command.arguments[1];
  NSDictionary* localizedStrings = command.arguments[2];
  OMBiometricAuthenticator* biometricAuthenticator;

  if ([authType isEqualToString:LOCAL_AUTH_FINGERPRINT])
    biometricAuthenticator = [self getFingerprintAuthenticator:authId];
  else
    biometricAuthenticator = [self getBiometricAuthenticator:authId];

  if (biometricAuthenticator == nil) {
    [commandDelegate sendPluginResult:[IdmAuthenticationPlugin errorCodeToPluginResult:LOCAL_AUTHENTICATOR_NOT_FOUND]
                           callbackId:command.callbackId];
    return;
  }

  // The thread on which authenticate is called is blocked by SDK.
  // Because if this we need to get a new thread here. Blocking main thread will be fatal.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    NSError* authError = nil;
    BOOL isAuthenticated = NO;
    self.biometricAuthDelegate = commandDelegate;
    self.biometricAuthCallbackId = command.callbackId;
    self.authenticatedViaPin = NO;
    [biometricAuthenticator setDelegate:self];

    if (![localizedStrings isEqual:[NSNull null]]) {
      if (localizedStrings[PROMPT_MESSAGE])
        biometricAuthenticator.localizedBiometricUsingReason = localizedStrings[PROMPT_MESSAGE];
      if (localizedStrings[PIN_FALLBACK_BUTTON_LABEL])
        biometricAuthenticator.localizedFallbackTitle = localizedStrings[PIN_FALLBACK_BUTTON_LABEL];
    }

    isAuthenticated = [biometricAuthenticator authenticate:nil error:&authError];

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
            delegate:(id<CDVCommandDelegate>)commandDelegate {
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
         delegate:(id<CDVCommandDelegate>)commandDelegate {
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
    OMAuthenticator* biometricAuthenticator = [self getBiometricAuthenticator:authId];
    if (biometricAuthenticator) {
      [biometricAuthenticator updateAuthData:[self getAuthDataForPIN:command.arguments[1]]
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

-(void) getLocalAuthSupportInfo:(CDVInvokedUrlCommand*)command
                       delegate:(id<CDVCommandDelegate>)commandDelegate {
  NSMutableDictionary* auths = [[NSMutableDictionary alloc] init];
  auths[LOCAL_AUTH_PIN] = ENROLLED;
  auths[LOCAL_AUTH_FINGERPRINT] = [self getFingerprintSupportOnDevice];
  auths[LOCAL_AUTH_BIOMETRIC] = [self getBiometricSupportOnDevice];

  CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                                          messageAsDictionary:auths];
  [commandDelegate sendPluginResult:result callbackId:command.callbackId];
}

- (NSString*) getBiometricSupportOnDevice {
  NSError* error = nil;
  BOOL available = [OMBiometricAuthenticator canEnableBiometricAuthentication:&error];

  if (available)
    return ENROLLED;

  if (!error)
    return NOT_AVAILABLE;

  // Deduce the reason why biometrics is not evaluated using error returned.
  switch (error.code) {
    case LAErrorBiometryLockout:
      return LOCKED_OUT;
    case LAErrorBiometryNotEnrolled:
      return NOT_ENROLLED;
    default:
      return NOT_AVAILABLE;
  }
}

- (NSString*) getFingerprintSupportOnDevice {
  NSError* error = nil;
  BOOL available = [OMBiometricAuthenticator canEnableBiometricAuthentication:&error];

  if (available) {
    if ([OMBiometricAuthenticator biometricType] == BiometryTypeTouchID)
      return ENROLLED;
    return NOT_AVAILABLE;
  }

  if (!error)
    return NOT_AVAILABLE;

  // FaceID support is 11.0+ and if OS is lesser, then error is about TouchID.
  // In case of error when OS is >= 11.0, it could be either Face or Touch, so just return not available for touch.
  if (SYSTEM_VERSION_LESS_THAN(@"11.0")) {
    // Deduce the reason why biometrics is not evaluated using error returned.
    switch (error.code) {
      case LAErrorBiometryLockout:
        return LOCKED_OUT;
      case LAErrorBiometryNotEnrolled:
        return NOT_ENROLLED;
      default:
        return NOT_AVAILABLE;
    }
  }

  return NOT_AVAILABLE;
}


// OMBiometricFallbackDelegate touch ID fallback to PIN implementation
- (void)didSelectFallbackAuthentication:(NSError *)fallBackReason
                      completionHandler:(OMFallbackAuthenticationCompletionBlock)handler {
  self.fallbackHandler = handler;
  CDVPluginResult* result;
  if (fallBackReason.code == LAErrorUserCancel) {
    result = [IdmAuthenticationPlugin errorCodeToPluginResult:AUTHENTICATION_CANCELLED];
  } else {
    result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:FALLBACK_RESULT];
  }

  [self.biometricAuthDelegate sendPluginResult:result callbackId:self.biometricAuthCallbackId];
  self.biometricAuthDelegate = nil;
  self.biometricAuthCallbackId = nil;
}

// Utility methods

- (void)registerAuthenticatorIfNeeded:(NSString*)authenticatorName error:(NSError**)error {
  if ([sharedManager isAuthenticatorRegistered:authenticatorName])
    return;

  NSString *authenticatorClassName = [self authenticatorClassForType:authenticatorName];
  [sharedManager registerAuthenticator:authenticatorName
                             className:authenticatorClassName
                                 error:error];
}

- (NSString *)authenticatorClassForType:(NSString*)authenticatorName
{
  if ([LOCAL_AUTH_BIOMETRIC isEqualToString:authenticatorName] || [LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName])
    return NSStringFromClass([OMBiometricAuthenticator class]);
  if ([LOCAL_AUTH_PIN isEqualToString:authenticatorName])
    return NSStringFromClass([OMPinAuthenticator class]);
  if ([LOCAL_AUTH_DEFAULT isEqualToString:authenticatorName])
    return NSStringFromClass([OMDefaultAuthenticator class]);
  return nil;
}

-(OMAuthenticator*) getAuthenticator:(NSString*) authId authenticatorName:(NSString*) authenticatorName {
  if ([LOCAL_AUTH_PIN isEqualToString:authenticatorName])
    return [self getPinAuthenticator:authId];
  else if ([LOCAL_AUTH_FINGERPRINT isEqualToString:authenticatorName])
    return [self getFingerprintAuthenticator:authId];
  else if ([LOCAL_AUTH_BIOMETRIC isEqualToString:authenticatorName])
    return [self getBiometricAuthenticator:authId];
  else if ([LOCAL_AUTH_DEFAULT isEqualToString:authenticatorName])
    return [self getDefaultAuthenticator:authId];
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

-(OMDefaultAuthenticator*) getDefaultAuthenticator:(NSString*) authId {
  NSString* instanceId = [self getInstanceId:authId authenticatorName:LOCAL_AUTH_DEFAULT];
  if (![sharedManager isAuthenticatorRegistered:LOCAL_AUTH_DEFAULT])
    return nil;

  OMAuthenticator* auth = [sharedManager authenticatorForInstanceId:instanceId error:nil];
  if (auth && [auth isKindOfClass:[OMDefaultAuthenticator class]]) {
    return (OMDefaultAuthenticator*) auth;
  }
  return nil;
}

-(OMBiometricAuthenticator*) getFingerprintAuthenticator:(NSString*) authId {
  NSString* instanceId = [self getInstanceId:authId authenticatorName:LOCAL_AUTH_FINGERPRINT];

  if (![sharedManager isAuthenticatorRegistered:LOCAL_AUTH_FINGERPRINT])
    return nil;

  OMAuthenticator* auth = [sharedManager authenticatorForInstanceId:instanceId error:nil];
  if (auth && [auth isKindOfClass:[OMBiometricAuthenticator class]])
    return (OMBiometricAuthenticator*) auth;

  return nil;
}

-(OMBiometricAuthenticator*) getBiometricAuthenticator:(NSString*) authId {
  NSString* instanceId = [self getInstanceId:authId authenticatorName:LOCAL_AUTH_BIOMETRIC];

  if (![sharedManager isAuthenticatorRegistered:LOCAL_AUTH_BIOMETRIC])
    return nil;

  OMAuthenticator* auth = [sharedManager authenticatorForInstanceId:instanceId error:nil];
  if (auth && [auth isKindOfClass:[OMBiometricAuthenticator class]])
    return (OMBiometricAuthenticator*) auth;

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

  NSObject* biometricAuthenticator = [self getBiometricAuthenticator:authId];
  NSObject* fingerprintAuthenticator = [self getFingerprintAuthenticator:authId];
  NSObject* pinAuthenticator = [self getPinAuthenticator:authId];

  if (biometricAuthenticator != nil)
    [auths addObject:LOCAL_AUTH_BIOMETRIC];
  if (fingerprintAuthenticator != nil)
    [auths addObject:LOCAL_AUTH_FINGERPRINT];
  if (pinAuthenticator != nil)
    [auths addObject:LOCAL_AUTH_PIN];

  IdmLog(@"Enabled authenticators: %@", auths);
  return auths;
}
@end
