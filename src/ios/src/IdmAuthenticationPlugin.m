/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import "IdmAuthenticationPlugin.h"
#import "IdmAuthentication.h"
#import "LocalAuthenticator.h"

NS_ASSUME_NONNULL_BEGIN

#define ERROR_CODE @"errorCode"
#define ERROR_SOURCE @"errorSource"
#define TRANSLATED_ERROR_MSG @"translatedErrorMessage"
#define PLUGIN_ERROR_SOURCE @"plugin"
#define SYSTEM_ERROR_SOURCE @"system"
#define UNEXPECTED_OBJECT_IN_INIT @"P1005"
#define NO_CHALLENGE_FIELDS @"P1006"
#define AUTH_FLOW_KEY_EXPECTED @"P1007"
#define NULL_OR_EMPTY_AUTH_FLOW_KEY @"P1008"
#define NO_AUTH_CONTEXT_ERROR_CODE @"P1010"
#define INVALID_AUTH_FLOW_KEY @"P1009"
#define SETUP_ERROR @"10015" // Reuse existing code from IDM SDK

#ifdef DEBUG
#   define IdmLog(...) NSLog(__VA_ARGS__)
#else
#   define IdmLog(...)
#endif

NSMutableDictionary<NSString *, IdmAuthentication *>  *AUTH_CACHE;

@interface IdmAuthenticationPlugin() {
  dispatch_queue_t dispatchQueue;
}

@property (nonatomic, strong) IdmAuthentication* currentAuthFlow;
@property (nonatomic, strong, nullable) void (^setupCompletionCallback)(IdmAuthentication*, NSError*);

@end

@implementation IdmAuthenticationPlugin

+ (CDVPluginResult*) errorToPluginResult: (NSError*) error {
  return [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[IdmAuthenticationPlugin errorToMap:error]];
}

+ (NSDictionary*) errorToMap: (NSError*) error {
  NSString* errorSource = PLUGIN_ERROR_SOURCE;
  NSString* translatedErrorMessage = @"";
  if (!([[error domain] isEqualToString:@"ORAIDMMOBILE"])) {
    errorSource = SYSTEM_ERROR_SOURCE;
    translatedErrorMessage = error.localizedDescription;
  }

  return @{ERROR_CODE: [@(error.code) stringValue], ERROR_SOURCE: errorSource, TRANSLATED_ERROR_MSG: translatedErrorMessage};
}

+ (CDVPluginResult*) errorCodeToPluginResult: (NSString*) errorCode {
  return [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:@{ERROR_CODE: errorCode,
                                                                                        ERROR_SOURCE: PLUGIN_ERROR_SOURCE,
                                                                                        TRANSLATED_ERROR_MSG: @""}];
}

- (instancetype) init {
  if (self = [super init]) {
    dispatchQueue = dispatch_queue_create("IdmAuthenticationPlugin Queue", DISPATCH_QUEUE_CONCURRENT);
  }
  return self;
}

- (void) pluginInitialize {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    AUTH_CACHE = [[NSMutableDictionary alloc] init];
  });
}

- (void)handleOpenURL:(NSNotification*)notification {
  IdmLog(@"Handle open url received notification.");
  id notificationObject = notification.object;

  if ([notificationObject isKindOfClass:[NSURL class]] && self.currentAuthFlow != nil) {
    [self.currentAuthFlow submitExternalBrowserChallengeResponse:(NSURL*) notificationObject];
  }

  [super handleOpenURL:notification];
}

/**
 * Handles the initial setup of an OMMSS instance based on the authentication properties provided.
 */
- (void) setup:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Setup with command args: %@", command.arguments);
  NSDictionary *dictionary = nil;

  if (command.arguments && [command.arguments count] > 0 && [command.arguments[0] isKindOfClass:NSDictionary.class]) {
    IdmLog(@"Setup converting command arg [0] to NSDictionary.");
    dictionary = (NSDictionary *) command.arguments[0];
  }

  if (dictionary == nil || [dictionary isKindOfClass:[NSNull class]]) {
    IdmLog(@"Setup error, map of props missing.");
    CDVPluginResult *result = [IdmAuthenticationPlugin errorCodeToPluginResult:UNEXPECTED_OBJECT_IN_INIT];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId ];
    return;
  }

  __weak id<CDVCommandDelegate> delegate = self.commandDelegate;

  self.setupCompletionCallback = ^(IdmAuthentication * authFlow, NSError * error) {
    if (error != nil) {
      IdmLog(@"Setup error, creation of OMSS instance failed: %@", error);
      CDVPluginResult *result = [IdmAuthenticationPlugin errorToPluginResult:error];
      [delegate sendPluginResult:result callbackId:command.callbackId];
      return;
    }

    if (authFlow == nil) {
      IdmLog(@"Setup error, null OMMSS instance returned.");
      CDVPluginResult *result = [IdmAuthenticationPlugin errorCodeToPluginResult:SETUP_ERROR];
      [delegate sendPluginResult:result callbackId:command.callbackId];
      return;
    }

    NSString *uuid = [NSUUID UUID].UUIDString;
    AUTH_CACHE[uuid] = authFlow;

    IdmLog(@"Setup success, returning AuthFlowKey: %@", uuid);
    [delegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:@{@"AuthFlowKey" : uuid}] callbackId:command.callbackId];
  };

  self.currentAuthFlow = [[IdmAuthentication alloc] initWithProperties:dictionary
                                                    baseViewController:self.viewController
                                                              callback:self.setupCompletionCallback];
}

/**
 * Handles the login start on OMMSS instance.
 */
- (void) startLogin:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin startLogin");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];

  if (idmAuthentication) {
    [idmAuthentication startLogin:self.commandDelegate withCallbackId:command.callbackId];
  }
  IdmLog(@"Plugin startLogin finished.");
}

/**
 * Handles cancellation of login on OMMSS instance.
 */
- (void) cancelLogin:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin cancelLogin");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];

  if (idmAuthentication) {
    [idmAuthentication cancelLogin:self.commandDelegate withCallbackId:command.callbackId];
  }
  IdmLog(@"Plugin cancelLogin finished.");
}


/**
 * Handles the login finish on OMMSS instance.
 */
- (void) finishLogin:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin finishLogin");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];
  if (idmAuthentication) {
    if (!command.arguments[1] || ![command.arguments[1] isKindOfClass:NSDictionary.class]) {
      CDVPluginResult* result = [IdmAuthenticationPlugin errorCodeToPluginResult:NO_CHALLENGE_FIELDS];
      [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
      return;
    }
    NSDictionary* challengeFields = (NSDictionary *) command.arguments[1];
    [idmAuthentication finishLogin:self.commandDelegate
                    withCallbackId:command.callbackId
                   challengeResult:challengeFields];

  }
}

/**
 * Handles the logout on OMMSS instance.
 */
- (void) logout:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin logout");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];
  if (idmAuthentication) {
    BOOL forget = [command.arguments[1] boolValue];
    [idmAuthentication logout:self.commandDelegate
               withCallbackId:command.callbackId
               withForgetOption:forget];
    IdmLog(@"Plugin logout finished");
  }
}

/**
 * Handles the isValid on OMMSS instance.
 */
- (void) isAuthenticated:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin isAuthenticated");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];
  if (idmAuthentication) {
    NSDictionary* extraProps = nil;
    if ([command.arguments count] > 1) {
      extraProps = (NSDictionary *) command.arguments[1];
    }
    [idmAuthentication isAuthenticated:self.commandDelegate
                        withCallbackId:command.callbackId
                        withProperties:extraProps];
    IdmLog(@"Plugin isAuthenticated finished");
  }
}

/**
 * Handles the timeout callback addition on OMMSS instance.
 */
- (void) addTimeoutCallback:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin addTimeoutCallback");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];
  if (idmAuthentication) {
    [idmAuthentication addTimeoutCallback:self.commandDelegate
                           withCallbackId:command.callbackId];
    IdmLog(@"Plugin addTimeoutCallback finished");
  }
}

/**
 * Handles the reset idle timeout on OMMSS instance.
 */
- (void) resetIdleTimeout:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin resetIdleTimeout");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];
  if (idmAuthentication) {
    [idmAuthentication resetIdleTimeout:self.commandDelegate
                         withCallbackId:command.callbackId];
    IdmLog(@"Plugin resetIdleTimeout finished");
  }
}

/**
 * Handles collecting headers from OMMSS instance.
 */
- (void) getHeaders:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin getHeaders");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];
  if (idmAuthentication) {
    NSArray* args = command.arguments;
    NSString* fedAuthSecuredUrl = nil;
    NSSet* scopeSet = nil;

    if ([args count] > 1 && [args[1] isKindOfClass:[NSString class]]) {
      fedAuthSecuredUrl = (NSString *) args[1];
    }

    if ([args count] > 2 && [args[2] isKindOfClass:[NSArray class]]) {
      NSArray* scope = (NSArray*) args[2];
      if (scope) {
        scopeSet = [NSSet setWithArray:scope];
      }

    }

    [idmAuthentication getHeaders:self.commandDelegate
                   withCallbackId:command.callbackId
            withFedAuthSecuredUrl:fedAuthSecuredUrl
                  withOauthScopes:scopeSet];
    IdmLog(@"Plugin getHeaders finished");
  }
}

// Local auth related methods
- (void) enabledLocalAuthsPrimaryFirst:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] enabledLocalAuthsPrimaryFirst:command delegate:self.commandDelegate];
}
- (void) enableLocalAuth:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] enable:command delegate:self.commandDelegate];
}
- (void) disableLocalAuth:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] disable:command delegate:self.commandDelegate];
}
- (void) authenticatePin:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] authenticatePin:command
                                              delegate:self.commandDelegate];
}
- (void) authenticateBiometric:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] authenticateBiometric:command
                                                    delegate:self.commandDelegate];
}
- (void) changePin:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] changePin:command
                                        delegate:self.commandDelegate];
}
- (void) getLocalAuthSupportInfo:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] getLocalAuthSupportInfo:command
                                                      delegate:self.commandDelegate];
}

- (void) getPreference:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] getPreference:command
                                                      delegate:self.commandDelegate];
}

- (void) setPreference:(CDVInvokedUrlCommand *) command {
  [[LocalAuthenticator sharedInstance] setPreference:command
                                                      delegate:self.commandDelegate];
}

/**
 * Validates the arguments passed from javascript layer.
 */
- (IdmAuthentication*) validateArgsAndGetAuth:(CDVInvokedUrlCommand *) command {
  CDVPluginResult *result;
  NSString* errorMessage;

  if (!command.arguments || !(command.arguments.count > 0) ) {
    errorMessage = AUTH_FLOW_KEY_EXPECTED;
  } else if (!command.arguments[0] || ![command.arguments[0] isKindOfClass:NSString.class]) {
    errorMessage = NULL_OR_EMPTY_AUTH_FLOW_KEY;
  } else {
    NSString* authFlowKey = (NSString*) command.arguments[0];
    IdmLog(@"Auth flow key is %@", authFlowKey);

    if (!authFlowKey || !([authFlowKey length] > 0) || [authFlowKey isEqualToString:@"null"]) {
      errorMessage = NULL_OR_EMPTY_AUTH_FLOW_KEY;
    } else  if (![AUTH_CACHE objectForKey:authFlowKey]) {
      errorMessage = INVALID_AUTH_FLOW_KEY;
    } else {
      self.currentAuthFlow = AUTH_CACHE[authFlowKey];
      if (self.currentAuthFlow)
        return self.currentAuthFlow;
      errorMessage = NO_AUTH_CONTEXT_ERROR_CODE;
    }
  }

  IdmLog(@"Plugin validateArgsAndGetAuth error: %@", errorMessage);
  result = [IdmAuthenticationPlugin errorCodeToPluginResult:errorMessage];
  [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
  return nil;
}
@end

NS_ASSUME_NONNULL_END
