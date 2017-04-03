/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import "IdmAuthenticationPlugin.h"
#import "IdmAuthentication.h"

NS_ASSUME_NONNULL_BEGIN

#ifdef DEBUG
#   define IdmLog(...) NSLog(__VA_ARGS__)
#else
#   define IdmLog(...)
#endif

NSMutableDictionary<NSString *, IdmAuthentication *>  *AUTH_CACHE;

@interface IdmAuthenticationPlugin() {
  dispatch_queue_t dispatchQueue;
}

@property (nonatomic, weak) IdmAuthentication* currentAuthFlow;
@end

@implementation IdmAuthenticationPlugin

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
    CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"P1005"];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId ];
    return;
  }

  IdmAuthentication* idmAuthentication = nil;
  NSError *error;
  idmAuthentication = [[IdmAuthentication alloc] initWithProperties:dictionary baseViewController:self.viewController error:&error];

  if (error) {
    IdmLog(@"Setup error, creation of OMSS instance failed");
    NSString* errorCode = [@(error.code) stringValue];
    CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorCode];
    [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    return;
  }

  NSString *uuid = [NSUUID UUID].UUIDString;
  AUTH_CACHE[uuid] = idmAuthentication;

  IdmLog(@"Setup success, returning AuthFlowKey: %@", uuid);
  [self.commandDelegate sendPluginResult:[CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:@{@"AuthFlowKey" : uuid}] callbackId:command.callbackId];
}

/**
 * Handles the login start on OMMSS instance.
 */
- (void) startLogin:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin startLogin");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];

  if (idmAuthentication) {
    [idmAuthentication startLogin:self.commandDelegate withCallbackId:command.callbackId];
    IdmLog(@"Plugin startLogin finished.");
  }
}

/**
 * Handles the login finish on OMMSS instance.
 */
- (void) finishLogin:(CDVInvokedUrlCommand *) command {
  IdmLog(@"Plugin finishLogin");
  IdmAuthentication* idmAuthentication = [self validateArgsAndGetAuth:command];
  if (idmAuthentication) {
    if (!command.arguments[1] || ![command.arguments[1] isKindOfClass:NSDictionary.class]) {
      CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"P1006"];
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
    [idmAuthentication logout:self.commandDelegate
               withCallbackId:command.callbackId];
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
    NSString* fedAuthSecuredUrl = nil;
    if ([command.arguments count] > 1) {
      fedAuthSecuredUrl = (NSString *) command.arguments[1];
    }
    [idmAuthentication getHeaders:self.commandDelegate
                   withCallbackId:command.callbackId
            withFedAuthSecuredUrl:fedAuthSecuredUrl];
    IdmLog(@"Plugin getHeaders finished");
  }
}

/**
 * Validates the arguments passed from javascript layer.
 */
- (IdmAuthentication*) validateArgsAndGetAuth:(CDVInvokedUrlCommand *) command {
  CDVPluginResult *result;
  NSString* errorMessage;
  IdmLog(@"Plugin validateArgsAndGetAuth: %@", command.arguments);

  if (!command.arguments || !(command.arguments.count > 0) ) {
    errorMessage = @"P1007";
  } else if (!command.arguments[0] || ![command.arguments[0] isKindOfClass:NSString.class]) {
    errorMessage = @"P1008";
  } else {
    NSString* authFlowKey = (NSString*) command.arguments[0];
    IdmLog(@"Auth flow key is %@", authFlowKey);

    if (!authFlowKey || !([authFlowKey length] > 0) || [authFlowKey isEqualToString:@"null"]) {
      errorMessage = @"P1008";
    } else  if (![AUTH_CACHE objectForKey:authFlowKey]) {
      errorMessage = @"P1009";
    } else {
      self.currentAuthFlow = AUTH_CACHE[authFlowKey];
      return self.currentAuthFlow;
    }
  }
  
  IdmLog(@"Plugin validateArgsAndGetAuth error: %@", errorMessage);
  result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];
  [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
  return nil;
}
@end

NS_ASSUME_NONNULL_END
