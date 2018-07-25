/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import <Foundation/Foundation.h>
#import <Cordova/CDVPlugin.h>
#import "AuthViewController.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * This class is the plugin entry point at iOS side.
 * All the cordova.exec calls ends up here.
 */
@interface IdmAuthenticationPlugin : CDVPlugin

@property (nonatomic, strong) AuthViewController* authViewController;

+ (NSDictionary*) errorToMap: (NSError*) error;
+ (CDVPluginResult*) errorToPluginResult: (NSError*) error;
+ (CDVPluginResult*) errorCodeToPluginResult: (NSString*) error;
- (void) setup:(CDVInvokedUrlCommand *) command;
- (void) startLogin:(CDVInvokedUrlCommand *) command;
- (void) finishLogin:(CDVInvokedUrlCommand *) command;
- (void) cancelLogin:(CDVInvokedUrlCommand *) command;
- (void) logout:(CDVInvokedUrlCommand *) command;
- (void) isAuthenticated:(CDVInvokedUrlCommand *) command;
- (void) getHeaders:(CDVInvokedUrlCommand *) command;
- (void) resetIdleTimeout:(CDVInvokedUrlCommand *) command;
- (void) addTimeoutCallback:(CDVInvokedUrlCommand *) command;

// Local Auth related methods
- (void) getLocalAuthDetails:(CDVInvokedUrlCommand *) command;
- (void) enableLocalAuth:(CDVInvokedUrlCommand *) command;
- (void) disableLocalAuth:(CDVInvokedUrlCommand *) command;
- (void) authenticatePin:(CDVInvokedUrlCommand *) command;
- (void) authenticateFingerPrint:(CDVInvokedUrlCommand *) command;
- (void) changePin:(CDVInvokedUrlCommand *) command;
@end


NS_ASSUME_NONNULL_END
