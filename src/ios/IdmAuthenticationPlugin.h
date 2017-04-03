/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
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

- (void) setup:(CDVInvokedUrlCommand *) command;
- (void) startLogin:(CDVInvokedUrlCommand *) command;
- (void) finishLogin:(CDVInvokedUrlCommand *) command;
- (void) logout:(CDVInvokedUrlCommand *) command;
- (void) isAuthenticated:(CDVInvokedUrlCommand *) command;
- (void) getHeaders:(CDVInvokedUrlCommand *) command;
- (void) resetIdleTimeout:(CDVInvokedUrlCommand *) command;
- (void) addTimeoutCallback:(CDVInvokedUrlCommand *) command;
@end


NS_ASSUME_NONNULL_END
