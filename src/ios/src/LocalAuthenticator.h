/**
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import <Foundation/Foundation.h>
#import "IDMMobileSDKv2Library.h"
#import <Cordova/CDVCommandDelegateImpl.h>
#import <Cordova/CDVPluginResult.h>

@interface LocalAuthenticator : NSObject

+(LocalAuthenticator*) sharedInstance;

-(void) enabledLocalAuthsPrimaryFirst:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate;
-(void) enable:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate;
-(void) disable:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate;
-(void) authenticateBiometric:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate;
-(void) authenticatePin:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate;
-(void) changePin:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate;
-(void) getLocalAuthSupportInfo:(CDVInvokedUrlCommand*)command delegate:(CDVCommandDelegateImpl*) commandDelegate;
@end
