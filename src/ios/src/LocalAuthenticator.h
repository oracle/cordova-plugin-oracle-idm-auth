/**
 * Copyright (c) 2018, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import <Foundation/Foundation.h>
#import "IDMMobileSDKv2Library.h"
#import <Cordova/CDVCommandDelegate.h>
#import <Cordova/CDVPluginResult.h>

@interface LocalAuthenticator : NSObject

+(LocalAuthenticator*) sharedInstance;

-(void) enabledLocalAuthsPrimaryFirst:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) enable:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) disable:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) authenticateBiometric:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) authenticatePin:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) changePin:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) getLocalAuthSupportInfo:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) getPreference:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
-(void) setPreference:(CDVInvokedUrlCommand*)command delegate:(id<CDVCommandDelegate>) commandDelegate;
@end
