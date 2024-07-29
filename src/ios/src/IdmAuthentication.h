/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import <Foundation/Foundation.h>
#import <Cordova/CDVCommandDelegate.h>
#import <Cordova/CDVPlugin.h>

#import "IDMMobileSDKv2Library.h"
#import "IdmAuthenticationPlugin.h"

NS_ASSUME_NONNULL_BEGIN

/**
 * Class used to perform authentication activities.
 * This class implements the protocols for handling the OMMSS lifecycle callbacks and timeout callbacks.
 */
@interface IdmAuthentication: NSObject<OMMobileSecurityServiceDelegate, OMAuthenticationContextDelegate>
-(nullable instancetype) initWithProperties:(NSDictionary<NSString *, NSObject *> *) properties
                         baseViewController:(nonnull UIViewController *)baseVc
                                   callback:(void(^)(IdmAuthentication* authFlow, NSError* error))setupCompletion;
- (void) startLogin: (id<CDVCommandDelegate>) commandDelegate
     withCallbackId: (NSString*) callbackId;
- (void) cancelLogin: (id<CDVCommandDelegate>) commandDelegate
     withCallbackId: (NSString*) callbackId;
- (void) finishLogin: (id<CDVCommandDelegate>) commandDelegate
      withCallbackId: (NSString*) callbackId
     challengeResult: (NSDictionary*) challengeFields;
- (void) isAuthenticated: (id<CDVCommandDelegate>) commandDelegate
          withCallbackId: (NSString*) callbackId
          withProperties: (NSDictionary*) properties;
- (void) getHeaders: (id<CDVCommandDelegate>) commandDelegate
     withCallbackId: (NSString*) callbackId
withFedAuthSecuredUrl: (NSString*) fedAuthSecuredUrl
    withOauthScopes: (NSSet*) scopes;
- (void) logout: (id<CDVCommandDelegate>) commandDelegate
 withCallbackId: (NSString*) callbackId
 withForgetOption:(BOOL) forget;
- (void) addTimeoutCallback: (id<CDVCommandDelegate>) commandDelegate
             withCallbackId: (NSString*) callbackId;
- (void) resetIdleTimeout: (id<CDVCommandDelegate>) commandDelegate
           withCallbackId: (NSString*) callbackId;
- (void) submitExternalBrowserChallengeResponse: (NSURL*) incomingUrl;
@end

NS_ASSUME_NONNULL_END
