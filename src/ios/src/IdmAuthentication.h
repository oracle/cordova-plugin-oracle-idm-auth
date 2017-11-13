/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import <Foundation/Foundation.h>
#import <Cordova/CDVCommandDelegateImpl.h>
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
- (void) startLogin: (CDVCommandDelegateImpl*) commandDelegate
     withCallbackId: (NSString*) callbackId;
- (void) finishLogin: (CDVCommandDelegateImpl*) commandDelegate
      withCallbackId: (NSString*) callbackId
     challengeResult: (NSDictionary*) challengeFields;
- (void) isAuthenticated: (CDVCommandDelegateImpl*) commandDelegate
          withCallbackId: (NSString*) callbackId
          withProperties: (NSDictionary*) properties;
- (void) getHeaders: (CDVCommandDelegateImpl*) commandDelegate
     withCallbackId: (NSString*) callbackId
withFedAuthSecuredUrl: (NSString*) fedAuthSecuredUrl
    withOauthScopes: (NSSet*) scopes;
- (void) logout: (CDVCommandDelegateImpl*) commandDelegate
 withCallbackId: (NSString*) callbackId;
- (void) addTimeoutCallback: (CDVCommandDelegateImpl*) commandDelegate
             withCallbackId: (NSString*) callbackId;
- (void) resetIdleTimeout: (CDVCommandDelegateImpl*) commandDelegate
           withCallbackId: (NSString*) callbackId;
- (void) submitExternalBrowserChallengeResponse: (NSURL*) incomingUrl;
@end

NS_ASSUME_NONNULL_END
