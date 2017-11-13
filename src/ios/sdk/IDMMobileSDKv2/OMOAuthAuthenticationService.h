/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMAuthenticationService.h"
#import "OMOAuthConfiguration.h"

@class OMAuthorizationGrant;

@interface OMOAuthAuthenticationService : OMAuthenticationService {
    
}

@property (nonatomic, strong) OMAuthorizationGrant *grantFlow;
@property (nonatomic, strong) NSString *accessToken;
@property (nonatomic) NSUInteger expiryTimeInSeconds;
@property (nonatomic, strong) NSString *refreshToken;
@property (nonatomic) NSUInteger nextStep;
@property (nonatomic) BOOL frontChannelRequestDone;
@property (nonatomic, strong) NSString *userName;
@property (nonatomic, strong) NSString *password;
@property (nonatomic, weak) OMOAuthConfiguration *config;
@property (nonatomic) NSUInteger retryCount;

- (void)openURLInBrowser:(NSURL *)url;
- (void)processOAuthResponse:(NSDictionary *)urlQueryDict;
- (void)performAuthentication:(NSMutableDictionary *)authData
                        error:(NSError *__autoreleasing *)error;
- (void)performBackChannelRequest:(NSDictionary *)data;
- (void)setAuthContext;
- (void)sendFinishAuthentication:(id)object;
+ (NSError *)oauthErrorFromResponse:(NSDictionary *)response
                      andStatusCode:(NSInteger)code;
- (NSDictionary *)parseFrontChannelResponse:(NSURL *)url;
- (void)storeOfflineCredential:(OMAuthenticationContext *)ctx;
- (void)setGrantFlowManually;
@end
