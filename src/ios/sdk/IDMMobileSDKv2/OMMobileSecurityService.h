/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>
#import "OMMobileSecurityConfiguration.h"
#import "OMAuthenticationContext.h"
#import "OMAuthenticationRequest.h"
#import "OMAuthenticationChallenge.h"


@class OMAuthenticationManager;
@protocol OMMobileSecurityServiceDelegate;

@interface OMMobileSecurityService : NSObject

@property (nonatomic, strong) id<OMMobileSecurityServiceDelegate> delegate;
@property (nonatomic, strong) OMMobileSecurityConfiguration *configuration;
@property (nonatomic, strong) OMAuthenticationManager *authManager;

@property (nonatomic, strong) NSMutableDictionary *cacheDict;
- (id)initWithProperties: (NSDictionary *)properties
                delegate: (id<OMMobileSecurityServiceDelegate>) delegate
                   error:(NSError **)error;
-(NSError *)setup;
-(NSError *)startAuthenticationProcess:(OMAuthenticationRequest*)request;

-(void)logout:(BOOL)clearRegistrationHandles;
-(NSString *)authKey;
-(NSString *)offlineAuthKey;
-(NSString *)rememberCredKey;
-(NSString *) offlineAuthenticationKeyWithIdentityDomain:(NSString *)identityDomain
                                                 username:(NSString *)username;
-(NSString *) maxRetryKeyWithIdentityDomain:(NSString *)identityDomain
                                    username:(NSString *)username;
-(void)clearRememberCredentials:(BOOL)clearPreferences;
-(void)cancelAuthentication;
+(NSArray *)cookiesForURL: (NSURL *)theURL;
-(OMAuthenticationContext *)authenticationContext;
-(NSData *)symmetricEncryptionKey;
-(NSDictionary *)logoutHeaders:(OMAuthenticationContext *)ctx;
-(void)clearOfflineCredentials:(BOOL)clearPreferences;


@end

@protocol OMMobileSecurityServiceDelegate <NSObject>
@required
-(void)mobileSecurityService:(OMMobileSecurityService *)mss
didReceiveAuthenticationChallenge:(OMAuthenticationChallenge *)challenge;
-(void)mobileSecurityService:(OMMobileSecurityService *)mss
     didFinishAuthentication:(OMAuthenticationContext *)context
                       error:(NSError *)error;
-(void)mobileSecurityService:(OMMobileSecurityService *)mss
             didFinishLogout:(NSError *)error;
@optional
-(void)mobileSecurityService:(OMMobileSecurityService *)mss
didReceiveLogoutAuthenticationChallenge:(OMAuthenticationChallenge *)challenge;
-(void)mobileSecurityService:(OMMobileSecurityService *)mss
completedSetupWithConfiguration:(OMMobileSecurityConfiguration *)configuration
                       error:(NSError *)error;

@end



