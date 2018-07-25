/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMMobileSecurityService.h"
#import "OMAuthenticationRequest.h"
#import "OMAuthenticationDelegate.h"
#import "OMAuthenticationChallenge.h"

@class OMMobileSecurityConfiguration;

@interface OMAuthenticationService : NSObject

@property (nonatomic, weak) OMMobileSecurityService *mss;
@property (nonatomic, weak) OMAuthenticationRequest *request;
@property (nonatomic, strong) NSThread *callerThread;
@property (nonatomic, strong) OMAuthenticationContext *context;
@property (nonatomic, weak) id<OMAuthenticationDelegate> delegate;
@property (nonatomic, strong) OMAuthenticationChallenge *challenge;
@property (nonatomic, strong) NSError *error;
@property (nonatomic, strong) NSDictionary *authResponse;
@property (nonatomic, strong) NSMutableDictionary *authData;
@property(nonatomic) BOOL maxRetryError;
@property (nonatomic, strong) dispatch_semaphore_t requestPauseSemaphore;

-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
             authenticationRequest:(OMAuthenticationRequest *)authReq
                          delegate:(id<OMAuthenticationDelegate>)delegate;
-(void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError **)error;
-(BOOL)isInputRequired:(NSMutableDictionary *)authData;
-(BOOL)isRequiredTokens:(NSSet *)tokens presentFor:(NSArray *)visitedHosts;
-(NSString *)protectPassword:(NSString *)password
                cryptoScheme:(NSUInteger)scheme
                    outError:(NSError **)error;
-(BOOL) verifyPassword:(NSString *)userPassword
 withProtectedPassword:(NSString *)protectedPassword
              outError:(NSError **)error;

/**
 * Populates a dictionary sent by individual authentication service with user
 * credentials and user preferences.
 *
 * @param authnData Dictiornay that will be populated with credentials and
 *                  preferences
 * @return void
 */
- (void)retrieveRememberCredentials:(NSMutableDictionary *) authnData;

/**
 * Persists user credentials in keychain
 *
 * @param authnData Dictionary that has user credentials and preferences
 * @return void
 */
- (void)storeRememberCredentials:(NSMutableDictionary *) authnData;

/**
 * Persists user prefernces in NSUserDefaults
 * @param authnData Dictionary that has user preferences
 * @return void
 */
- (void)storeRememberCredentialsPreference:(NSDictionary *) authnData;

- (BOOL) shouldPerformAutoLogin:(NSDictionary *)authnData;

+ (NSError *)setErrorObject:(NSDictionary *)errorDict
              withErrorCode:(NSUInteger)code;
+ (NSUInteger)getErrorCodeForError:(NSString *)error;

-(void)sendFinishAuthentication:(id)object;

- (void)cancelAuthentication;

- (BOOL)isMaxRetryReached:(NSInteger)previousFaliureCount maxRetryCount:
    (NSInteger)maxRetryCount;

- (void)resetMaxRetryCount;
-(BOOL)isMaxRetryReached:(NSUInteger)maxRetry;

- (NSString *)maskPassword:(NSString *)password;
- (NSString *)unMaskPassword:(NSString *)password;

@end
