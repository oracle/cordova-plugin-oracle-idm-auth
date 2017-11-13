/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMCredential.h"

enum
{
    OMLocal = 1,
    OMRemote = 2
};
typedef NSUInteger OMAuthenticationMode;

enum
{
    OMSessionTimer,
    OMIdleTimer
};
typedef NSUInteger OMTimerType;

@class OMMobileSecurityService;
@class OMAuthenticationContext;


@protocol  OMAuthenticationContextDelegate<NSObject>

-(void)authContext:(OMAuthenticationContext *)context
timeoutOccuredForTimer:(OMTimerType)timerType
     remainingTime:(NSTimeInterval)duration;

@end

@interface OMAuthenticationContext : NSObject

@property (nonatomic, strong) NSString *userName;
@property (nonatomic, strong) NSMutableArray *visitedHosts;
@property (nonatomic) OMAuthenticationMode authMode;
@property (nonatomic, weak) id delegate;
@property (nonatomic, strong) NSMutableDictionary *accessTokens;
@property (nonatomic, strong) NSString *tokenValue;
@property (nonatomic, strong) NSString *identityDomain;
@property (nonatomic, strong) NSMutableArray *tokens;
@property (nonatomic, strong) NSString *idToken;
@property (nonatomic, strong) NSString *offlineCredentialKey;
@property (nonatomic) BOOL isLogoutFalseCalled;
@property (nonatomic, strong) NSDictionary *userInfo;
@property (nonatomic, strong) NSDate *sessionExpiryDate;

-(id)initWithMss:(OMMobileSecurityService*)inObj;

/**
 * Clear all cookies of URLs visited during login operation from cookie store
 */
-(void)clearCookies:(BOOL)clearPersistentCookies;
- (NSArray *)cookies;

- (void)startTimers;
- (void)stopTimers;

- (BOOL)resetTimer:(OMTimerType)timerType;
- (BOOL)isValid:(BOOL)validateOnline;
- (NSDictionary *)requestParametersForURL:(NSString *)theURL
                           includeHeaders:(BOOL)includeHeaders;
-(void)setCredentialInformation:(NSDictionary *)credInfo;
- (NSDictionary *)credentialInformationForKeys:(NSArray *)keys;
- (BOOL)isValidForScopes:(NSSet *)scopes refreshExpiredToken:(BOOL)refresh;
- (BOOL)isValid;
- (NSString *)passwordForCredential:(OMCredential *)cred
                           outError:(NSError **)error;
- (NSDictionary *)customHeaders;
- (NSArray *)tokensForScopes:(NSSet *)scopes;
@end
