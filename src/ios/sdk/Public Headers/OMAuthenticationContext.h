/* Copyright (c) 2011, 2015, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMAuthenticationContext.h - Authentication Context Object
 
 DESCRIPTION
 Oracle Mobile Authentication Context object
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    04/13/16 - Added isValid without parameters
 shivap      04/12/16 - Change the startSessionTimers api to startTimers
 asashiss    02/24/16 - OMSS 28141
 asashiss    03/23/16 - OWSM MA APIs
 shivap      03/10/16 - Change the getCookies api to cookies
 asashiss    03/01/16 - Added isValid
 shivap      02/12/16 - Added session timout related changes
 asashiss    02/04/16 - Creation
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
@property (nonatomic, strong) NSString *offlineCredentialKey;
@property (nonatomic) BOOL isLogoutFalseCalled;

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
@end
