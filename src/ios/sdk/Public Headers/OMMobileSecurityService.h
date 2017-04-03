/* Copyright (c) 2011, 2015, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMMobileSecurityService.h - Mobile Security Service
 
 DESCRIPTION
 Implementation file of MobileSecurityService, which is used by the
 applications using IDMMobilseSDK to initialize SDK. To initialize SDK,
 Mobile applications have to create MobileSecurityService object by passing
 OIC server details from which IDMMobileSDK download authentication &
 authorization details.
 
 RELATED DOCUMENTS
 None
 
 INHERITS FROM
 NSObject
 
 PROTOCOLS IMPLEMENTED
 None
 
 EXTENSION FUNCTIONS
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    06/21/16 - OMSS-29783
 asashiss    03/23/16 - OWSM MA APIs
 asashiss    03/01/16 - Clear remember credential method
 shivap      02/10/16 - Added remember credkey method
 asashiss    02/12/16 - Logout method added
 asashiss    02/04/16 - Creation
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

@end



