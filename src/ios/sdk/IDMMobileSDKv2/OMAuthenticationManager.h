/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMMobileSecurityConfiguration.h"
#import "OMAuthenticationService.h"
#import "OMAuthenticationDelegate.h"

@class OMMobileSecurityService;
@interface OMAuthenticationManager : NSObject<OMAuthenticationDelegate>
@property (nonatomic, weak) OMMobileSecurityService *mss;
@property (nonatomic, strong) NSMutableDictionary *authData;
@property (nonatomic, strong) OMAuthenticationService *curentAuthService;
@property (nonatomic, strong) OMAuthenticationRequest *request;
@property (nonatomic, assign) BOOL isAuthRequestInProgress;

-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
             authenticationRequest:(OMAuthenticationRequest *)authReq;
-(void)startAuthenticationProcess;
-(void)cancelAuthentication;
-(void)sendAuthenticationContext:(OMAuthenticationContext *)context
                                error:(NSError *)error;

@end
