/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMMobileSecurityConfiguration.h"
#import "OMAuthenticationRequest.h"

@interface OMHTTPBasicConfiguration : OMMobileSecurityConfiguration

@property (nonatomic, strong) NSSet *requiredTokens;
@property (nonatomic) BOOL isMultiTenantEnabled;
@property (nonatomic, strong) NSString *applicationID;
@property (nonatomic) NSUInteger connectivityMode;
@property (nonatomic,) BOOL offlineAuthAllowed;
@property (nonatomic) BOOL collectIdentityDomain;
@property (nonatomic, strong) NSURL *loginURL;
@property (nonatomic, strong) NSURL *logoutURL;

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;

@end
