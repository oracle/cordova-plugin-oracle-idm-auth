/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAuthConfiguration.h"
#import "OMMobileSecurityService.h"
#import "OMToken.h"

@interface OMOAMOAuthConfiguration : OMOAuthConfiguration
@property (nonatomic, strong) NSURL *oauthServiceEndpoint;
@property (nonatomic, strong) NSURL *notificationEndpoint;
@property (nonatomic, strong) NSMutableArray *userProfileEndpoints;
@property (nonatomic, strong) NSString *deliveryMechanism;
@property (nonatomic, weak) OMMobileSecurityService *mss;
@property (nonatomic, strong) NSString *clientRegistrationType;
@property (nonatomic, strong) NSString *deviceProfile;
@property (nonatomic, strong) OMToken *preAuthzCode;
@property (nonatomic, strong) OMToken *userAssertionToken;
@property (nonatomic) BOOL ssoEnabled;
@property (nonatomic, strong) NSArray *allowedGrants;
@property (nonatomic, strong) NSArray *claimAttributes;

- (NSURL*)discoveryUrl;

@end
