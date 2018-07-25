/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMOAuthConfiguration.h"

@class OMMobileSecurityService;

@interface OMOIDCConfiguration : OMOAuthConfiguration
@property(nonatomic, weak) OMMobileSecurityService *mss;
@property (nonatomic, strong) NSURL *configURL;
@property (nonatomic, strong) NSString *configJSON;
@property (nonatomic, strong) NSString *issuer;
@property (nonatomic, strong) NSURL *userInfoEndpoint;
@property (nonatomic, strong) NSURL *revocationEndpoint;
@property (nonatomic, strong) NSURL *introspectionEndpoint;
@property (nonatomic, strong) NSURL *endSessionEndpoint;
@property (nonatomic, strong) NSURL *jwksURI;
@property (nonatomic, strong) NSSet *scopesSupported;
@property (nonatomic, strong) NSSet *responseSupported;
@property (nonatomic, strong) NSSet *subjectSupported;
@property (nonatomic, strong) NSSet *signAlgoSupported;
@property (nonatomic, strong) NSSet *claimsSupported;
@property (nonatomic, strong) NSSet *grantSupported;
@property (nonatomic, strong) NSSet *tokenEndpointAuthSuported;
@property (nonatomic, strong) NSSet *tokenEndpointSignAlgoSupported;
@property (nonatomic, strong) NSSet *userInfoSignAlgoSupported;
@property (nonatomic, strong) NSSet *localeSupported;
@property (nonatomic) BOOL claimParameterSupported;
@property (nonatomic) BOOL httpLogoutSupported;
@property (nonatomic) BOOL logoutSessionSupported;
@property (nonatomic) BOOL requestParameterSupported;
@property (nonatomic) BOOL requestURIParameterSupported;
@property (nonatomic) BOOL requireRequestURIReg;
-(void)parseConfigData:(NSDictionary *)jsonData;

- (NSURL*)discoveryUrl;
@end
