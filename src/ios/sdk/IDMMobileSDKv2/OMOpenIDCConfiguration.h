/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>
#import "OMOAuthConfiguration.h"

typedef void (^OIDCDiscoveryCallback)(NSError *_Nullable discoveryError);

@interface OMOpenIDCConfiguration :OMOAuthConfiguration

@property (nonatomic, strong) NSString *properties;
@property (nonatomic, strong) NSString *issuer;
@property (nonatomic, strong) NSSet *claims;
@property (nonatomic, strong) NSURL *revocationEndpoint;
@property (nonatomic, strong) NSURL *userInfoEndpoint;
@property (nonatomic, strong) NSURL *discoveryEndpoint;
@property (nonatomic, strong) NSString *discoveryJSON;

- (BOOL)needDiscovery;
- (void)startDiscoveryWithCompletion:(OIDCDiscoveryCallback _Null_unspecified)completion;

@end
