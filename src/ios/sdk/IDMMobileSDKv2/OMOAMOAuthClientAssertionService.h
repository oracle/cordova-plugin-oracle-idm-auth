/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMAuthenticationService.h"
#import "OMOAMOAuthConfiguration.h"

@interface OMOAMOAuthClientAssertionService : OMAuthenticationService
@property (nonatomic, weak) OMOAMOAuthConfiguration *config;
@property (nonatomic, strong) NSString *authCode;
@end
