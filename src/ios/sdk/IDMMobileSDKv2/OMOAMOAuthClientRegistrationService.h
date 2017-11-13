/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticationService.h"
#import "OMOAMOAuthConfiguration.h"
@interface OMOAMOAuthClientRegistrationService : OMAuthenticationService
@property (nonatomic, weak) OMOAMOAuthConfiguration *config;
@end
