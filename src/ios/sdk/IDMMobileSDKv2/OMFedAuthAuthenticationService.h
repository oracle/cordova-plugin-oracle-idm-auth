/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticationService.h"

@class OMFedAuthConfiguration;

@interface OMFedAuthAuthenticationService : OMAuthenticationService
@property(nonatomic, weak) OMFedAuthConfiguration *configuration;
@property(nonatomic, assign) BOOL authChallengeReceived;

@end
