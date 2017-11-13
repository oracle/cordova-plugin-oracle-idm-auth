/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMOAuthAuthenticationService.h"

@interface OMIDCSClientRegistrationService : OMOAuthAuthenticationService

@property (nonatomic) BOOL backChannelRequestDone;
@property (nonatomic, strong) NSString *tokenType;
@end
