/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMOAuthAuthenticationService.h"

@interface OMOIDCAuthenticationService : OMOAuthAuthenticationService
@property (nonatomic, strong) NSString *idToken;
@end
