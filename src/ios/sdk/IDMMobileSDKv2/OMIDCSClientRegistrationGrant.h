/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthorizationCodeGrant.h"

@interface OMIDCSClientRegistrationGrant : OMAuthorizationCodeGrant

- (NSDictionary*)registrationHeader;
- (NSData*)registrationBody;

@end
