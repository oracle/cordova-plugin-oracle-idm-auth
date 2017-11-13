/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthorizationGrant.h"

@interface OMResourceOwnerGrant : OMAuthorizationGrant
@property(nonatomic) volatile int32_t finished;
@end
