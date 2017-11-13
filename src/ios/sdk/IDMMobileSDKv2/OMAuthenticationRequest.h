/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMObject.h"

@interface OMAuthenticationRequest : NSObject
@property(nonatomic) OMConnectivityMode connectivityMode;
@property (nonatomic, strong) NSString *identityDomain;
@property (nonatomic) BOOL forceAuth;
@end
