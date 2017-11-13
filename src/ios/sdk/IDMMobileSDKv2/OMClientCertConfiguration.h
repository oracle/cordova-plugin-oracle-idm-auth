/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMMobileSecurityConfiguration.h"

@interface OMClientCertConfiguration : OMMobileSecurityConfiguration

@property (nonatomic, retain) NSSet *requiredTokens;
@property (nonatomic, strong) NSURL *loginURL;
@property (nonatomic, strong) NSURL *logoutURL;

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;

@end

