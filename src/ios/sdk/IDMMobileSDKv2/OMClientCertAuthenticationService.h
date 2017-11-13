/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMAuthenticationService.h"

@class OMAuthenticationService,OMClientCertConfiguration;

@interface OMClientCertAuthenticationService :
                                OMAuthenticationService<NSURLSessionDelegate>

@property(nonatomic) volatile int32_t finished;
@property(nonatomic, strong) NSURLSession *session;
@property(nonatomic, weak) OMClientCertConfiguration *configuration;
@property(nonatomic, assign) BOOL authChallengeReceived;

@end
