/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMAuthenticationService.h"
#import "OMHTTPBasicConfiguration.h"

@interface OMHTTPBasicAuthenticationService : OMAuthenticationService
                                                <NSURLSessionDelegate,
                                                    NSURLSessionTaskDelegate>
@property(nonatomic, strong) NSString *userName;
@property(nonatomic, strong) NSString *password;
@property(nonatomic, strong) NSString *identityDomain;
@property(nonatomic, strong) NSURLSessionDataTask *sessionDataTask;
@property(nonatomic) BOOL authChallengeReceived;
@property(nonatomic, weak) OMHTTPBasicConfiguration *configuration;
@property(nonatomic) BOOL usePreviousCredential;

@end
