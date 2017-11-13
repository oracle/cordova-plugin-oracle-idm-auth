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
@property(nonatomic) volatile int32_t finished;
@property(nonatomic, strong) NSString *userName;
@property(nonatomic, strong) NSString *password;
@property(nonatomic, strong) NSString *identityDomain;
@property(nonatomic, strong) NSURLSession *session;
@property(nonatomic) BOOL authChallengeReceived;
@property(nonatomic, weak) OMHTTPBasicConfiguration *configuration;
/*
 * Using a int32_t instead of a bool as a volatile BOOL did not 
 * worked when threads switched
 * http://stackoverflow.com/questions/2259956/is-bool-read-write-atomic-in-objective-c
 * will be a good starting point to understand how to avoid that
*/
 @property(atomic) int32_t volatile useOfflineAuthCred;

@end
