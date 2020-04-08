/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@interface OMClientCertChallangeHandler : NSObject

+ (OMClientCertChallangeHandler*)sharedHandler;

- (void)doServerTrustForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                               challengeReciver:(id)reciver
                              completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                                          NSURLCredential *credential))completionHandler;

- (void)doClientTrustForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                               challengeReciver:(id)reciver
                              completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                                          NSURLCredential *credential))completionHandler;


- (void)doServerTrustSynchronouslyForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                                   challengeReciver:(id)reciver
                                  completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                                              NSURLCredential *credential))completionHandler;
- (void)doClientTrustSynchronouslyForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                                   challengeReciver:(id)reciver
                                  completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                                              NSURLCredential *credential))completionHandler;

@end
