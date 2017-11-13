/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>

@interface OMConnectionHandler : NSObject<NSURLSessionDataDelegate,
                                          NSURLSessionDataDelegate>

@property (nonatomic, strong) NSURLSession *session;
@property (nonatomic, strong) NSMutableData *data;

- (void) invokeHTTPRequestAsynchronouslyForURL: (NSString *)url
                                   withPayload: (NSString *)payload
                                        header: (NSDictionary *)header
                                   requestType: (NSString *)type
                             convertDataToJSON: (BOOL)convertToJSON
                             completionHandler:(void (^)(id data, NSURLResponse *response, NSError *error))completionHandler;

- (id)invokeHTTPRequestSynchronouslyForURL:(NSString *)url
                               withPayload:(NSString *)payload
                                    header:(NSDictionary *)header
                               requestType:(NSString *)type
                         convertDataToJSON:(BOOL)convertToJSON
                         returningResponse:(NSURLResponse **)response
                                  andError:(NSError **)error;

@end
