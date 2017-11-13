/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMConnectionHandler.h"
#import <libkern/OSAtomic.h>

@implementation OMConnectionHandler

- (id)init
{
    self = [super init];
    if(self)
    {
        self.session = [NSURLSession
                        sessionWithConfiguration:[NSURLSessionConfiguration
                                                  defaultSessionConfiguration]];
        self.data = [[NSMutableData alloc] init];
    }
    return self;
}

- (void)invokeHTTPRequestAsynchronouslyForURL:(NSString *)url
                                  withPayload:(NSString *)payload
                                       header:(NSDictionary *)header
                                  requestType:(NSString *)type
                            convertDataToJSON:(BOOL)convertToJSON
                            completionHandler:(void (^)(id data, NSURLResponse *response, NSError *error))completionHandler
{
    NSURL *reqURL = [NSURL URLWithString:url];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reqURL];
    [request setHTTPMethod:type];
    [request setAllHTTPHeaderFields:header];
    [request setHTTPBody:[payload dataUsingEncoding:NSUTF8StringEncoding]];
    NSURLSessionDataTask *dTask = [self.session dataTaskWithRequest:request
                                                  completionHandler:^(NSData *data,NSURLResponse *response, NSError *error)
    {
        if(convertToJSON)
        {
            NSError *errorJson=nil;
            NSDictionary* responseDict =
            [NSJSONSerialization JSONObjectWithData:data options:kNilOptions
                                              error:&errorJson];
            
            NSLog(@"responseDict=%@",responseDict);
            if (completionHandler)
                completionHandler(responseDict, response, error);
        }
        else
        {
            if (completionHandler)
                completionHandler(data, response, error);
        }
    }];

    [dTask resume];
}

- (id)invokeHTTPRequestSynchronouslyForURL:(NSString *)url
                               withPayload:(NSString *)payload
                                    header:(NSDictionary *)header
                               requestType:(NSString *)type
                         convertDataToJSON:(BOOL)convertToJSON
                         returningResponse:(NSURLResponse **)response
                                  andError:(NSError **)error
{
    return nil;
}

@end
