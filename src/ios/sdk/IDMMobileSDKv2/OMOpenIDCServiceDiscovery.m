/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOpenIDCServiceDiscovery.h"
#import "OMObject.h"
#import "OMDefinitions.h"

@implementation OMOpenIDCServiceDiscovery


+ (void)discoverConfigurationWithURL:(NSURL *)discoveryURL
        completion:(OMOpenIDCDiscoveryCallback)completion {
    
    if (NO == (![OMObject checkConnectivityToHost:discoveryURL]))
    {
        NSError *netWorkError = [OMObject
                                 createErrorWithCode:OMERR_NETWORK_UNAVAILABLE];
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(nil, netWorkError);
        });
    }
    else
    {
        NSURLSession *session = [NSURLSession sharedSession];
        NSURLSessionDataTask *task =
        [session dataTaskWithURL:discoveryURL
               completionHandler:^(NSData *data,
                                   NSURLResponse *response,
                                   NSError *error) {
                   
                   NSUInteger errorCode = -1;
                   NSString *responseText = nil;
                   
                   if ((nil == data) ||
                       (nil != error) ||
                       (NO == [response
                               isKindOfClass:[NSHTTPURLResponse class]]))
                   {
                       errorCode = OMERR_OIDC10_DISCOVERY_ENDPOINT_INVALID;
                   }
                   else
                   {
                       NSHTTPURLResponse *urlResponse = (NSHTTPURLResponse *)response;
                       
                       responseText = [[NSString alloc] initWithData:data
                                                            encoding:NSUTF8StringEncoding];

                       if (urlResponse.statusCode != 200)
                       {
                           if (urlResponse.statusCode == 401)
                           {
                               errorCode = OMERR_OAUTH_UNAUTHORIZED_CLIENT;
                           }
                           else
                           {
                               errorCode = OMERR_OAUTH_INVALID_REQUEST;
                           }
                       }
                       else
                       {
                           NSMutableDictionary *json =
                           [NSJSONSerialization JSONObjectWithData:data
                                                           options:0
                                                             error:&error];
                           
                           if ((nil == json) || (nil != error))
                           {
                               errorCode = OMERR_OIDC10_INVALID_JSON;
                           }
                           else
                           {
                               dispatch_async(dispatch_get_main_queue(), ^{
                                   completion(json, nil);
                               });
                           }
                       }
                   }
                   if (errorCode != -1)
                   {
                       if (nil == error)
                       {
                           errorCode = OMERR_OIDC10_UNKNOWN;
                       }
                       
                       if (nil != responseText)
                       {
                           error = [OMObject createErrorWithCode:errorCode
                                                      andMessage:responseText];
                       }
                       else
                       {
                           error = [OMObject createErrorWithCode:errorCode];
                       }
                       
                       dispatch_async(dispatch_get_main_queue(), ^{
                           completion(nil, error);
                       });
                   }
               }];
        [task resume];
    }
}

@end
