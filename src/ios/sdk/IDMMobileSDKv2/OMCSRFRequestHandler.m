//
//  OMCSRFRquestHandler.m
//  IDMMobileSDKv2
//
//  Created by Shiva Prasad on 17/02/20.
//  Copyright © 2020 Oracle. All rights reserved.
//

#import "OMCSRFRequestHandler.h"
#import "OMUtilities.h"

NSString *ANTI_CSRF_PATH = @"fscmRestApi/anticsrf";
NSString *TOKEN_END_PATH = @"fscmRestApi/tokenrelay";
NSString *XSRF_TOKEN = @"xsrftoken";

@implementation OMCSRFRequestHandler

- (NSDictionary*)retrieveAntiCSRFTokenWithConfig:(OMFedAuthConfiguration*)config error:(NSError**)error
{
    NSError *error_obj = nil;
    NSURLResponse *response = nil;
    NSURL *hostURL = [[NSURL URLWithString:@"/" relativeToURL:[config loginURL]] absoluteURL];
    NSURL *antiCSRFUrlString = [hostURL URLByAppendingPathComponent:ANTI_CSRF_PATH];
    NSURLRequest *request = [NSURLRequest requestWithURL:antiCSRFUrlString];
    
    NSData *data =[OMUtilities sendSynchronousRequest:request returningResponse:&response error:&error_obj];
    
    NSDictionary *json = nil;
    
    if (error_obj == nil && data) {
        
       json =  [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:error];
    }

    NSLog(@"responce = %@", response);
    return json;
}

- (NSDictionary*)retrieveJWTTokenWithConfig:(OMFedAuthConfiguration*)config antiCSRFToken:(NSString*)token error:(NSError**)error
{
    NSURLResponse *response = nil;
    NSURL *hostURL = [[NSURL URLWithString:@"/" relativeToURL:[config loginURL]] absoluteURL];
    NSURL *jwtUrl = [hostURL URLByAppendingPathComponent:TOKEN_END_PATH];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:jwtUrl cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:20.0f];
    
    [request setValue:token forHTTPHeaderField:@"X-XSRF-TOKEN"];
    
    
    NSData *data =[OMUtilities sendSynchronousRequest:request returningResponse:&response error:error];
    
    NSDictionary *json = nil;
    
    if (*error == nil && data) {
        
       json =  [NSJSONSerialization JSONObjectWithData:data options:NSJSONReadingMutableContainers error:error];
    }

//    NSLog(@"responce = %@", response);
    return json;
}


- (NSDictionary*)extractTokenRelayTokensWithConfig:(OMFedAuthConfiguration*)config error:(NSError**)error
{
    NSDictionary *jwtToken = nil;
    NSDictionary *antiCSRF = [self retrieveAntiCSRFTokenWithConfig:config error:error];
    
    if (*error) {
        
        return nil;
    }
    else
    {
         jwtToken = [self retrieveJWTTokenWithConfig:config antiCSRFToken:[antiCSRF valueForKey:XSRF_TOKEN] error:error];
        
    }

    return jwtToken;
}
@end
