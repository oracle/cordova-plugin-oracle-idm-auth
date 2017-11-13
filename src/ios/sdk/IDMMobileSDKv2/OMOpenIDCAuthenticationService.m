/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMOpenIDCAuthenticationService.h"
#import "OMOpenIDCConfiguration.h"
#import "OMToken.h"
#import "OMObject.h"
#import "OMErrorCodes.h"
#import "OMOpenIDCServiceDiscovery.h"
#import "OMURLProtocol.h"

@implementation OMOpenIDCAuthenticationService

- (id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
              authenticationRequest:(OMAuthenticationRequest *)authReq
                           delegate:(id<OMAuthenticationDelegate>)delegate
{
    self = [super initWithMobileSecurityService:mss
                          authenticationRequest:authReq
                                       delegate:delegate];
    if (self)
    {
        
    }
    return self;
}

- (void)setAuthContext
{
    [super setAuthContext];
    self.context.idToken = self.idToken;
}

- (void)userInfoWithCompletion:(OMOpenIDCUserInfoCallback _Null_unspecified)completion;
{
    OMOpenIDCConfiguration *config = (OMOpenIDCConfiguration *)self.mss.configuration;
    
        // creates request to the userinfo endpoint, with access token in the Authorization header
    NSMutableURLRequest *request = [NSMutableURLRequest
                                    requestWithURL:config.userInfoEndpoint];
    
    NSString *authorizationHeaderValue = [NSString stringWithFormat:@"Bearer %@",
                                          self.accessToken];
    [request addValue:authorizationHeaderValue forHTTPHeaderField:@"Authorization"];
    
    NSURLSessionConfiguration *configuration =
    [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
                                                          delegate:nil
                                                     delegateQueue:nil];
    NSURLSessionDataTask *postDataTask =
    [session dataTaskWithRequest:request
               completionHandler:^(NSData *data,
                                   NSURLResponse *response,
                                   NSError *error)
     {
         NSUInteger errorCode = -1;
         NSString *responseText = nil;
         
         if ((nil == data) ||
             (nil != error) ||
             (NO == [response isKindOfClass:[NSHTTPURLResponse class]]))
         {
             errorCode = OMERR_OAUTH_INVALID_REQUEST;
         }
         else
         {
             NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
             
             if (httpResponse.statusCode != 200)
             {
                 responseText = [[NSString alloc] initWithData:data
                                                      encoding:NSUTF8StringEncoding];
                 if (httpResponse.statusCode == 401)
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
                 NSMutableDictionary *json =  [NSJSONSerialization
                                               JSONObjectWithData:data
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
    
    [postDataTask resume];
}

- (void)performAuthentication:(NSMutableDictionary *)authData
                        error:(NSError *__autoreleasing *)error
{
    OMOpenIDCConfiguration *config = (OMOpenIDCConfiguration *)self.mss.configuration;
    

    __block NSError * __strong errorLocal = nil;
    
    if (NULL != error) {
        errorLocal = *error;
    }

    if (YES == config.needDiscovery)
    {
        [config startDiscoveryWithCompletion:^(NSError * _Nullable discoveryError)
        {
            errorLocal = discoveryError;
            
            if (nil == discoveryError)
            {
                [self setGrantFlowManually];
                [super performAuthentication:authData error:&errorLocal];
            }
            else
            {
                self.nextStep = OM_NEXT_AUTH_STEP_NONE;
                self.error = errorLocal;
                [self sendFinishAuthentication:self.error];
                [NSURLProtocol unregisterClass:[OMURLProtocol class]];
            }
        }];
    }
    else
    {
        [super performAuthentication:authData error:error];
    }
}

@end
