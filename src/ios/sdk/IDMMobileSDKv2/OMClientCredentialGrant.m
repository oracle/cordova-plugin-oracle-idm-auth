/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMClientCredentialGrant.h"
#import "OMOAuthConfiguration.h"
#import "OMDefinitions.h"

@implementation OMClientCredentialGrant
- (NSDictionary *)backChannelRequest:(NSDictionary *)authData
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.oauthService.
                                                    mss.configuration;
    NSString *tokenEndpoint = [config.tokenEndpoint absoluteString];
    NSMutableString *requestString = [NSMutableString stringWithString:
                                      @"grant_type=client_credentials"];
    NSString *requestBody = [self backChannelRequestBody:requestString];
    NSDictionary *headerDict = [self backChannelRequestHeader];
    NSMutableDictionary *requestDict = [[NSMutableDictionary alloc] init];
    [requestDict setObject:tokenEndpoint
                    forKey:OM_OAUTH_BACK_CHANNEL_REQUEST_URL];
    [requestDict setObject:requestBody forKey:OM_OAUTH_BACK_CHANNEL_PAYLOAD];
    if(headerDict)
        [requestDict setObject:headerDict forKey:OM_OAUTH_BACK_CHANNEL_HEADERS];
    [requestDict setObject:@"POST" forKey:OM_OAUTH_BACK_CHANNEL_REQUEST_TYPE];
    return requestDict;
}

- (void)OAuthBackChannelResponse:(NSURLResponse *)urlResponse
                            data:(id)data
                        andError:(NSError *)error
{
    [super OAuthBackChannelResponse:urlResponse data:data andError:error];
}
@end
