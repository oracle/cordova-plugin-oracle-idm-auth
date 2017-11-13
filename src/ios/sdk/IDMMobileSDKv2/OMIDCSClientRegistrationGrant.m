/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMIDCSClientRegistrationGrant.h"
#import "OMCryptoService.h"
#import "OMIDCSClientRegistrationService.h"

NSString *scope = @"urn:opc:idm:t.app.register";

@implementation OMIDCSClientRegistrationGrant

- (NSString *)queryParameters:(NSMutableString *)url
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)
    self.oauthService.mss.configuration;
    NSURL *redirectURI = config.redirectURI;
    int stateVal = (int)[OMCryptoService secureRandomNumberOfDigits:4];
    NSString *stateString = [NSString stringWithFormat:@"&state=%d",stateVal];
    config.state = [NSString stringWithFormat:@"%d",stateVal];
    [url appendString:stateString];
    [url appendFormat:@"&scope=%@",scope];
    [url appendFormat:@"&nonce=%d",stateVal];

    if (redirectURI)
    {
        NSString *redirectURIString = [NSString stringWithFormat:
                                       @"&redirect_uri=%@",
                                       redirectURI.absoluteString];
        [url appendString:redirectURIString];
    }
    NSString *urlString = [url
                           stringByAddingPercentEncodingWithAllowedCharacters:
                           NSCharacterSet.URLQueryAllowedCharacterSet];
    return urlString;
}

- (void)OAuthBackChannelResponse:(NSURLResponse *)urlResponse
                            data:(id)data
                        andError:(NSError *)error
{
    if (error != nil)
    {
        self.oauthService.error = error;
        return;
    }
    NSDictionary *returnResponse = [NSJSONSerialization
                                    JSONObjectWithData:data
                                    options:0
                                    error:nil];
    NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)urlResponse;
    NSInteger statusCode = [httpResponse statusCode];
    self.oauthService.error = [OMOAuthAuthenticationService
                               oauthErrorFromResponse:returnResponse
                               andStatusCode:statusCode];
    if (self.oauthService.error == nil)
    {
        self.oauthService.accessToken = [returnResponse
                                         valueForKey:@"access_token"];
        self.oauthService.expiryTimeInSeconds = [[returnResponse
                                                  valueForKey:@"expires_in"]
                                                 intValue];
        self.oauthService.refreshToken = [returnResponse
                                          valueForKey:@"refresh_token"];

        [(OMIDCSClientRegistrationService*)self.oauthService setTokenType:
         [returnResponse valueForKey:@"token_type"]];
        
        self.oauthService.nextStep = OM_NEXT_AUTH_STEP_NONE;
    }
}

- (NSDictionary*)registrationHeader
{
    OMIDCSClientRegistrationService* service = self.oauthService;
    NSString *auth = [NSString stringWithFormat:@"%@ %@",service.tokenType,
                      service.accessToken];
    
    return @{OM_AUTHORIZATION: auth,@"Content-Type":@"application/json"};
}

- (NSData*)registrationBody
{
    NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
    NSString *deviceModel = [[UIDevice currentDevice] model];
    NSString *osVersion = [[UIDevice currentDevice] systemVersion];
    NSString *vendorIdentifier = [[[UIDevice currentDevice] identifierForVendor]
                                  UUIDString];
    NSDictionary *deviceInfo = @{ @"client_device_id": vendorIdentifier,
                                  @"device_platform_version":osVersion,
                                  @"device_model":deviceModel,
                                  @"ios_bundle_id":bundleID};

    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:deviceInfo
                                                       options:0
                                                         error:&error];
    
    return jsonData;
}
@end
