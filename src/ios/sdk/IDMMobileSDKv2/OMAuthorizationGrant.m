/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthorizationGrant.h"
#import "OMJSONUtlity.h"
#import "OMDefinitions.h"
#import "OMOAuthConfiguration.h"
#import "OMCryptoService.h"
#import "NSData+OMBase64.h"
#import "OMOpenIDCAuthenticationService.h"
#import "OMOIDCAuthenticationService.h"

@implementation OMAuthorizationGrant
- (id)initWithOAuthService:(OMOAuthAuthenticationService *)oauthService
{
    self = [super init];
    if (self)
    {
        _oauthService = oauthService;
    }
    return nil;
}
- (NSURL *)frontChannelRequestURL
{
    return nil;
}
- (NSDictionary *)backChannelRequest:(NSDictionary *)authData
{
    return nil;
}
- (void)processOAuthResponse:(NSDictionary *)urlQueryDict
{
    return;
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
        
        if ([self.oauthService isKindOfClass:
             [OMOIDCAuthenticationService class]])
        {
            ((OMOIDCAuthenticationService *)self.oauthService).idToken =
                                    [returnResponse valueForKey:@"id_token"];
        }
        [self.oauthService setAuthContext];
        self.oauthService.nextStep = OM_NEXT_AUTH_STEP_NONE;
    }
}
- (NSString *)queryParameters:(NSMutableString *)url
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)
                                    self.oauthService.mss.configuration;
    NSURL *redirectURI = config.redirectURI;
    NSSet *scope = config.scope;
    int stateVal = (int)[OMCryptoService secureRandomNumberOfDigits:6];
    NSString *stateString = [NSString stringWithFormat:@"&state=%d",stateVal];
    config.state = [NSString stringWithFormat:@"%d",stateVal];
    [url appendString:stateString];
    if ([scope count])
    {
        NSArray *scopeArray = [scope allObjects];
        NSString *scopeString = [scopeArray componentsJoinedByString:@" "];
        [url appendFormat:@"&scope=%@",scopeString];
    }
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
- (NSString *)backChannelRequestBody:(NSMutableString *)url
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)
                                        self.oauthService.mss.configuration;
    if (config.clientSecret == nil)
    {
        [url appendFormat:@"&client_id=%@",config.clientId];
    }
    NSSet *scope = config.scope;
    if ([scope count] && config.grantType != OMOAuthAuthorizationCode)
    {
        NSArray *scopeArray = [scope allObjects];
        NSString *scopeString = [scopeArray componentsJoinedByString:@" "];
        [url appendFormat:@"&scope=%@",scopeString];
    }
    if (config.clientAssertion)
    {
        NSString *clientAssertionString = [NSString
            stringWithFormat:@"&client_assertion_type=%@&client_assertion=%@",
                            config.clientAssertionType,config.clientAssertion];
        [url appendString:clientAssertionString];
    }
    NSString *urlString = [url stringByAddingPercentEncodingWithAllowedCharacters:NSCharacterSet.URLQueryAllowedCharacterSet];
    return urlString;
}
- (NSDictionary *)backChannelRequestHeader
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)
    self.oauthService.mss.configuration;
    NSString *clientID = config.clientId;
    NSString *clientSecret = config.clientSecret;
    NSMutableDictionary *headerDict = [[NSMutableDictionary alloc] init];
    NSString *passwordString = nil;
    if([clientSecret length] > 0)
    {
        passwordString = [NSString stringWithFormat:@"%@:%@",clientID,
                          clientSecret];
    }
    else if(config.includeClientHeader)
    {
        passwordString = [NSString stringWithFormat:@"%@:",clientID];
    }
    if(passwordString != nil)
    {
        NSData *passwordData = [passwordString
                                dataUsingEncoding:NSUTF8StringEncoding];
        NSString *passwordBase64 = [passwordData base64EncodedString];
        NSString *headerValue = [NSString stringWithFormat:@"Basic %@",
                                 passwordBase64];
        [headerDict setObject:headerValue forKey:OM_AUTHORIZATION];
    }
    if(config.identityDomainInHeader
       &&config.identityDomain)
    {
        NSString *headerName = (config.identityDomainHeaderName)
        ? config.identityDomainHeaderName :
        OM_DEFAULT_IDENTITY_DOMAIN_HEADER;
        [headerDict setObject:config.identityDomain
                       forKey:headerName];
    }
    if(config.customHeaders)
    {
        [headerDict addEntriesFromDictionary:config.customHeaders];
    }
    return headerDict;
}

- (BOOL)doOfflineAuthentication:(NSURL *)offlineHost
{
    return false;
}

-(void)sendFrontChannelChallenge
{
    
}
@end
