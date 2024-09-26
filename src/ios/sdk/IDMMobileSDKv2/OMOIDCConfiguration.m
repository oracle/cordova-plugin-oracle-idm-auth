/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOIDCConfiguration.h"
#import "OMMobileSecurityService.h"
#import "OMDefinitions.h"
#import "OMClientCertChallangeHandler.h"
#import "OMErrorCodes.h"

@interface OMOIDCConfiguration()<NSURLSessionDelegate>
@property(nonatomic, strong) NSError *error;
@property(nonatomic, strong) NSThread *callerThread;
@end
@implementation OMOIDCConfiguration

-(id)initWithProperties:(NSDictionary *)properties
                  error:(NSError *__autoreleasing *)error
{
    self = [super initWithProperties:properties error:error];
    if (self)
    {
        NSUInteger errorCode = -1;
        id configURL = [properties
                        valueForKey:OM_PROP_OPENID_CONNECT_CONFIGURATION_URL];
        id configJSON = [properties
                         valueForKey:OM_PROP_OPENID_CONNECT_CONFIGURATION];
        if (configURL)
        {
            if([self isValidString:configURL] && [self isValidUrl:configURL])
            {
                _configURL =[NSURL URLWithString:configURL];
            }
            else
            {
                errorCode = OMERR_OIDC10_DISCOVERY_ENDPOINT_INVALID;
            }
        }
        else if (configJSON)
        {
            
            NSData *jsonData = [configJSON
                                dataUsingEncoding:NSUTF8StringEncoding];
            NSError *jsonError = nil;
            
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:jsonData
                                            options:NSJSONReadingMutableContainers
                                            error:&jsonError];
            if (jsonError)
            {
                errorCode = OMERR_OIDC10_INVALID_JSON;
            }
            else
            {
                [self parseConfigData:json];

            }
        }
        
        if (errorCode !=-1)
        {
            self = nil;
            
            if (error)
            {
                *error = [OMObject createErrorWithCode:errorCode];
            }
        }
    }
    return self;
}

-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    //we don't need to handle any other challenge type
    NSString *challengeType = challenge.protectionSpace.authenticationMethod;
    if ([challengeType isEqualToString:NSURLAuthenticationMethodServerTrust ])
    {
        [[OMClientCertChallangeHandler sharedHandler]
         doServerTrustForAuthenticationChallenge:challenge
         challengeReciver:self completionHandler:completionHandler];
    }
    else
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                          nil);
    }

}

-(void)parseConfigData:(NSDictionary *)json
{
    NSDictionary *config = [json valueForKey:OM_PROP_OPENID_CONFIGURATION];
    if (config)
    {
        self.issuer = [config valueForKey:OM_PROP_ISSUER];
        self.userInfoEndpoint = [NSURL URLWithString:[config valueForKey:OM_PROP_USERINFO_ENDPOINT]];
        self.revocationEndpoint = [NSURL URLWithString:[config valueForKey:OM_PROP_REVOCATION_ENDPOINT]];
        self.introspectionEndpoint = [NSURL URLWithString:[config valueForKey:OM_PROP_INTROSPECT_ENDPOINT]];
        self.endSessionEndpoint = [NSURL URLWithString:[config valueForKey:OM_PROP_END_SESSION_ENDPOINT]];
        self.jwksURI = [NSURL URLWithString:[config valueForKey:OM_PROP_JWKS_URI]];
        self.scopesSupported = [config valueForKey:OM_PROP_SCOPES_SUPPORTED];
        self.responseSupported = [config valueForKey:OM_PROP_RESPONSE_TYPES_SUPPORTED];
        self.subjectSupported = [config valueForKey:OM_PROP_SUBJECT_TYPES_SUPPORTED];
        self.signAlgoSupported = [config valueForKey:OM_PROP_TOKEN_SIGN_ALGO_SUPPORTED];
        self.claimsSupported = [config valueForKey:OM_PROP_CLAIMS_SUPPORTED];
        self.grantSupported = [config valueForKey:OM_PROP_GRANT_TYPES_SUPPORTED];
        self.tokenEndpointAuthSuported = [config valueForKey:OM_PROP_TOKEN_ENDPOINT_AUTH_SUPPORTED];
        self.tokenEndpointSignAlgoSupported = [config valueForKey:OM_PROP_TOKEN_ENDPOINT_AUTH_SIGNING_SUPPORTED];
        self.userInfoSignAlgoSupported = [config valueForKey:OM_PROP_USERINFO_SIGNING_ALGO_SUPPORTED];
        self.localeSupported = [config valueForKey:OM_PROP_LOCALES_SUPPORTED];
        self.claimParameterSupported = [OMMobileSecurityConfiguration boolValue:[config valueForKey:OM_PROP_CLAIMS_PARAM_SUPPORTED]];
        self.httpLogoutSupported = [OMMobileSecurityConfiguration boolValue:[config valueForKey:OM_PROP_HTTP_LOGOUT_SUPPORTED]];
        self.logoutSessionSupported = [OMMobileSecurityConfiguration boolValue:[config valueForKey:OM_PROP_LOGOUT_SESSION_SUPPORTED]];
        self.requestParameterSupported = [OMMobileSecurityConfiguration boolValue:[config valueForKey:OM_PROP_REQUEST_PARAM_SUPPORTED]];
        self.requestURIParameterSupported = [OMMobileSecurityConfiguration boolValue:[config valueForKey:OM_PROP_REQUEST_URI_SUPPORTED]];
        self.requireRequestURIReg = [OMMobileSecurityConfiguration boolValue:[config valueForKey:OM_PROP_REQUIRE_REQ_URI_REG]];
        self.tokenEndpoint = [NSURL URLWithString:[config valueForKey:OM_PROP_TOKEN_ENDPOINT]];
        self.authEndpoint = [NSURL URLWithString:[config valueForKey:OM_PROP_AUTHORIZATION_ENDPOINT]];
        self.clientRegistrationEndpoint = [NSURL URLWithString:[config valueForKey:OM_PROP_REGISTRATION_ENDPOINT]];
    }
}

- (NSURL*)discoveryUrl;
{
    return self.configURL;
}
@end
