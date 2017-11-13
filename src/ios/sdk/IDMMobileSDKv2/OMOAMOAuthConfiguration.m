/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAMOAuthConfiguration.h"
#import "OMIdentityContext.h"
#import "OMErrorCodes.h"

@interface OMOAMOAuthConfiguration()<NSURLSessionDelegate>
@property (nonatomic, strong) NSError *error;
@property (nonatomic, strong) NSThread *callerThread;
@end
@implementation OMOAMOAuthConfiguration
-(id)initWithProperties:(NSDictionary *)properties error:(NSError *__autoreleasing *)error
{
    self = [super initWithProperties:properties error:error];
    if (self)
    {
        id oauthServiceEndpoint =
        [properties valueForKey:OM_PROP_OAUTH_OAM_SERVICE_ENDPOINT];
        if ([self isValidString:oauthServiceEndpoint] &&
            [self isValidUrl:oauthServiceEndpoint])
        {
            _oauthServiceEndpoint = [NSURL URLWithString:oauthServiceEndpoint];
        }
        
    }
    return self;
}

-(void)parseConfigData:(NSDictionary *)applicationProfile;
{
    NSUInteger *location = [[self.oauthServiceEndpoint absoluteString]
                            rangeOfString:@"/ms_oauth"].location;
    NSString *oamAddress = [[self.oauthServiceEndpoint absoluteString]
                            substringToIndex:location];
    NSString *tokenEndpoint = [applicationProfile
                               valueForKey:@"oauthTokenService"];
    tokenEndpoint = [NSString stringWithFormat:@"%@%@",oamAddress,tokenEndpoint];
    self.tokenEndpoint = [NSURL URLWithString:tokenEndpoint];
    NSString *authzEnpoint = [applicationProfile
                              valueForKey:@"oauthAuthZService"];
    authzEnpoint = [NSString stringWithFormat:@"%@%@",oamAddress,authzEnpoint];
    self.authEndpoint = [NSURL URLWithString:authzEnpoint];
    self.claimAttributes = [[applicationProfile valueForKey:@"mobileAppConfig"]
                            valueForKey:@"claimAttributes"];
    if (self.grantType == OMOAuthAuthorizationCode)
    {
        self.clientRegistrationType = OM_OAM_OAUTH_THREE_LEGGED_REGISTRATION;
    }
    else
    {
        self.clientRegistrationType = OM_OAM_OAUTH_TWO_LEGGED_REGISTRATION;
    }
}

- (NSDictionary *)getIdentityClaims
{
    OMIdentityContext *identityContext = [OMIdentityContext sharedInstance];
    [identityContext setApplicationID:self.appName];
    [identityContext setIdentityContextClaims:self.claimAttributes];
    NSDictionary *deviceClaims = [identityContext
                                  getJSONDictionaryForAuthentication:nil];
    return deviceClaims;
}

- (NSURL*)discoveryUrl;
{
    NSString *deviceOS = @"iPhone OS";
    NSString *osVersion = [[UIDevice currentDevice] systemVersion];
    NSString *profileURL = [NSString stringWithFormat:
                            @"%@/appprofiles/%@?device_os=%@&os_ver=%@",
                            self.oauthServiceEndpoint,self.clientId,deviceOS,
                            osVersion];
    return [NSURL URLWithString:profileURL];
}

@end
