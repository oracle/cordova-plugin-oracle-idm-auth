/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */




#import "OMOpenIDCConfiguration.h"
#import "OMMobileSecurityConfiguration.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"
#import "OMOpenIDCServiceDiscovery.h"
#import "OMObject.h"

@interface OMOpenIDCConfiguration ()
- (NSMutableDictionary *)createPropertiesFromDiscoveryJSON:(NSMutableDictionary *) discoveryJSON
                                          andAppProperties:(NSMutableDictionary *) appProperties;
@end

@implementation OMOpenIDCConfiguration

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;
{
    self.properties = properties;
    self = [super initWithProperties:properties error:error];
    NSUInteger errorCode = -1;
    if (self)
    {
        id authServerType = [properties valueForKey:OM_PROP_AUTHSERVER_TYPE];
        
        if ([OM_PROP_OPENID_CONNECT_SERVER caseInsensitiveCompare:authServerType] ==
            NSOrderedSame)
        {
            id discoveryEndpoint = [properties
                                    valueForKey:OM_PROP_OPENID_CONNECT_CONFIGURATION_URL];
            
            id discoveryJSON = [properties
                                valueForKey:OM_PROP_OPENID_CONNECT_CONFIGURATION];
            
            if (nil != discoveryEndpoint)
            {
                if(![self isValidString:discoveryEndpoint])
                {
                    errorCode = OMERR_OIDC10_DISCOVERY_ENDPOINT_INVALID;
                }
                else
                {
                    self.discoveryEndpoint = [NSURL
                                              URLWithString:discoveryEndpoint];
                }
            }
            else if (nil != discoveryJSON)
            {
                if(![self isValidString:discoveryJSON])
                {
                    errorCode = OMERR_OIDC10_INVALID_JSON;
                }
                else
                {
                    self.discoveryEndpoint = discoveryJSON;
                }
            }
            else
            {
                errorCode = [self setConfiguration:properties];
            }
        }
    }
    if (errorCode != -1)
    {
        self = nil;
        
        if (error)
        {
            *error = [OMObject createErrorWithCode:errorCode];
        }
    }
    
    return self;
}

- (void)startDiscoveryWithCompletion:(OIDCDiscoveryCallback _Null_unspecified)completion
{
    if (nil != self.discoveryEndpoint)
    {
        [OMOpenIDCServiceDiscovery
         discoverConfigurationWithURL:self.discoveryEndpoint
         completion:^(NSMutableDictionary * _Nullable propertiesJSON,
                      NSError * _Nullable discoveryError)
         {
             NSUInteger errorcode = -1;
             
             if (nil == discoveryError && nil != propertiesJSON)
             {
                 NSMutableDictionary *properties =
                 [self createPropertiesFromDiscoveryJSON:propertiesJSON
                                        andAppProperties:self.properties];
                 errorcode = [self setConfiguration:properties];
             }
             else
             {
                 errorcode = discoveryError.code;
             }
             
             NSError *localError = nil;
             if (errorcode != -1)
             {
                 localError = [OMObject createErrorWithCode:errorcode];
             }
             
             completion(localError);
         }];
    }
    else if (nil != self.discoveryJSON)
    {
        NSUInteger errorcode = -1;
        NSMutableDictionary *properties =
        [self createPropertiesFromDiscoveryJSON:self.discoveryJSON
                               andAppProperties:self.properties];
        errorcode = [self setConfiguration:properties];
        
        NSError *localError = nil;
        if (errorcode != -1)
        {
            localError = [OMObject createErrorWithCode:errorcode];
        }
        
        completion(localError);
    }
}

- (NSMutableDictionary *)createPropertiesFromDiscoveryJSON:(NSMutableDictionary *) discoveryJSON
                                          andAppProperties:(NSMutableDictionary *) appProperties;
{
    
    NSMutableDictionary  *sdkProps =
    [[NSMutableDictionary alloc] initWithDictionary:appProperties];
    NSMutableDictionary  *jsonDict = discoveryJSON;
    
    if (nil != [jsonDict valueForKey:@"openid-configuration"])
    {
        jsonDict = [jsonDict valueForKey:@"openid-configuration"];
    }
    
    [sdkProps setObject:OM_PROP_OPENID_CONNECT_SERVER
                 forKey:OM_PROP_AUTHSERVER_TYPE];
    
    [sdkProps setObject:OM_OAUTH_AUTHORIZATION_CODE
                 forKey:OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE];
    
    NSString *tokenEndpoint = [jsonDict valueForKey:@"token_endpoint"];
    if (nil != tokenEndpoint)
    {
        [sdkProps setObject:tokenEndpoint forKey:OM_PROP_OAUTH_TOKEN_ENDPOINT];
    }
    
    NSString *authEndpoint = [jsonDict valueForKey:@"authorization_endpoint"];
    if (nil != authEndpoint)
    {
        [sdkProps setObject:authEndpoint
                     forKey:OM_PROP_OAUTH_AUTHORIZATION_ENDPOINT];
    }
    
    NSArray *scopesArray = @[OM_PROP_OPENID_CONNECT_SCOPE_OPENID,
                             OM_PROP_OPENID_CONNECT_SCOPE_PROFILE];
    [sdkProps setObject:[NSSet setWithArray:scopesArray]
                 forKey:OM_PROP_OAUTH_SCOPE];
    
    NSString *revocationEndpoint = [jsonDict valueForKey:@"revocation_endpoint"];
    if (nil != revocationEndpoint)
    {
        [sdkProps setObject:revocationEndpoint
                     forKey:OM_PROP_OPENID_CONNECT_REVOCATION_ENDPOINT];
    }
    
    NSString *userInfoEndpoint = [jsonDict valueForKey:@"userinfo_endpoint"];
    if (nil != userInfoEndpoint)
    {
        [sdkProps setObject:userInfoEndpoint
                     forKey:OM_PROP_OPENID_CONNECT_USERINFO_ENDPOINT];
    }
    
    NSArray *claimsArray = [jsonDict valueForKey:@"claims_supported"];
    if (nil != claimsArray)
    {
        [sdkProps setObject:[NSSet setWithArray:claimsArray]
                     forKey:OM_PROP_OPENID_CONNECT_CLAIMS];
    }
    
    NSString *issuer = [jsonDict valueForKey:@"issuer"];
    if (nil == issuer)
    {
        [sdkProps setObject:issuer forKey:OM_PROP_OPENID_CONNECT_ISSUER];
    }
    
    NSString *logOutEndPoint = [jsonDict valueForKey:@"end_session_endpoint"];
    if (nil != logOutEndPoint)
    {
        [sdkProps setObject:logOutEndPoint forKey:OM_PROP_LOGOUT_URL];
    }
    
    NSString *logOutRedirectEndPoint = [jsonDict
                                        valueForKey:@"OpenIDConnect10LogoutRedirectEndpoint"];
    if (nil != logOutRedirectEndPoint)
    {
        [sdkProps setObject:logOutRedirectEndPoint
                     forKey:OM_PROP_LOGOUT_REDIRECT_ENDPOINT];
    }
    
    return sdkProps;
}

- (NSInteger)setConfiguration:(NSDictionary *) properties
{
    NSInteger errorCode = [super setConfiguration:properties];
    if (errorCode == -1)
    {
        id issuer = [properties valueForKey:OM_PROP_OPENID_CONNECT_ISSUER];
        id claims = [properties valueForKey:OM_PROP_OPENID_CONNECT_CLAIMS];
        id userInfoEndpoint = [properties
                               valueForKey:OM_PROP_OPENID_CONNECT_USERINFO_ENDPOINT];
        
        id revocationEndpoint = [properties
                                 valueForKey:OM_PROP_OPENID_CONNECT_REVOCATION_ENDPOINT];
        
        if(![self isValidString:issuer])
        {
            errorCode = OMERR_OIDC10_UNAUTHORIZED_ISSUER;
        }
        else
        {
            self.issuer = issuer;
        }
        
        if ((claims != nil && [claims isKindOfClass:[NSSet class]] == false))
        {
            errorCode = OMERR_OIDC10_INVALID_CLAIMS;
        }
        else
        {
            self.claims = claims;
        }
        
        if([self isValidString:userInfoEndpoint] &&
           [self isValidUrl:userInfoEndpoint])
        {
            self.userInfoEndpoint =[NSURL URLWithString:userInfoEndpoint];
        }
        else
        {
            errorCode = OMERR_OIDC10_USERINFO_ENDPOINT_INVALID;
        }
        
        if([self isValidString:revocationEndpoint] &&
           [self isValidUrl:revocationEndpoint])
        {
            self.revocationEndpoint =[NSURL URLWithString:revocationEndpoint];
        }
        else
        {
            errorCode = OMERR_OIDC10_REVOCATION_ENDPOINT_INVALID;
        }
    }
    
    return errorCode;
}

- (BOOL)needDiscovery
{
    BOOL retValue = NO;
    
    if (nil != self.discoveryEndpoint)
    {
        if (nil == self.tokenEndpoint || nil == self.authEndpoint)
        {
            retValue = YES;
        }
    }
    
    return retValue;
}

@end

