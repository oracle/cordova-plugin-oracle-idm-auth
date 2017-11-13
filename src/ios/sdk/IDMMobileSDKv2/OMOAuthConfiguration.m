/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAuthConfiguration.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"
#import "OMClientCertChallangeHandler.h"

NSString const *kLoginHint = @"defaultUser";

@interface OMOAuthConfiguration ()

@property(nonatomic, strong) NSThread *callerThread;

@end

@implementation OMOAuthConfiguration

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;
{
    self = [super initWithProperties:properties error:error];
    NSUInteger errorCode = -1;

    if (self)
    {
        
        //Some properties are not discovered with config URL
        id grantType = [properties
                        valueForKey:OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE];
        id clientSecret = [properties
                           valueForKey:OM_PROP_OAUTH_CLIENT_SECRET];
        id clientId = [properties valueForKey:OM_PROP_OAUTH_CLIENT_ID];
        id scope = [properties valueForKey:OM_PROP_OAUTH_SCOPE];
        id logoutURL = [properties valueForKey:OM_PROP_LOGOUT_URL];
        id offlineAuthAllowed = [properties
                                 valueForKey:OM_PROP_OFFLINE_AUTH_ALLOWED];
        id connectivityMode = [properties
                               valueForKey:OM_PROP_CONNECTIVITY_MODE];
        id redirectURI = [properties
                          valueForKey:OM_PROP_OAUTH_REDIRECT_ENDPOINT];
        id browserMode = [properties valueForKey:OM_PROP_BROWSERMODE];
        id rememberUsernameEnabled = [properties
                                      valueForKey:OM_PROP_REMEMBER_USERNAME_ALLOWED];
        id rememberUsernameDefault = [properties
                                      valueForKey:OM_REMEMBER_USERNAME_DEFAULT];
        id enablePkce = [properties valueForKey:OM_PROP_OAUTH_ENABLE_PKCE];
        id clientRegistrationRequired = [properties
                                          valueForKey:OM_PROP_IDCS_REGISTER_CLIENT];
        id loginHint = [properties valueForKey:OM_PROP_LOGIN_HINT];

        if ([OM_OAUTH_RESOURCE_OWNER caseInsensitiveCompare:grantType] ==
            NSOrderedSame)
        {
            _grantType = OMOAuthResourceOwner;
        }
        else if ([OM_OAUTH_AUTHORIZATION_CODE caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthAuthorizationCode;
        }
        else if ([OM_OAUTH_IMPLICIT caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthImplicit;
        }
        else if ([OM_OAUTH_CLIENT_CREDENTIALS caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMAOAuthClientCredential;
        }
        else if ([OM_OAUTH_ASSERTION caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthAssertion;
        }
        else if ([OM_OAUTH_OAM_CREDENTIAL caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthOAMCredential;
        }
        else
        {
            errorCode = OMERR_OAUTH_INVALID_GRANT;
        }
        
        //RedirectURI is needed only in AuthZCode and Implicit flow
        if (_grantType == OMOAuthAuthorizationCode ||
            _grantType == OMOAuthImplicit)
        {
            if([self isValidString:redirectURI])
            {
                _redirectURI =[NSURL URLWithString:redirectURI];
            }
            else
            {
                errorCode = OMERR_OAUTH_REDIRECT_ENDPOINT_INVALID;
            }
        }
        if([self isValidString:clientId])
        {
            _clientId = clientId;
        }
        else
        {
            errorCode = OMERR_OAUTH_CLIENT_ID_INVALID;
        }
        
        if ((clientSecret != nil &&
             [clientSecret isKindOfClass:[NSString class]] == false))
        {
            errorCode = OMERR_OAUTH_CLIENT_SECRET_INVALID;
        }
        else
        {
            _clientSecret = clientSecret;
        }
        if ((scope != nil &&
             [scope isKindOfClass:[NSSet class]] == false))
        {
            errorCode = OMERR_OAUTH_INVALID_SCOPE;
        }
        else
        {
            _scope = scope;
        }
        if (logoutURL != nil &&
            [logoutURL isKindOfClass:[NSString class]] == false)
        {
            errorCode = OMERR_LOGOUT_URL_IS_INVALID;
        }
        else if (logoutURL)
        {
            _logoutURL = [NSURL URLWithString:logoutURL];
            if (!_logoutURL)
            {
                errorCode = OMERR_LOGOUT_URL_IS_INVALID;
            }
        }
        _offlineAuthAllowed = [OMMobileSecurityConfiguration
                               boolValue:offlineAuthAllowed];
        if (connectivityMode &&
            [connectivityMode isKindOfClass:[NSString class]] == false)
        {
            errorCode =  OMERR_INVALID_CONNECTIVITY_MODE;
            
        }
        else
        {
            if ([OM_CONNECTIVITY_ONLINE
                 caseInsensitiveCompare:connectivityMode] == NSOrderedSame)
            {
                _connectivityMode = OMConnectivityOnline;
            }
            else if ([OM_CONNECTIVITY_OFFLINE
                      caseInsensitiveCompare:connectivityMode]
                     == NSOrderedSame)
            {
                _connectivityMode = OMConnectivityOffline;
            }
            else
            {
                _connectivityMode = OMConnectivityAuto;
            }
            
        }
        
        _browserMode = OMBrowserModeEmbedded;
        if (browserMode && [browserMode isKindOfClass:[NSString class]])
        {
            if ([OM_PROP_BROWSERMODE_EMBEDDED
                 caseInsensitiveCompare:browserMode] == NSOrderedSame)
            {
                self.browserMode = OMBrowserModeEmbedded;
            }
            else if([OM_PROP_BROWSERMODE_EXTERNAL
                     caseInsensitiveCompare:browserMode] == NSOrderedSame)
            {
                self.browserMode = OMBrowserModeExternal;
            }
        }
        self.rememberUsernameAllowed = [OMMobileSecurityConfiguration
                                        boolValue:rememberUsernameEnabled];
        self.rememberUsernameDefault = [OMMobileSecurityConfiguration
                                        boolValue:rememberUsernameDefault];
        
        self.enablePkce = [OMMobileSecurityConfiguration boolValue:enablePkce];
        _isClientRegistrationRequired = [OMMobileSecurityConfiguration boolValue:clientRegistrationRequired];
        
        if ([self isValidString:loginHint])
        {
            _loginHint = loginHint;

        }
        self.sessionTimeout = 0;
        // Token and authorization endpoint are required if discovery
        // JSON/URL is not present
        id discoveryEndpoint = [properties
                                valueForKey:OM_PROP_OAUTH_DISCOVERY_URL];
        if (discoveryEndpoint == nil)
        {
            discoveryEndpoint =  [properties valueForKey:OM_PROP_OPENID_CONNECT_CONFIGURATION_URL];

        }
        id discoveryJSON = [properties
                            valueForKey:OM_PROP_OPENID_CONNECT_CONFIGURATION];
        id oauthServiceEndpoint =
                [properties valueForKey:OM_PROP_OAUTH_OAM_SERVICE_ENDPOINT];

        if ((nil == discoveryEndpoint && nil == discoveryJSON) &&
            oauthServiceEndpoint == nil)
        {
            id tokenEndpoint = [properties
                                valueForKey:OM_PROP_OAUTH_TOKEN_ENDPOINT];
            if([self isValidString:tokenEndpoint] &&
               [self isValidUrl:tokenEndpoint])
            {
                _tokenEndpoint =[NSURL URLWithString:tokenEndpoint];
            }
            else
            {
                errorCode = OMERR_OAUTH_TOKEN_ENDPOINT_INVALID;
            }
            
            if (_grantType == OMOAuthAuthorizationCode ||
                _grantType == OMOAuthImplicit)
            {
                id authEndpoint = [properties
                                   valueForKey:OM_PROP_OAUTH_AUTHORIZATION_ENDPOINT];
                if([self isValidString:authEndpoint] &&
                   [self isValidUrl:authEndpoint])
                {
                    _authEndpoint =[NSURL URLWithString:authEndpoint];
                }
                else
                {
                    errorCode = OMERR_OAUTH_AUTHZ_ENDPOINT_INVALID;
                }
            }
            
            id clientRegistrationEndpoint = [properties
                                valueForKey:OM_PROP_IDCS_REGISTER_ENDPOINT];
           
            if([self isValidString:clientRegistrationEndpoint] &&
               [self isValidUrl:clientRegistrationEndpoint])
            {
                _clientRegistrationEndpoint =[NSURL URLWithString:clientRegistrationEndpoint];
            }

        }
        else
        {
            if([self isValidString:discoveryEndpoint] &&
               [self isValidUrl:discoveryEndpoint])
            {
                _discoverEndpoint =[NSURL URLWithString:discoveryEndpoint];
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

- (NSInteger)setConfiguration:(NSDictionary *) properties
{
    NSInteger errorCode = -1;
    id authServerType = [properties valueForKey:OM_PROP_AUTHSERVER_TYPE];
    id grantType = [properties
                    valueForKey:OM_PROP_OAUTH_AUTHORIZATION_GRANT_TYPE];
    if (([OM_PROP_OAUTH_OAUTH20_SERVER caseInsensitiveCompare:authServerType] == NSOrderedSame)
        || ([OM_PROP_OPENID_CONNECT_SERVER caseInsensitiveCompare:authServerType] == NSOrderedSame))
    {
        if ([OM_OAUTH_RESOURCE_OWNER caseInsensitiveCompare:grantType] ==
            NSOrderedSame)
        {
            _grantType = OMOAuthResourceOwner;
        }
        else if ([OM_OAUTH_AUTHORIZATION_CODE caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthAuthorizationCode;
        }
        else if ([OM_OAUTH_IMPLICIT caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthImplicit;
        }
        else if ([OM_OAUTH_CLIENT_CREDENTIALS caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMAOAuthClientCredential;
        }
        else if ([OM_OAUTH_ASSERTION caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthAssertion;
        }
        else if ([OM_OAUTH_OAM_CREDENTIAL caseInsensitiveCompare:grantType] ==
                 NSOrderedSame)
        {
            _grantType = OMOAuthOAMCredential;
        }
        else
        {
            errorCode = OMERR_OAUTH_INVALID_GRANT;
        }
        id tokenEndpoint = [properties
                            valueForKey:OM_PROP_OAUTH_TOKEN_ENDPOINT];
        id clientSecret = [properties
                           valueForKey:OM_PROP_OAUTH_CLIENT_SECRET];
        id clientId = [properties valueForKey:OM_PROP_OAUTH_CLIENT_ID];
        id scope = [properties valueForKey:OM_PROP_OAUTH_SCOPE];
        id logoutURL = [properties valueForKey:OM_PROP_LOGOUT_URL];
        id offlineAuthAllowed = [properties
                                 valueForKey:OM_PROP_OFFLINE_AUTH_ALLOWED];
        id connectivityMode = [properties
                               valueForKey:OM_PROP_CONNECTIVITY_MODE];
        
        id authEndpoint = [properties
                           valueForKey:OM_PROP_OAUTH_AUTHORIZATION_ENDPOINT];
        id redirectURI = [properties
                          valueForKey:OM_PROP_OAUTH_REDIRECT_ENDPOINT];
        id browserMode = [properties valueForKey:OM_PROP_BROWSERMODE];
        id rememberUsernameEnabled = [properties
                                      valueForKey:OM_PROP_REMEMBER_USERNAME_ALLOWED];
        id rememberUsernameDefault = [properties
                                      valueForKey:OM_REMEMBER_USERNAME_DEFAULT];
        
        if (_grantType == OMOAuthAuthorizationCode ||
            _grantType == OMOAuthImplicit)
        {
            if([self isValidString:authEndpoint] &&
               [self isValidUrl:authEndpoint])
            {
                _authEndpoint =[NSURL URLWithString:authEndpoint];
            }
            else
            {
                errorCode = OMERR_OAUTH_AUTHZ_ENDPOINT_INVALID;
            }
            if([self isValidString:redirectURI])
            {
                _redirectURI =[NSURL URLWithString:redirectURI];
            }
            else
            {
                errorCode = OMERR_OAUTH_REDIRECT_ENDPOINT_INVALID;
            }
            
        }
        if([self isValidString:tokenEndpoint] &&
           [self isValidUrl:tokenEndpoint])
        {
            _tokenEndpoint =[NSURL URLWithString:tokenEndpoint];
        }
        else
        {
            errorCode = OMERR_OAUTH_TOKEN_ENDPOINT_INVALID;
        }
        if([self isValidString:clientId])
        {
            _clientId = clientId;
        }
        else
        {
            errorCode = OMERR_OAUTH_CLIENT_ID_INVALID;
        }
        if ((clientSecret != nil &&
             [clientSecret isKindOfClass:[NSString class]] == false))
        {
            errorCode = OMERR_OAUTH_CLIENT_SECRET_INVALID;
        }
        else
        {
            _clientSecret = clientSecret;
        }
        if ((scope != nil &&
             [scope isKindOfClass:[NSSet class]] == false))
        {
            errorCode = OMERR_OAUTH_INVALID_SCOPE;
        }
        else
        {
            _scope = scope;
        }
        if (logoutURL != nil &&
            [logoutURL isKindOfClass:[NSString class]] == false)
        {
            errorCode = OMERR_LOGOUT_URL_IS_INVALID;
        }
        else if (logoutURL)
        {
            _logoutURL = [NSURL URLWithString:logoutURL];
            if (!_logoutURL)
            {
                errorCode = OMERR_LOGOUT_URL_IS_INVALID;
            }
        }
        _offlineAuthAllowed = [OMMobileSecurityConfiguration
                               boolValue:offlineAuthAllowed];
        if (connectivityMode &&
            [connectivityMode isKindOfClass:[NSString class]] == false)
        {
            errorCode =  OMERR_INVALID_CONNECTIVITY_MODE;
            
        }
        else
        {
            if ([OM_CONNECTIVITY_ONLINE
                 caseInsensitiveCompare:connectivityMode] == NSOrderedSame)
            {
                _connectivityMode = OMConnectivityOnline;
            }
            else if ([OM_CONNECTIVITY_OFFLINE
                      caseInsensitiveCompare:connectivityMode]
                     == NSOrderedSame)
            {
                _connectivityMode = OMConnectivityOffline;
            }
            else
            {
                _connectivityMode = OMConnectivityAuto;
            }
            
        }
        
        _browserMode = OMBrowserModeEmbedded;
        if (browserMode && [browserMode isKindOfClass:[NSString class]])
        {
            if ([OM_PROP_BROWSERMODE_EMBEDDED
                 caseInsensitiveCompare:browserMode] == NSOrderedSame)
            {
                self.browserMode = OMBrowserModeEmbedded;
            }
            else if([OM_PROP_BROWSERMODE_EXTERNAL
                     caseInsensitiveCompare:browserMode] == NSOrderedSame)
            {
                self.browserMode = OMBrowserModeExternal;
            }
        }
        self.rememberUsernameAllowed = [OMMobileSecurityConfiguration
                                        boolValue:rememberUsernameEnabled];
        self.rememberUsernameDefault = [OMMobileSecurityConfiguration
                                        boolValue:rememberUsernameDefault];
    }
        // ignore session timeout
    self.sessionTimeout = 0;
    return errorCode;
}

-(void)parseConfigData:(NSDictionary *)json;
{
    NSDictionary *config = [json valueForKey:@"openid-configuration"];
    self.tokenEndpoint = [NSURL URLWithString:[config valueForKey:@"token_endpoint"]];
    self.authEndpoint = [NSURL URLWithString:[config valueForKey:@"authorization_endpoint"]];
    self.clientRegistrationEndpoint = [NSURL URLWithString:[config valueForKey:@"registration_endpoint"]];

}

- (NSString*)loginHint
{
    
    return (_loginHint != nil) ? _loginHint : kLoginHint;
}

- (NSURL*)discoveryUrl;
{
    return self.discoverEndpoint;
}

@end
