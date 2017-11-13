/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMHTTPBasicConfiguration.h"
#import "OMObject.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"

@implementation OMHTTPBasicConfiguration

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error
{
    self = [super initWithProperties:properties error:error];
    NSUInteger errorCode = -1;
    if (self)
    {
        NSString *authServerType = [properties
                                    valueForKey:OM_PROP_AUTHSERVER_TYPE];
        if ([OM_PROP_AUTHSERVER_HTTPBASIC
             caseInsensitiveCompare:authServerType] == NSOrderedSame)
        {
            
            id requiredTokens = [properties
                                 valueForKey:OM_PROP_REQUIRED_TOKENS];
            id connectivityMode = [properties
                                   valueForKey:OM_PROP_CONNECTIVITY_MODE];
            id offlineAuthAllowed = [properties
                                     valueForKey:OM_PROP_OFFLINE_AUTH_ALLOWED];
            id identityDomain = [properties
                                 valueForKey:OM_PROP_IDENTITY_DOMAIN_NAME];
            id collectIdentityDomain = [properties valueForKey:
                                        OM_PROP_COLLECT_IDENTITY_DOMAIN];
            id autoLoginEnabled = [properties
                                   valueForKey:OM_PROP_AUTO_LOGIN_ALLOWED];
            id rememberCredEnabled = [properties
                                      valueForKey:OM_PROP_REMEMBER_CREDENTIALS_ALLOWED];
            id rememberUsernameEnabled = [properties
                                          valueForKey:OM_PROP_REMEMBER_USERNAME_ALLOWED];
            id autoLoginDefault = [properties
                                   valueForKey:OM_AUTO_LOGIN_DEFAULT];
            id rememberCredDefault = [properties
                                      valueForKey:OM_REMEMBER_CREDENTIALS_DEFAULT];
            id rememberUsernameDefault = [properties
                                          valueForKey:OM_REMEMBER_USERNAME_DEFAULT];
            id loginURL = [properties valueForKey:OM_PROP_LOGIN_URL];
            id logoutURL = [properties valueForKey:OM_PROP_LOGOUT_URL];
            
            id provideIdentityDomainNameInHeader = [properties valueForKey:
                                                  OM_PROP_IDENTITY_DOMAIN_NAME_IN_HEADER];
            id identityDomainHeaderName = [properties valueForKey:
                                           OM_PROP_IDENTITY_DOMAIN_HEADER_NAME];

            if (requiredTokens &&
                [requiredTokens isKindOfClass:[NSSet class]] == false)
            {
                errorCode =  OMERR_INVALID_REQUIRED_TOKENS;
                
            }
            else
            {
                _requiredTokens = requiredTokens;
                
            }
            
            if (connectivityMode && [connectivityMode
                                     isKindOfClass:[NSString class]] == false)
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
            _offlineAuthAllowed = [OMMobileSecurityConfiguration
                                   boolValue:offlineAuthAllowed];
            
            
            if (identityDomain && [identityDomain isKindOfClass:
                                   [NSString class]] == false)
            {
                errorCode =  OMERR_INVALID_IDENTITY_DOMAIN;
                
            }
            else
            {
                self.identityDomain = identityDomain;
            }
            
            _collectIdentityDomain = [OMMobileSecurityConfiguration
                                      boolValue:collectIdentityDomain];
            if (identityDomain && [identityDomain isKindOfClass:
                                   [NSString class]] == false)
            {
                errorCode =  OMERR_INVALID_IDENTITY_DOMAIN;
                
            }
            else
            {
                self.identityDomain = identityDomain;
            }
            self.provideIdentityDomainToMobileAgent =
            [OMMobileSecurityConfiguration
             boolValue:provideIdentityDomainNameInHeader];

            if (identityDomainHeaderName &&
                [identityDomainHeaderName isKindOfClass:
                                          [NSString class]] == false)
            {
                errorCode =  OMERR_INVALID_COLLECT_IDENTITY_DOMAIN;
                
            }
            else
            {
                    self.identityDomainHeaderName = identityDomainHeaderName;
            }

            self.autoLoginAllowed = [OMMobileSecurityConfiguration
                                     boolValue:autoLoginEnabled];
            self.rememberCredAllowed = [OMMobileSecurityConfiguration
                                        boolValue:rememberCredEnabled];
            self.rememberUsernameAllowed = [OMMobileSecurityConfiguration
                                            boolValue:rememberUsernameEnabled];
            self.autoLoginDefault = [OMMobileSecurityConfiguration
                                     boolValue:autoLoginDefault];
            self.rememberCredDefault = [OMMobileSecurityConfiguration
                                        boolValue:rememberCredDefault];
            self.rememberUsernameDefault = [OMMobileSecurityConfiguration
                                            boolValue:rememberUsernameDefault];
            if([self isValidString:loginURL] && [self isValidUrl:loginURL])
            {
                _loginURL = [NSURL URLWithString:loginURL];
            }
            else
            {
                errorCode =  OMERR_LOGIN_URL_IS_INVALID;
            }
            
            if([self isValidString:logoutURL] && [self isValidUrl:logoutURL])
            {
                _logoutURL =[NSURL URLWithString:logoutURL];
            }
            else
            {
                errorCode = OMERR_LOGOUT_URL_IS_INVALID;
            }
        }
        else
        {
            errorCode = OMERR_INVALID_AUTH_SERVER_TYPE;
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

-(NSString *)description
{
    return [NSString stringWithFormat:@"%@:%@\n%@:%@\n%@:%@\n%@:%@\n%@:%@\n"
            "%@:%d\n%@:%d\n%@:%d\n%@:%d\n",
            OM_PROP_AUTHSERVER_TYPE, OM_PROP_AUTHSERVER_HTTPBASIC,
            OM_PROP_LOGIN_URL,self.loginURL,
            OM_PROP_LOGOUT_URL,self.logoutURL,
            OM_PROP_REQUIRED_TOKENS,_requiredTokens,
            OM_PROP_APPNAME,self.appName,
            OM_PROP_MAX_LOGIN_ATTEMPTS,self.authenticationRetryCount,
            OM_PROP_OFFLINE_AUTH_ALLOWED,_offlineAuthAllowed,
            OM_PROP_IDLE_TIMEOUT_VALUE, self.idleTimeout,
            OM_PROP_SESSION_TIMEOUT_VALUE,self.sessionTimeout];
}

@end
