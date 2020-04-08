/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMMobileSecurityService.h"
#import "OMMobileSecurityConfiguration.h"
#import "OMHTTPBasicConfiguration.h"
#import "OMObject.h"
#import "OMHTTPBasicConfiguration.h"
#import "OMAuthenticationManager.h"
#import "OMDefinitions.h"
#import "OMHTTPBasicLogoutService.h"
#import "OMCredentialStore.h"
#import "OMCredential.h"
#import "OMClientCertConfiguration.h"
#import "OMFedAuthConfiguration.h"
#import "OMClientCertLogoutService.h"
#import "OMFedAuthLogoutService.h"
#import "OMOAuthConfiguration.h"
#import "OMAuthenticationManager.h"
#import "OMErrorCodes.h"
#import "OMOAuthLogoutService.h"
#import "OMCryptoService.h"
#import "NSData+OMBase64.h"
#import "OMOpenIDCConfiguration.h"
#import "OMOIDCConfiguration.h"
#import "OMOAMOAuthConfiguration.h"
#import "OMOIDCLogoutService.h"
#import "OMServiceDiscoveryHandler.h"
#import "OMURLProtocol.h"

@interface OMMobileSecurityService()

@property (nonatomic, strong) id logoutSer;
@end

@implementation OMMobileSecurityService

- (id)initWithProperties: (NSDictionary *)properties
                delegate: (id<OMMobileSecurityServiceDelegate>) delegate
                   error:(NSError **)error;
{
    self = [super init];
    if (self)
    {
        self.delegate = delegate;
        if (properties)
        {
            NSString *authServerType =
            [properties valueForKey:OM_PROP_AUTHSERVER_TYPE];
            if (![authServerType isKindOfClass:[NSString class]])
            {
                if(error)
                {
                    *error = [OMObject
                              createErrorWithCode:OMERR_INVALID_AUTH_SERVER_TYPE];
                }
            }
            else if ([OM_PROP_AUTHSERVER_HTTPBASIC
                      caseInsensitiveCompare:authServerType] == NSOrderedSame)
            {
                _configuration = [[OMHTTPBasicConfiguration alloc]
                                  initWithProperties:properties error:error];
            }
            else if ([OM_PROP_AUTHSERVER_CLIENT_CERT
                      caseInsensitiveCompare:authServerType] == NSOrderedSame)
            {
                _configuration = [[OMClientCertConfiguration alloc]
                                  initWithProperties:properties error:error];
            }
            else if ([OM_PROP_OAUTH_OAUTH20_SERVER
                      caseInsensitiveCompare:authServerType] == NSOrderedSame)
            {
                id oauthServiceEndpoint =
                [properties valueForKey:OM_PROP_OAUTH_OAM_SERVICE_ENDPOINT];
                if (oauthServiceEndpoint)
                {
                    _configuration = [[OMOAMOAuthConfiguration alloc]
                                      initWithProperties:properties
                                      error:error];
                }
                else
                {
                    _configuration = [[OMOAuthConfiguration alloc]
                                      initWithProperties:properties error:error];
                }
            }
            else if ([OM_PROP_AUTHSERVER_FED_AUTH
                      caseInsensitiveCompare:authServerType] == NSOrderedSame)
            {
                _configuration = [[OMFedAuthConfiguration alloc]
                                  initWithProperties:properties error:error];
                
            }
            else if ([OM_PROP_OPENID_CONNECT_SERVER
                      caseInsensitiveCompare:authServerType] == NSOrderedSame)
            {
                _configuration = [[OMOIDCConfiguration alloc]
                                  initWithProperties:properties error:error];
                
            }
            else if(error)
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_INVALID_AUTH_SERVER_TYPE];
            }
            if (!_configuration)
            {
                self = nil;
                if (error && [*error code] < 999)
                {
                    *error = [OMObject
                              createErrorWithCode:OMERR_INITIALIZATION_FAILED];
                }
                
            }
            else
            {
                _cacheDict = [[NSMutableDictionary alloc] init];
                
                if (_configuration.localAuthenticatorIntanceId)
                {
                    [[OMCredentialStore sharedCredentialStore]
                     setLocalAuthenticatorInstanceId:
                     _configuration.localAuthenticatorIntanceId];
                }
                
            }
        }
        else
        {
            *error = [OMObject
                      createErrorWithCode:OMERR_INITIALIZATION_FAILED];
        }
    }
    return self;
}

-(NSError *)setup
{
    NSError *error = nil;
    
    if ([self.configuration isKindOfClass:[OMOIDCConfiguration class]])
    {
        OMOIDCConfiguration *config = (OMOIDCConfiguration *)self.configuration;
        
        [[OMServiceDiscoveryHandler sharedHandler]
         discoverConfigurationWithURL:[config discoveryUrl] withMss:self
         completion:^(NSDictionary * _Nullable propertiesJSON, NSError * _Nullable discoveryError)
        {
            [config parseConfigData:propertiesJSON];
        }];
    }
    else if ([self.configuration isKindOfClass:[OMOAMOAuthConfiguration class]])
    {
        
        OMOAMOAuthConfiguration *config = (OMOAMOAuthConfiguration *)
                                            self.configuration;
        [[OMServiceDiscoveryHandler sharedHandler]
         discoverConfigurationWithURL:[config discoveryUrl] withMss:self
         completion:^(NSDictionary * _Nullable propertiesJSON, NSError * _Nullable discoveryError)
         {
             [config parseConfigData:propertiesJSON];
         }];
        

    }
    else if ([self.configuration isKindOfClass:[OMOAuthConfiguration class]] &&
             [(OMOAuthConfiguration *)self.configuration discoveryUrl])
    {
            OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.configuration;
        
            [[OMServiceDiscoveryHandler sharedHandler]
             discoverConfigurationWithURL:[config discoveryUrl] withMss:self
             completion:^(NSDictionary * _Nullable propertiesJSON, NSError * _Nullable discoveryError)
             {
                 [config parseConfigData:propertiesJSON];
             }];

    }
    else
    {
        if ([self.delegate
             respondsToSelector:@selector(mobileSecurityService:
                                          completedSetupWithConfiguration:
                                          error:)])
        {
            [self.delegate mobileSecurityService:self
                 completedSetupWithConfiguration:self.configuration
                                           error:nil];
        }
        else
        {
            error = [OMObject createErrorWithCode:OMERR_DELEGATE_NOT_SET];
            
        }

    }
    return error;
}
-(NSError *)startAuthenticationProcess:(OMAuthenticationRequest*)request
{
    NSError *error = nil;
    if (!self.delegate)
    {
        error = [OMObject createErrorWithCode:OMERR_DELEGATE_NOT_SET];
    }
    else if (self.authManager.isAuthRequestInProgress)
    {
        error = [OMObject createErrorWithCode:OMERR_LOGIN_IS_IN_PROGRESS];
    }
    else if (self.authManager != nil &&
        [self.authManager.curentAuthService.context isValid:NO] &&
        !request.forceAuth)
    {
        [self.authManager sendAuthenticationContext:self.authManager.curentAuthService.context
                                              error:nil];
    }
    else if ([[self authenticationContext] isValid:YES])
    {
        self.authManager = [[OMAuthenticationManager alloc]
                            initWithMobileSecurityService:self
                            authenticationRequest:request];

        [self.authManager sendAuthenticationContext:[self authenticationContext]
                                              error:nil];        
    }
    else
    {
        self.authManager = [[OMAuthenticationManager alloc]
                            initWithMobileSecurityService:self
                            authenticationRequest:request];
        [self.authManager startAuthenticationProcess];

    }
    
    return error;
}

-(void)logout:(BOOL)clearRegistrationHandles
{
    OMLogoutService *logoutService = nil;
    
    if ([self.configuration isKindOfClass:[OMHTTPBasicConfiguration class]])
    {
        logoutService = [[OMHTTPBasicLogoutService alloc]
                         initWithMobileSecurityService:self];
    }
    else if ([self.configuration isKindOfClass:[OMClientCertConfiguration class]])
    {
        
        logoutService = [[OMClientCertLogoutService alloc]
                             initWithMobileSecurityService:self];

    }
    else if ([self.configuration isKindOfClass:[OMFedAuthConfiguration class]])
    {
        
        logoutService = [[OMFedAuthLogoutService alloc]
                         initWithMobileSecurityService:self];
        
    }
    else if ([self.configuration isKindOfClass:[OMOIDCConfiguration class]])
    {
        logoutService = [[OMOIDCLogoutService alloc]
                         initWithMobileSecurityService:self];
    }
    else if ([self.configuration isKindOfClass:[OMOAuthConfiguration class]])
    {
        logoutService = [[OMOAuthLogoutService alloc]
                         initWithMobileSecurityService:self];
    }
    _logoutSer = logoutService;
    
    if (_logoutSer) 
    {
        OMAuthenticationContext *context = [self.cacheDict valueForKey:self.authKey];
        if (clearRegistrationHandles)
        {
            NSString *key = [self
                             offlineAuthenticationKeyWithIdentityDomain:
                             context.identityDomain
                             username:context.userName];
            [[OMCredentialStore sharedCredentialStore]
             deleteCredential:key];
            
        }
        [self clearRememberCredentials:clearRegistrationHandles];
        [context stopTimers];
        [logoutService performLogout:clearRegistrationHandles];
    }
}

-(NSString *)key
{
    NSString *key = nil;
    NSString *credentialKey = (self.configuration.authKey != nil)?
                                self.configuration.authKey:
                                self.configuration.appName;
    
    if ([self.configuration isKindOfClass:[OMHTTPBasicConfiguration class]])
    {
        OMHTTPBasicConfiguration *config = (OMHTTPBasicConfiguration *)
        self.configuration;
        key = [NSString stringWithFormat:@"%@_%@",
               config.loginURL,credentialKey];
    }
    else if ([self.configuration
              isKindOfClass:[OMClientCertConfiguration class]])
    {
        OMClientCertConfiguration *config = (OMClientCertConfiguration *)
        self.configuration;
        key = [NSString stringWithFormat:@"%@_%@",
               config.loginURL,credentialKey];
    }
    else if ([self.configuration
              isKindOfClass:[OMFedAuthConfiguration class]])
    {
        OMFedAuthConfiguration *config = (OMFedAuthConfiguration *)
        self.configuration;
        key = [NSString stringWithFormat:@"%@_%@",
               config.loginURL,credentialKey];
    }
    else if ([self.configuration
              isKindOfClass:[OMOAuthConfiguration class]])
    {
        OMOAuthConfiguration *config = (OMOAuthConfiguration *)
        self.configuration;
        key = [NSString stringWithFormat:@"%@_%@",
               config.tokenEndpoint,credentialKey];
    }
    return key;
}

-(NSString *)authKey
{
    return [NSString stringWithFormat:@"%@_authContext",[self key]];
}

-(NSString *)rememberCredKey
{
    return [NSString stringWithFormat:@"%@_RC",[self key]];
}

-(NSString *)offlineAuthKey
{
    return [NSString stringWithFormat:@"%@_offlineAuth",[self key]];
}

- (NSString *) offlineAuthenticationKeyWithIdentityDomain:(NSString *)identityDomain
                                                 username:(NSString *)username
{
    return [NSString stringWithFormat:@"%@_%@::%@",
            [self offlineAuthKey],
            [identityDomain length]?identityDomain:@"",
            username];
}

-(NSString *) maxRetryKeyWithIdentityDomain:(NSString *)identityDomain
                                   username:(NSString *)username
{
    return [NSString stringWithFormat:@"%@_MAXRETRY%@::%@",
            [self key],
            [identityDomain length]?identityDomain:@"",
            username];
}

-(void)clearRememberCredentials:(BOOL)clearPreferences
{
    NSString *rememberCredKey = [self rememberCredKey];
    [[NSUserDefaults standardUserDefaults]
     setObject:[NSNumber numberWithBool:FALSE]
     forKey:[NSString stringWithFormat:@"%@_%@", rememberCredKey,
             OM_AUTH_SUCCESS]];
    if (clearPreferences)
    {
        [[NSUserDefaults standardUserDefaults] setObject:
         [NSNumber numberWithBool:FALSE]
        forKey:[NSString stringWithFormat:@"%@_%@",rememberCredKey,
                OM_AUTO_LOGIN_PREF]];
        [[NSUserDefaults standardUserDefaults]
         setObject:[NSNumber numberWithBool:FALSE]
         forKey:[NSString stringWithFormat:@"%@_%@",rememberCredKey,
                 OM_REMEMBER_CREDENTIALS_PREF]];
        
        [[NSUserDefaults standardUserDefaults]
         setObject:[NSNumber numberWithBool:FALSE]
         forKey:[NSString stringWithFormat:@"%@_%@",rememberCredKey,
                 OM_REMEMBER_USERNAME_PREF]];
       
        [[NSUserDefaults standardUserDefaults]
         setObject:[NSNumber numberWithBool:FALSE]
         forKey:[NSString stringWithFormat:@"%@_%@", rememberCredKey,
                 OM_REMEMBER_CRED_PREF_SET]];

        [[OMCredentialStore sharedCredentialStore]
         deleteCredential:rememberCredKey];
    }
    else
    {
        OMCredential *storedCred = [[OMCredentialStore sharedCredentialStore]
                                    getCredential:rememberCredKey];
        storedCred.userPassword = nil;
        [[OMCredentialStore sharedCredentialStore] saveCredential:storedCred
                                                        forKey:rememberCredKey];
    }
}

-(void)clearOfflineCredentials:(BOOL)clearPreferences
{
    OMAuthenticationContext *context = [self.cacheDict valueForKey:self.authKey];
    if (clearPreferences)
    {
        NSString *key = [self
                         offlineAuthenticationKeyWithIdentityDomain:
                         context.identityDomain
                         username:context.userName];
        [[OMCredentialStore sharedCredentialStore]
         deleteCredential:key];
        
    }

}
-(void)cancelAuthentication
{
    [self.authManager cancelAuthentication];

}

+(NSArray *)cookiesForURL: (NSURL *)theURL
{
    if (theURL == nil)
        return [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies];
    
    return [[NSHTTPCookieStorage sharedHTTPCookieStorage]
            cookiesForURL:theURL];
}

-(OMAuthenticationContext *)authenticationContext
{
    OMAuthenticationContext *context = [self.cacheDict
                                        valueForKey:self.authKey];
    if (!context)
    {
        context = [self retriveAuthenticationContext];
        
        if (context)
        {
            [context setMss:self];
            
            if (!self.cacheDict)
            {
                self.cacheDict = [NSMutableDictionary dictionary];
            }
            [self.cacheDict setObject:context forKey:self.authKey];

        }
    }
    return context;
}

-(NSData *)symmetricEncryptionKey
{
    NSError *error = nil;
    NSString *storageKey = [NSString stringWithFormat:@"%@_ENCKEY",self.authKey];
    OMCredentialStore *credStore = [OMCredentialStore sharedCredentialStore];
    NSString *uuid = [credStore getCredential:storageKey].userName;
    if (![uuid length])
    {
        uuid = [[NSUUID UUID]UUIDString];
        OMCredential *cred = [[OMCredential alloc] init];
        cred.userName = uuid;
        [credStore saveCredential:cred forKey:storageKey];
    }
    NSData *data = [OMCryptoService generateSymmetricKeyWithPassPhrase:uuid
                                                              outError:&error];
    return data.length?data:nil;
}

- (NSDictionary *)logoutHeaders:(OMAuthenticationContext *)ctx
{
    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
    if(self.configuration.sendCustomHeadersLogout &&
       [self.configuration.customHeaders count] > 0)
    {
        [headers
         addEntriesFromDictionary:self.configuration.customHeaders];
    }
    if(self.configuration.identityDomainInHeader &&
       [ctx.identityDomain length] > 0)
    {
        NSString *headerName = (self.configuration.identityDomainHeaderName)
        ? self.configuration.identityDomainHeaderName :
        OM_DEFAULT_IDENTITY_DOMAIN_HEADER;
        [headers setObject:ctx.identityDomain
                    forKey:headerName];
    }
    BOOL offlineAuthAllowed = ((OMHTTPBasicConfiguration *)self.configuration).
                                                            offlineAuthAllowed;
    if(self.configuration.sendAuthHeaderLogout &&
       offlineAuthAllowed)
    {
        NSString *encodedCred = [self base64EncodedCredentials:ctx];
        if([encodedCred length] > 0)
        {
            NSString *headerValue = [NSString stringWithFormat:@"Basic %@",
                                     encodedCred];
            [headers setObject:headerValue forKey:OM_AUTHORIZATION];
        }
    }
    if([headers count] > 0)
        return headers;
    return nil;
}

- (NSString *)base64EncodedCredentials:(OMAuthenticationContext *)ctx
{
    OMCredentialStore *credStore = [OMCredentialStore sharedCredentialStore];
    OMCredential *offlineCredential =[credStore
                                      getCredential:ctx.offlineCredentialKey];
    if(offlineCredential == nil)
        return nil;
    
    NSError *error = nil;
    NSString *userName = offlineCredential.userName;
    NSString *password = [ctx passwordForCredential:offlineCredential
                                           outError:&error];
    if(error != nil || [password length] == 0)
        return nil;
    
    NSString *credString = [NSString stringWithFormat:@"%@:%@",
                            userName,password];
    NSData *credData = [credString dataUsingEncoding:NSUTF8StringEncoding];
    password = nil;
    credString = nil;
    return [credData base64EncodedString];
}

- (void)saveAuthContext:(OMAuthenticationContext *)context
{
    if (context && self.configuration.sessionActiveOnRestart)
    {
        [[OMCredentialStore sharedCredentialStore]
         saveAuthenticationContext:context forKey:[self authKey]];
    }
}

- (OMAuthenticationContext*)retriveAuthenticationContext
{
    OMAuthenticationContext *authContext = nil;
    
    if (self.configuration.sessionActiveOnRestart)
    {
       authContext = [[OMCredentialStore sharedCredentialStore]
                      retriveAuthenticationContext:[self authKey]];
    }
    
    return authContext;
}
- (BOOL)isNSURLProtocolActive
{
    BOOL isActive = NO;

    if (self.authManager.curentAuthService == [OMURLProtocol currentOMAObject])
    {
        isActive = YES;
    }
    
    return isActive;
}

- (void)registerNSURLProtocol
{
    [OMURLProtocol setOMAObject:self.authManager.curentAuthService];
    [NSURLProtocol registerClass:[OMURLProtocol class]];

}
- (void)deregisterNSURLProtocol
{
    [OMURLProtocol setOMAObject:nil];
    [NSURLProtocol unregisterClass:[OMURLProtocol class]];
}

@end
