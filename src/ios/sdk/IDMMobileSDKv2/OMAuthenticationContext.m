/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticationContext.h"
#import "OMMobileSecurityService.h"
#import "OMTimer.h"
#import "OMTimeEvent.h"
#import "OMHTTPBasicConfiguration.h"
#import "OMDefinitions.h"
#import "OMCredentialStore.h"
#import "OMCryptoService.h"
#import "OMClientCertConfiguration.h"
#import "OMFedAuthConfiguration.h"
#import "OMOAuthConfiguration.h"
#import "OMToken.h"
#import "OMOAuthConfiguration.h"
#import "NSData+OMBase64.h"
#import "OMOAuthAuthenticationService.h"
#import "OMOIDCConfiguration.h"
#import "OMWKWebViewCookieHandler.h"

 NSString *kSessionExpiryDate = @"sessionExpiryDate";
 NSString *kTokensList = @"tokensList";
 NSString *kUserInfo = @"userInfo";
 NSString *kOfflineCredentialKey = @"offlineCredentialKey";
 NSString *kIDToken = @"idToken";
 NSString *kVisitedHosts = @"visitedHosts";
 NSString *kAuthMode = @"authMode";
 NSString *kTokenValue = @"tokenValue";


@interface OMAuthenticationContext ()

@property (nonatomic, strong) OMTimer *sessionTimer;
@property (nonatomic, strong) OMTimer *idleTimer;
@property (nonatomic, strong) NSMutableArray *deletedToken;

@end

@implementation OMAuthenticationContext
-(id)initWithMss:(OMMobileSecurityService*)inObj
{
    self = [super init];
    if (self)
    {
        _visitedHosts = [[NSMutableArray alloc] init];
        _tokens = [[NSMutableArray alloc] init];
        _mss = inObj;
    }
    return self;
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    self = [super init];
    if(self)
    {
        _accessTokens = [aDecoder decodeObjectForKey:OM_TOKENS];
        _sessionExpiryDate = [aDecoder
                                  decodeObjectForKey:kSessionExpiryDate];
        _tokens = [aDecoder decodeObjectForKey:kTokensList];
        _userName = [aDecoder decodeObjectForKey:OM_USERNAME];
        _userInfo = [aDecoder decodeObjectForKey:kUserInfo];
        _offlineCredentialKey = [aDecoder
                                 decodeObjectForKey:kOfflineCredentialKey];
        _idToken = [aDecoder decodeObjectForKey:kIDToken];
        _visitedHosts = [aDecoder decodeObjectForKey:kVisitedHosts];
        _authMode = [[aDecoder decodeObjectForKey:kAuthMode] unsignedIntegerValue];
        _tokenValue = [aDecoder decodeObjectForKey:kTokenValue];
        _identityDomain = [aDecoder decodeObjectForKey:OM_IDENTITY_DOMAIN];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.accessTokens forKey:OM_TOKENS];
    [aCoder encodeObject:self.tokens forKey:kTokensList];
    [aCoder encodeObject:self.sessionExpiryDate forKey:kSessionExpiryDate];
    [aCoder encodeObject:self.userName forKey:OM_USERNAME];
    [aCoder encodeObject:_userInfo forKey:kUserInfo];
    [aCoder encodeObject:_offlineCredentialKey forKey:kOfflineCredentialKey];
    [aCoder encodeObject:_idToken forKey:kIDToken];
    [aCoder encodeObject:_visitedHosts forKey:kVisitedHosts];
    [aCoder encodeObject:[NSNumber numberWithUnsignedInteger:_authMode]
                  forKey:kAuthMode];
    [aCoder encodeObject:_tokenValue forKey:kTokenValue];
    [aCoder encodeObject:self.identityDomain forKey:OM_IDENTITY_DOMAIN];
}

- (id)copyWithZone:(NSZone *)zone
{
    OMAuthenticationContext *context = [[[self class] allocWithZone:zone] init];
    context.tokenValue = [_tokenValue copy];
    context.userName = [_userName copy];
    context.identityDomain = [_identityDomain copy];
    context.sessionExpiryDate = [_sessionExpiryDate copy];
    context.idleTimeExpiryDate = [_idleTimeExpiryDate copy];
    context.accessTokens = [_accessTokens mutableCopy];
    context.tokens = [_tokens mutableCopy];
    context.offlineCredentialKey = [_offlineCredentialKey copy];
    context.delegate = _delegate;
    context.visitedHosts = [_visitedHosts mutableCopy];
    context.deletedToken = [_deletedToken mutableCopy];
    return context;
}

///////////////////////////////////////////////////////////////////////////////
//Clear all cookies of URLs visited during login operation from cookie store
///////////////////////////////////////////////////////////////////////////////

-(void)clearCookies:(BOOL)clearPersistentCookies
{
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    for (NSURL *url in self.visitedHosts)
    {
        NSArray *cookies = [cookieStore cookiesForURL:url];
        for (NSHTTPCookie *cookie in cookies)
        {
            if (clearPersistentCookies)
            {
                [cookieStore deleteCookie:cookie];
            }
            if ([cookie isSessionOnly])
            {
                [cookieStore deleteCookie:cookie];
            }
        }
    }
}

- (NSArray *)getHttpCookies{
    
    NSMutableArray *cookiesList = [NSMutableArray array];
    
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    for (NSURL *url in self.visitedHosts)
    {
        NSArray *cookies = [cookieStore cookiesForURL:url];
        [cookiesList addObjectsFromArray:cookies];
    }
    
    return cookiesList;
    
}

- (NSArray *)cookies
{
    NSArray *cookiesList = nil;
    
    if(@available(iOS 11, *))
    {
        cookiesList = [self getHttpCookies];
    }
    else
    {
        if(![self isWkWebViewEnabled]){
            
            cookiesList = [self getHttpCookies];
        }
    }
        
    
    return cookiesList;
}

- (void)startTimers
{
    if([NSThread currentThread] == [NSThread mainThread])
    {
        [self startSessionTimer];
        [self startIdleTimer];
    }
    else
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            
            [self startSessionTimer];
            [self startIdleTimer];
        });
    }
}

- (void)stopTimers
{
    if([NSThread currentThread] == [NSThread mainThread])
    {
        [self.sessionTimer stop];
        [self.idleTimer stop];
    }
    else
    {
        dispatch_async(dispatch_get_main_queue(), ^{
            
            [self.sessionTimer stop];
            [self.idleTimer stop];
        });

    }
}

- (void)startSessionTimer
{
    if (_sessionTimer.isRunning) {
        return;
    }
    _sessionTimer = [[OMTimer alloc] init];
    _sessionTimer.duration	= self.mss.configuration.sessionTimeout;
    self.sessionExpiryDate = [[NSDate alloc] initWithTimeIntervalSinceNow:
                              self.mss.configuration.sessionTimeout];
    __weak OMAuthenticationContext *weakSelf = self;
    _sessionTimer.completionBlock = ^void (OMTimer *timer)
    {
        if ([weakSelf.delegate  respondsToSelector:@selector
             (authContext:timeoutOccuredForTimer:remainingTime:)])
        {
            [weakSelf.delegate  authContext:weakSelf
          timeoutOccuredForTimer:OMSessionTimer
                   remainingTime:0];
            [[weakSelf idleTimer] stop];
            [weakSelf isValid];
        }
    };
    [_sessionTimer start];
}

- (void)startIdleTimer
{
    _idleTimer = [[OMTimer alloc] init];
    _idleTimer.duration	= self.mss.configuration.idleTimeout;
    self.idleTimeExpiryDate = [[NSDate alloc] initWithTimeIntervalSinceNow:
                              self.mss.configuration.idleTimeout];
    __weak OMAuthenticationContext *weakSelf = self;
    NSInteger timeOutDelta = (self.mss.configuration.percentageToIdleTimeout >1 &&
                            self.mss.configuration.percentageToIdleTimeout < 100) ?
    self.mss.configuration.percentageToIdleTimeout : 80;

    float deltaValue = (self.mss.configuration.idleTimeout *
                        (timeOutDelta * 0.01));
    float idleTimeOutWarningTime = self.mss.configuration.idleTimeout -
                                    deltaValue;
   
    [_idleTimer addEvent:[OMTimeEvent eventAtTime:idleTimeOutWarningTime
                                          withEventBlock:^(OMTimeEvent *event,
                                                           OMTimer *timer)
    {
        if ([weakSelf.delegate respondsToSelector:@selector
             (authContext:timeoutOccuredForTimer:remainingTime:)])
        {            
            [weakSelf.delegate  authContext:weakSelf
          timeoutOccuredForTimer:OMIdleTimer
                   remainingTime:[timer remainingTime]];
        }

    }]];
    
    _idleTimer.completionBlock = ^void (OMTimer *timer)
    {
        
        if ([weakSelf.delegate  respondsToSelector:@selector
             (authContext:timeoutOccuredForTimer:remainingTime:)])
        {
            [weakSelf.delegate  authContext:weakSelf
                     timeoutOccuredForTimer:OMIdleTimer
                              remainingTime:0];
            
            if ([weakSelf.mss.configuration isKindOfClass:
                 [OMFedAuthConfiguration class]])
            {
                [[weakSelf sessionTimer] stop];
                [weakSelf.delegate  authContext:weakSelf
                         timeoutOccuredForTimer:OMSessionTimer
                                  remainingTime:0];
                
            }
        }
        [weakSelf isValid];
    };
    [_idleTimer start];
}

- (BOOL)resetTimer:(OMTimerType)timerType;
{
    BOOL isResetDone = NO;
    
    if (timerType == OMIdleTimer && [self.idleTimer isRunning])
    {
        [self.idleTimer stop];
        [self startIdleTimer];
        isResetDone = YES;
    }
    else
    {
        // don't reset SessionTimer
        isResetDone = NO;
    }
    return isResetDone;
}

- (BOOL)isValid
{
    return [self isValid:false];
}

-(BOOL)isValid:(BOOL)validateOnline
{
    BOOL valid = true;
    OMAuthenticationContext *cachedContext = [self.mss.cacheDict
                                              valueForKey:self.mss.authKey];
    if (!cachedContext || cachedContext.isLogoutFalseCalled)
    {
        return false;
    }
    if ([self.mss.configuration isKindOfClass:[OMHTTPBasicConfiguration class]])
    {
        if (self.idleTimer.duration >0 &&
            (int)self.idleTimer.remainingTime <= 0)
        {
            valid = false;
            if (![(OMHTTPBasicConfiguration*)self.mss.configuration
                 offlineAuthAllowed])
            {
                [self clearCookies:false];

            }
        }
        else
        {
            if (self.idleTimer)
            {
                if([NSThread currentThread] == [NSThread mainThread])
                {
                    [self resetTimer:OMIdleTimer];
                }
                else
                {
                    dispatch_async(dispatch_get_main_queue(), ^{

                        [self resetTimer:OMIdleTimer];

                    });
                }
            }
            else
            {
                valid = false;
            }
        }
        if (self.sessionTimer.duration >0 &&
            (int)self.sessionTimer.remainingTime <= 0)
        {
            valid = false;
            [self clearCookies:false];
            [self.mss clearRememberCredentials:false];
            [self.mss clearOfflineCredentials:true];

            [self.mss.cacheDict removeObjectForKey:self.mss.authKey];
        }
    }
    else if ([self.mss.configuration
              isKindOfClass:[OMFedAuthConfiguration class]])
    {
        if (self.idleTimer.duration >0 &&
            (int)self.idleTimer.remainingTime <= 0)
        {
            valid = false;
           
            if ([self isWkWebViewEnabled]) {
                
                [self clearWebViewCookies:false];
            }
            else
            {
                [self clearCookies:false];
            }
        }
        else
        {
            if([NSThread currentThread] == [NSThread mainThread])
            {
                [self resetTimer:OMIdleTimer];
            }
            else
            {
                dispatch_async(dispatch_get_main_queue(), ^{
                    
                    [self resetTimer:OMIdleTimer];
                    
                });
            }
        }
        if (self.sessionTimer.duration >0 &&
            (int)self.sessionTimer.remainingTime <= 0)
        {
            valid = false;
            if ([self isWkWebViewEnabled]) {
                
                [self clearWebViewCookies:false];
            }
            else
            {
                [self clearCookies:false];
            }
            [self.mss.cacheDict removeObjectForKey:self.mss.authKey];
        }

        if ([(OMFedAuthConfiguration*)self.mss.configuration parseTokenRelayResponse]) {
            
            if ([self isTokensValid:self.tokens])
            {
                valid = true;
            }
            else
            {
                valid = false;
            }
        }

    }
    else if ([self.mss.configuration
              isKindOfClass:[OMClientCertConfiguration class]])
    {
        valid = true;
    }
    else if ([self.mss.configuration
              isKindOfClass:[OMOAuthConfiguration class]])
    {
        if (self.authMode == OMLocal)
        {
            if (self.idleTimer.duration >0 &&
                (int)self.idleTimer.remainingTime <= 0)
            {
                valid = false;
            }
            else
            {
                if([NSThread currentThread] == [NSThread mainThread])
                {
                    [self resetTimer:OMIdleTimer];
                }
                else
                {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        
                        [self resetTimer:OMIdleTimer];
                        
                    });
                }
            }
        }
        else
        {
            if ([self isTokensValid:self.tokens])
            {
                return true;
            }
            OMOAuthConfiguration *config = (OMOAuthConfiguration*)self.mss.configuration;
            valid =  [self isValidForScopes:config.scope
               refreshExpiredToken:validateOnline];
        }
    }
    return valid;
}

- (BOOL)isTokensValid:(NSArray*)omTokens
{
    BOOL isValid = NO;
    
    if([omTokens count] >0)
    {
        NSDate *currentDate = [NSDate date];
        for (OMToken *token in omTokens)
        {
            NSTimeInterval interval = [currentDate
                                       timeIntervalSinceDate:token.tokenIssueDate];
            if(interval < token.expiryTimeInSeconds)
            {
                isValid = true;
                return isValid;
            }
        }
    }
        
    return isValid;
}

- (NSDictionary *)requestInfoForURL:(NSString *)theURL
                     includeHeaders:(BOOL)includeHeaders
{
    NSMutableDictionary *cookieDict = [NSMutableDictionary dictionary];
    
    NSURL *cookieURL = [NSURL URLWithString:theURL];
    NSArray *cookieArray = [OMMobileSecurityService cookiesForURL:cookieURL];
    NSMutableString *cookieString = [[NSMutableString alloc] init];
    for(NSHTTPCookie *cookie in cookieArray)
    {
        NSString *cookieParam = [NSString stringWithFormat:@"%@=%@;",
                                 cookie.name,cookie.value];
        [cookieString appendString:cookieParam];
    }
    
    if([cookieString length] > 0)
    {
        [cookieDict
         setObject:[cookieString substringToIndex:(cookieString.length - 1)]
         forKey:OM_PROP_COOKIES];
    }
    if(includeHeaders)
    {
        [cookieDict setObject:[self customHeaders]
                       forKey:OM_CUSTOM_HEADERS_MOBILE_AGENT];
    }
    
    return cookieDict;
    
}


- (NSDictionary *)requestParametersForURL:(NSString *)theURL
                           includeHeaders:(BOOL)includeHeaders
{
    NSDictionary *cookieDict = nil;

    if(@available(iOS 11, *)){
        
        cookieDict = [self requestInfoForURL:theURL includeHeaders:includeHeaders];
    }
    else{
        
        if(![self isWkWebViewEnabled])
        {
            cookieDict = [self requestInfoForURL:theURL includeHeaders:includeHeaders];

        }
        
    }
        
    return cookieDict;
}

-(NSDictionary *)customHeaders
{
    OMMobileSecurityConfiguration *configuration = self.mss.configuration;
    NSMutableDictionary *headerDict = [NSMutableDictionary dictionary];
    [headerDict addEntriesFromDictionary:
                        configuration.mobileAgentCustomHeaders];
    if(self.identityDomain && configuration.identityDomainInHeader
       && configuration.provideIdentityDomainToMobileAgent)
    {
        NSString *headerName = (configuration.identityDomainHeaderName) ?
                                configuration.identityDomainHeaderName :
                                    OM_DEFAULT_IDENTITY_DOMAIN_HEADER;
        [headerDict setObject:self.identityDomain forKey:headerName];
    }
    return headerDict;
}

-(void)setCredentialInformation:(NSDictionary *)credInfo
{
    NSArray *cookieArray = [credInfo allKeys];
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    for(NSString *key in cookieArray)
    {
        NSDictionary *cMap = [credInfo valueForKey:key];
        NSMutableDictionary *cDict = [[NSMutableDictionary alloc] init];
        NSString *cName = [cMap valueForKey:@"name"];
        if(cName)
            [cDict setObject:cName forKey:NSHTTPCookieName];
        
        NSString *cDomain = [cMap valueForKey:@"domain"];
        if(cDomain)
            [cDict setObject:cDomain forKey:NSHTTPCookieDomain];
        NSString *isSecure = [cMap valueForKey:@"issecure"];
        if(isSecure && ([isSecure caseInsensitiveCompare:@"true"]
                        == NSOrderedSame))
        {
            [cDict setObject:[isSecure uppercaseString]
                      forKey:NSHTTPCookieSecure];
        }
        NSString *path = [cMap valueForKey:@"path"];
        if(path)
            [cDict setObject:path forKey:NSHTTPCookiePath];
        NSString *port = [cMap valueForKey:@"portlist"];
        if([port length] > 0)
            [cDict setObject:port forKey:NSHTTPCookiePort];
        NSString *value = [cMap valueForKey:@"value"];
        if(value)
            [cDict setObject:value forKey:NSHTTPCookieValue];
        NSString *version = [cMap valueForKey:@"version"];
        if([version length] > 0)
            [cDict setObject:version forKey:NSHTTPCookieVersion];
        NSString *expires = [cMap valueForKey:@"expiresdate"];
        if([expires length] > 0)
        {
            NSDateFormatter *dateFormatter = [[NSDateFormatter alloc]init];
            [dateFormatter setDateFormat:@"dd-MMM-yyyy HH:mm:ss zzz"];
            NSDate *expDate = [dateFormatter dateFromString:expires];
            if(expDate != nil)
            {
                [cDict setObject:[dateFormatter dateFromString:expires]
                          forKey:NSHTTPCookieExpires];
            }
        }
        NSHTTPCookie *cookie = [NSHTTPCookie cookieWithProperties:cDict];
        NSString *url = [self urlForCookieWithName:cName andKey:key];
        [self.visitedHosts addObject:[NSURL URLWithString:url]];
        [cookieStore setCookie:cookie];
        cDict = nil;
    }
}

- (NSString *)urlForCookieWithName:(NSString *)name
                            andKey:(NSString *)key
{
    NSUInteger location = [name length] + 1;
    NSString *url = [key substringFromIndex:location];
    return url;
}

- (NSDictionary *)credentialInformationForKeys:(NSArray *)keys
{
    NSDictionary *credentials = nil;
    NSMutableDictionary *credentialDict = [[NSMutableDictionary alloc] init];
    for(NSString *key in keys)
    {
        NSError *error = nil;
        if(NSOrderedSame == [key caseInsensitiveCompare:OM_PROP_CREDENTIALS])
        {
            NSString *key = [self.mss
                             offlineAuthenticationKeyWithIdentityDomain:
                             self.identityDomain
                             username:self.userName];
            OMCredentialStore *credStore = [OMCredentialStore
                                            sharedCredentialStore];
            OMCredential *offlineCredential =[credStore getCredential:key];
            if(offlineCredential != nil)
            {
                NSString *password = [self passwordForCredential:offlineCredential
                                                        outError:&error];
                if(error == nil && [password length] > 0)
                {
                    [credentialDict setObject:password
                                       forKey:OM_PROP_CREDENTIALS_PASSWORD];
                    [credentialDict setObject:[offlineCredential userName]
                                       forKey:OM_PROP_CREDENTIALS_USERNAME];
                }
            }
        }
        if(NSOrderedSame == [key caseInsensitiveCompare:OM_PROP_COOKIES])
        {
            NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                                sharedHTTPCookieStorage];
            for (NSURL *url in self.visitedHosts)
            {
                NSArray *cookies = [cookieStore cookiesForURL:url];
                for(NSHTTPCookie *cookie in cookies)
                {
                    NSMutableDictionary *cDict = [[NSMutableDictionary alloc]
                                                  init];
                    if(cookie.name)
                        [cDict setObject:cookie.name forKey:@"name"];
                    if(cookie.domain)
                        [cDict setObject:cookie.domain forKey:@"domain"];
                    if(cookie.expiresDate)
                    {
                        NSString *dateString = [NSDateFormatter
                                    localizedStringFromDate:cookie.expiresDate
                                    dateStyle:NSDateFormatterShortStyle
                                    timeStyle:NSDateFormatterFullStyle];
                        [cDict setObject:dateString forKey:@"expiresDate"];
                    }
                    [cDict setObject:[NSNumber numberWithBool:cookie.isHTTPOnly]
                              forKey:@"isHTTPOnly"];
                    [cDict setObject:[NSNumber numberWithBool:cookie.isSecure]
                              forKey:@"isSecure"];
                    [cDict setObject:[NSNumber
                                      numberWithBool:cookie.isSessionOnly]
                              forKey:@"isSessionOnly"];
                    if(cookie.path)
                        [cDict setObject:cookie.path forKey:@"path"];
                    if(cookie.portList)
                        [cDict setObject:cookie.portList forKey:@"portList"];
                    if(cookie.value)
                        [cDict setObject:cookie.value forKey:@"value"];
                    [cDict setObject:[NSNumber
                                      numberWithUnsignedInteger:cookie.version]
                              forKey:@"version"];
                    [credentialDict setObject:[NSDictionary
                                               dictionaryWithDictionary:cDict]
                                    forKey:[NSString stringWithFormat:@"%@_%@",
                                               cookie.name,[url host]]];
                }
            }
        }
        if (NSOrderedSame == [key caseInsensitiveCompare:OM_PROP_TOKENS])
        {
            int count = 0;
            for(OMToken *token in self.tokens)
            {
                NSMutableDictionary *tDict = [[NSMutableDictionary alloc] init];
                [tDict setObject:token.tokenName forKey:@"name"];
                [tDict setObject:token.tokenValue forKey:@"value"];
                NSArray *scopes = [token.tokenScopes allObjects];
                if(scopes)
                {
                    [tDict setObject:scopes forKey:@"scope"];
                }
                /*Converting NSDate to NSString as JSON serialization
                 is not available for NSDate*/
                NSString *dateString = [NSDateFormatter
                                        localizedStringFromDate:token.sessionExpiryDate
                                        dateStyle:NSDateFormatterShortStyle
                                        timeStyle:NSDateFormatterFullStyle];
                if(dateString)
                {
                    [tDict setObject:dateString forKey:@"expires"];
                }
                NSString *name = [NSString stringWithFormat:@"%@%d",
                                  OM_OAUTH_ACCESS_TOKEN,++count];
                [credentialDict setObject:tDict forKey:name];
            }

        }
    }
    if([credentialDict count] == 0)
    {
        [credentialDict setObject:@"Credentials unavailable"
                           forKey:OM_PROP_CREDENTIALS_ERROR];
    }
    else
    {
        NSDictionary *headers = [self customHeaders];
        if([headers count] > 0)
        {
            [credentialDict setObject:headers
                               forKey:OM_CUSTOM_HEADERS_MOBILE_AGENT];
        }
    }
    credentials = [NSDictionary dictionaryWithDictionary:credentialDict];
    return credentials;
}

- (NSString *)passwordForCredential:(OMCredential *)cred
                           outError:(NSError **)error
{
    NSString *storedPassword = [cred userPassword];
    if([storedPassword hasPrefix:@"{"])
    {
        NSString *passwordForPrefixCheck = [storedPassword
                                            substringFromIndex:1];
        if([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_AES])
        {
            NSString *password = [self decryptString:storedPassword
                                            outError:error];
            if(*error == nil && [password length] > 0)
            {
                return password;
            }
            
        }
    }
    else if([storedPassword length] > 0)
    {
        return storedPassword;
    }
    return nil;
}

- (NSString *)decryptString:(NSString *) string outError:(NSError **) error
{
    NSData *key = [self.mss symmetricEncryptionKey];
    if (!key)
    {
        return nil;
    }
    NSUInteger algorithmLength = [OM_PROP_CRYPTO_AES length] + 2;
    NSData *decryptedData = [OMCryptoService decryptData:[string
                                                          substringFromIndex:
                                                          algorithmLength]
                                        withSymmetricKey:key
                                    initializationVector:nil
                                               algorithm:OMAlgorithmAES128
                                                 padding:OMPaddingPKCS7
                                                    mode:OMModeCBC
                        isInputPrefixedWithAlgorithmName:NO
                                    isInputBase64Encoded:YES
                                                outError:error];
    if (!decryptedData)
    {
        return nil;
    }
    NSString *decryptedString = [[NSString alloc]
                                 initWithData:decryptedData
                                 encoding:NSUTF8StringEncoding];
    return decryptedString;
}

- (BOOL)isValidForScopes:(NSSet *)scopes refreshExpiredToken:(BOOL)refresh
{
    BOOL valid = FALSE;

    OMAuthenticationContext *cachedContext = [self.mss.cacheDict
                                              valueForKey:self.mss.authKey];
    if (!cachedContext || cachedContext.isLogoutFalseCalled)
    {
        return false;
    }

    for(OMToken *token in self.tokens)
    {
        OMTokenStatus tokenStatus = [self isToken:token validForScopes:scopes];
        if(tokenStatus == eAlive)
        {
            valid = TRUE;
            break;
        }
        else if(tokenStatus == eUseRefreshToken)
        {
            if(refresh)
            {
                NSError *err = [self refreshAccessTokenRequest:token];
                if(err == nil)
                {
                    valid = TRUE;
                    [self.mss saveAuthContext:self];
                }
                break;
            }
        }
    }
    [self.tokens removeObjectsInArray:self.deletedToken];
    self.deletedToken = nil;
    return valid;
}

- (NSError *)refreshAccessTokenRequest:(OMToken *)token
{
    OMOAuthConfiguration *config =
    (OMOAuthConfiguration *)self.mss.configuration;

    NSMutableString *requestString = [NSMutableString stringWithFormat:
                                      @"grant_type=refresh_token&refresh_token=%@",
                                      token.refreshToken];

    NSDictionary *headerDict = [self backChannelRequestHeader:config];
    if(config.clientAssertion != nil)
    {
        NSString *clientAssertionString = [NSString stringWithFormat:
                                           @"&client_assertion_type=%@&client_assertion=%@",
                                           config.clientAssertionType,
                                           config.clientAssertion];
        [requestString appendString:clientAssertionString];
    }
    

    NSMutableURLRequest *request = [NSMutableURLRequest
                                    requestWithURL:config.tokenEndpoint];
    [request setHTTPMethod:@"POST"];
    [request setHTTPBody:[requestString
                          dataUsingEncoding:NSUTF8StringEncoding]];
    [request setAllHTTPHeaderFields:headerDict];
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration
                                                defaultSessionConfiguration];
    
    __block NSError *returnError = nil;
    __weak OMAuthenticationContext *weekSelf = self;
    
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    
    NSURLSession *session = [NSURLSession
                             sessionWithConfiguration:sessionConfig];
    [[session dataTaskWithRequest:request
                completionHandler:^(NSData * _Nullable data,
                NSURLResponse * _Nullable response, NSError * _Nullable error)
    {

        if(error != nil)
        {
            returnError = error;
        }
        else
        {
            NSDictionary *returnResponse = [NSJSONSerialization
                                            JSONObjectWithData:data
                                            options:0
                                            error:&returnError];
            
            returnError = [OMOAuthAuthenticationService
                           oauthErrorFromResponse:returnResponse
                           andStatusCode:[(NSHTTPURLResponse*)response statusCode]];

            if (!returnError && returnResponse)
            {
                token.tokenValue = [returnResponse valueForKey:@"access_token"];
                token.tokenIssueDate = [NSDate date];
                token.expiryTimeInSeconds = [[returnResponse
                                              valueForKey:@"expires_in"] intValue];
                NSString *rToken = [returnResponse valueForKey:@"refresh_token"];
                if(rToken != nil)
                    token.refreshToken = rToken;
                /*A successful refresh should change authenticated mode to REMOTE*/
                weekSelf.authMode = OMRemote;
            }
        }

        dispatch_semaphore_signal(semaphore);
    }] resume];
    
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    
    return returnError;
}

- (NSDictionary *)backChannelRequestHeader: (OMOAuthConfiguration *)config
{
    if(config.clientAssertion != nil)
    {
        return nil;
    }
    NSString *clientID = config.clientId;
    NSString *clientSecret = config.clientSecret;
    NSMutableDictionary *headerDict = [[NSMutableDictionary alloc] init];
    NSString *passwordString = nil;
    if([clientSecret length] > 0)
    {
        passwordString = [NSString stringWithFormat:@"%@:%@",clientID,
                          clientSecret];
    }
    else
    {
        passwordString = [NSString stringWithFormat:@"%@:",clientID];
    }
    NSData *passwordData = [passwordString
                            dataUsingEncoding:NSUTF8StringEncoding];
    NSString *passwordBase64 = [passwordData base64EncodedString];
    NSString *headerValue = [NSString stringWithFormat:@"Basic %@",
                             passwordBase64];
    [headerDict setObject:headerValue forKey:OM_AUTHORIZATION];
    return headerDict;
}

- (OMTokenStatus)isToken:(OMToken *)token validForScopes:(NSSet *)scopes
{
    OMTokenStatus  tokenStatus =  eExpired;
    NSDate *currentDate = [NSDate date];
    NSSet *cmpScopes = token.tokenScopes;
    NSTimeInterval interval = [currentDate
                               timeIntervalSinceDate:token.tokenIssueDate];

    if([scopes isSubsetOfSet:cmpScopes] || (scopes == nil && cmpScopes == nil))
    {
        if(interval < token.expiryTimeInSeconds)
        {
            tokenStatus =  eAlive;
        }
        else
        {
            if(token.refreshToken)
            {
                tokenStatus =  eUseRefreshToken;

            }
            else
            {
                if(!self.deletedToken)
                    _deletedToken = [[NSMutableArray alloc] init];
                [self.deletedToken addObject:token];
                tokenStatus =  eExpired;
            }
        }
    }
    return tokenStatus;
}

- (NSArray *)tokensForScopes:(NSSet *)scopes
{
    if(([scopes count] == 1) && [scopes containsObject:@"*"])
        return self.tokens;
    NSMutableArray *tArray = [[NSMutableArray alloc] init];
    for(OMToken *token in self.tokens)
    {
        if([self isToken:token validForScopes:scopes] == 0)
        {
            [tArray addObject:token];
        }
    }
    return tArray;
}

-(NSString *)description
{
    NSString *authMode = self.authMode == 1?@"Local":@"Remote";
    NSString *logoutmode = (self.isLogoutFalseCalled == YES)?@"YES":@"NO";

    return [NSString stringWithFormat:@"Username : %@\nAuth mode : %@ logoutmode: %@",self.userName,authMode,logoutmode];
}

- (BOOL)isWkWebViewEnabled
{
    BOOL isWKWebView = NO;
    
    if ([self.mss.configuration isKindOfClass:[OMFedAuthConfiguration class]] && [(OMFedAuthConfiguration*)self.mss.configuration enableWKWebView])
    {
        isWKWebView = YES;
    }
    
    return isWKWebView;
}

- (void)clearWebViewCookies:(BOOL)clearPersistentCookies
{
    NSMutableSet *visitedURLs = [self.mss.cacheDict
                                 valueForKey:OM_VISITED_HOST_URLS];
    
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    for (NSURL *url in visitedURLs)
    {
        NSArray *cookies = [cookieStore cookiesForURL:url];
        for (NSHTTPCookie *cookie in cookies)
        {
            
            if (clearPersistentCookies) {
                [cookieStore deleteCookie:cookie];
                [OMWKWebViewCookieHandler deleteCookieFromWKHTTPStore:cookie];
            }
            else if ([cookie isSessionOnly]){
                [cookieStore deleteCookie:cookie];
                [OMWKWebViewCookieHandler deleteCookieFromWKHTTPStore:cookie];
                
            }
        }
    }
    
}

@end
