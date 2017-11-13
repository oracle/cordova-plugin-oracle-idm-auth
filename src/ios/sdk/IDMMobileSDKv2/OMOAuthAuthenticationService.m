/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAuthAuthenticationService.h"
#import "OMAuthorizationGrant.h"
#import <UIKit/UIKit.h>
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMOAuthConfiguration.h"
#import "OMResourceOwnerGrant.h"
#import "OMAuthorizationCodeGrant.h"
#import "OMImplicitGrant.h"
#import "OMClientCredentialGrant.h"
#import "OMAssertionGrant.h"
#import "OMAuthenticationContext.h"
#import "OMToken.h"
#import "OMCredential.h"
#import "OMCredentialStore.h"
#import "OMErrorCodes.h"
#import "OMURLProtocol.h"
#import "OMAuthenticationContext.h"

@implementation OMOAuthAuthenticationService

- (id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
             authenticationRequest:(OMAuthenticationRequest *)authReq
                          delegate:(id<OMAuthenticationDelegate>)delegate
{
    self = [super initWithMobileSecurityService:mss authenticationRequest:authReq delegate:delegate];
    if (self)
    {
        self.request = authReq;
        self.config = (OMOAuthConfiguration *)self.mss.configuration;
        self.retryCount = 0;
        OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.mss.configuration;
        if (config.grantType == OMOAuthResourceOwner)
        {
            self.grantFlow = [[OMResourceOwnerGrant alloc] init];
        }
        else if (config.grantType == OMOAuthAuthorizationCode)
        {
            self.grantFlow = [[OMAuthorizationCodeGrant alloc] init];
        }
        else if (config.grantType == OMAOAuthClientCredential)
        {
            self.grantFlow = [[OMClientCredentialGrant alloc] init];
        }
        else if (config.grantType == OMOAuthImplicit)
        {
            self.grantFlow = [[OMImplicitGrant alloc] init];
        }
        else if (config.grantType == OMOAuthAssertion)
        {
            self.grantFlow = [[OMAssertionGrant alloc] init];
        }
        
        self.grantFlow.oauthService = self;
    }
    return self;
}

- (void)setGrantFlowManually
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.mss.configuration;
    if (config.grantType == OMOAuthResourceOwner)
    {
        self.grantFlow = [[OMResourceOwnerGrant alloc] init];
    }
    else if (config.grantType == OMOAuthAuthorizationCode)
    {
        self.grantFlow = [[OMAuthorizationCodeGrant alloc] init];
    }
    else if (config.grantType == OMAOAuthClientCredential)
    {
        self.grantFlow = [[OMClientCredentialGrant alloc] init];
    }
    else if (config.grantType == OMOAuthImplicit)
    {
        self.grantFlow = [[OMImplicitGrant alloc] init];
    }
    else if (config.grantType == OMOAuthAssertion)
    {
        self.grantFlow = [[OMAssertionGrant alloc] init];
    }
    
    self.grantFlow.oauthService = self;
}

- (void)openURLInBrowser:(NSURL *)url
{
    [[UIApplication sharedApplication] openURL:url];
}

- (void)processOAuthResponse: (NSDictionary *)urlQueryDict
{
    [self.grantFlow processOAuthResponse:urlQueryDict];
}

- (void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError *__autoreleasing *)error
{
    self.callerThread = [NSThread currentThread];
    self.authData = authData;
    [self performSelectorInBackground:
     @selector(performAuthenticationInBackground:)
                           withObject:authData];
}

-(void)performAuthenticationInBackground:(NSMutableDictionary *)authData
{
    [NSURLProtocol registerClass:[OMURLProtocol class]];
    [OMURLProtocol setOMAObject:self];
    if (self.config.offlineAuthAllowed &&
        [self.grantFlow doOfflineAuthentication:self.config.tokenEndpoint])
    {
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:self.error
                waitUntilDone:true];
        return;
    }
    NSURL *frontChannelURL = [self.grantFlow frontChannelRequestURL];
    if (frontChannelURL && !self.frontChannelRequestDone)
    {
        [self.authData setObject:frontChannelURL forKey:@"frontChannelURL"];
        [self.grantFlow performSelector:@selector(sendFrontChannelChallenge)
                               onThread:self.callerThread
                             withObject:nil
                          waitUntilDone:false];
        return;
    }
    NSDictionary *backChannelRequest = [self.grantFlow
                                        backChannelRequest:authData];
    if (backChannelRequest)
    {
        [self performBackChannelRequest:backChannelRequest];
    }
}

- (void)performBackChannelRequest:(NSDictionary *)data
{
    self.retryCount++;
    NSString *tokenEndpoint = [data valueForKey:OM_OAUTH_BACK_CHANNEL_REQUEST_URL];
    NSString *requestString = [data valueForKey:OM_OAUTH_BACK_CHANNEL_PAYLOAD];
    NSDictionary *headerDict = [data valueForKey:OM_OAUTH_BACK_CHANNEL_HEADERS];
    
    NSString *requestType = [data
                             valueForKey:OM_OAUTH_BACK_CHANNEL_REQUEST_TYPE];
    
    NSMutableURLRequest *urlRequest = [NSMutableURLRequest
                                       requestWithURL:
                                       [NSURL URLWithString:tokenEndpoint]];
    
    if (!self.config.isClientRegistrationRequired)
    {
        [urlRequest setAllHTTPHeaderFields:headerDict];
    }
    
    [urlRequest setHTTPBody:[requestString
                             dataUsingEncoding:NSUTF8StringEncoding]];
    [urlRequest setHTTPMethod:requestType];
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration
                                                defaultSessionConfiguration];
    
    sessionConfig.protocolClasses = @[[OMURLProtocol class]];
    [OMURLProtocol setOMAObject:self];

    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig
                                                 delegate:nil
                                            delegateQueue:nil];
    [[session dataTaskWithRequest:urlRequest
               completionHandler:^(NSData * _Nullable data,
                                   NSURLResponse * _Nullable response,
                                   NSError * _Nullable error)
     {
         NSMutableDictionary *dict = [NSMutableDictionary dictionary];
         response?[dict setObject:response forKey:@"URLResponse"]:nil;
         data?[dict setObject:data forKey:@"Data"]:nil;
         error?[dict setObject:error forKey:@"Error"]:nil;
         [self sendBackChannelResponse:dict];
         if (self.error.code == OMERR_INVALID_USERNAME_PASSWORD)
         {
             if (self.retryCount >= self.config.authenticationRetryCount)
             {
                 self.error = [OMObject
                               createErrorWithCode:OMERR_MAX_RETRIES_REACHED];
                 [self performSelector:@selector(sendFinishAuthentication:)
                              onThread:self.callerThread
                            withObject:self.error
                         waitUntilDone:false];
             }
             else
             {
                 NSError *error = [OMObject createErrorWithCode:
                                   OMERR_INVALID_USERNAME_PASSWORD];
                 [self.authData setObject:error
                                   forKey:OM_MOBILESECURITY_EXCEPTION];
                 [self.authData setObject:[NSNumber numberWithInteger:
                                           self.retryCount]
                                   forKey:OM_RETRY_COUNT];
                 [self performSelector:@selector(performAuthentication:error:)
                              onThread:self.callerThread
                            withObject:self.authData
                         waitUntilDone:false];
             }
         }
         else
         {
             [self performSelector:@selector(sendFinishAuthentication:)
                          onThread:self.callerThread
                        withObject:self.error
                     waitUntilDone:false];
         }
    }]resume];
    
}

- (void)setAuthContext
{
    OMAuthenticationContext *context = [[OMAuthenticationContext alloc]
                                        initWithMss:self.mss];
    context.userName = self.userName;
    OMToken *token = [[OMToken alloc] init];
    token.tokenName = OM_OAUTH_ACCESS_TOKEN;
    token.tokenValue = self.accessToken;
    token.tokenIssueDate = [NSDate date];
    token.expiryTimeInSeconds = (int)self.expiryTimeInSeconds;
    token.sessionExpiryDate = [NSDate
                               dateWithTimeIntervalSinceNow:self.expiryTimeInSeconds];
    token.tokenScopes = self.config.scope;
    token.refreshToken = self.refreshToken;
    [context.tokens addObject:token];
    context.authMode = OMRemote;
    
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.mss.
    configuration;

    if (config.offlineAuthAllowed &&
        [self.grantFlow isKindOfClass:[OMResourceOwnerGrant class]])
    {
        [self storeOfflineCredential:context];
    }
    
    [self.mss.cacheDict setObject:context forKey:self.mss.authKey];
    self.context = context;
}

- (void)storeOfflineCredential:(OMAuthenticationContext *)ctx
{
    NSString *protectedPassword =
    [self protectPassword:self.password
             cryptoScheme:OM_CRYPTO_SCHEME_SHA512
                 outError:nil];
    OMCredential *credential = [[OMCredential alloc]
                                initWithUserName:self.userName
                                password:protectedPassword
                                tenantName:nil
                                properties:nil];
    [[OMCredentialStore sharedCredentialStore]
     saveCredential:credential
     forKey:[self.mss offlineAuthKey]];
}

- (void)sendFinishAuthentication: (id)object
{
    if (object)
    {
        self.context = nil;
    }
    [self.context setIsLogoutFalseCalled:NO];
    [self.delegate didFinishCurrentStep:self
                               nextStep:self.nextStep
                           authResponse:nil
                                  error:object];
    [NSURLProtocol unregisterClass:[OMURLProtocol class]];

}

- (void)sendBackChannelResponse:(NSDictionary *)data
{
    NSURLResponse *urlResponse = [data valueForKey:@"URLResponse"];
    id urlData = [data valueForKey:@"Data"];
    NSError *error = [data valueForKey:@"Error"];
    [self.grantFlow OAuthBackChannelResponse:urlResponse
                                        data:urlData
                                    andError:error];
}

+ (NSError *)oauthErrorFromResponse:(NSDictionary *)response
                      andStatusCode:(NSInteger)code
{
    NSError *error = nil;
    if(code >= 400 && code < 500)
    {
        NSString *responseError = [response objectForKey:@"error"];
        if(responseError != nil)
        {
            if ([responseError isEqual:@"invalid_client"])
            {
                error = [OMObject
                         createErrorWithCode:OMERR_OAUTH_INVALID_CLIENT];
            }
            else if ([responseError isEqual:@"invalid_scope"])
            {
                error = [OMObject
                         createErrorWithCode:OMERR_OAUTH_INVALID_SCOPE];
            }
            else if ([responseError isEqual:@"invalid_grant"])
            {
                NSString *description = [response
                                         valueForKey:@"error_description"];
                if ([description containsString:@"password"])
                {
                    error = [OMObject
                             createErrorWithCode:
                             OMERR_INVALID_USERNAME_PASSWORD];
                }
                else
                {
                    error = [OMObject
                             createErrorWithCode:OMERR_OAUTH_INVALID_GRANT];
                }
            }
            else
            {
                error = [self setErrorObject:response withErrorCode:code];
            }
        }
        else
            error = [OMObject createErrorWithCode:OMERR_OAUTH_BAD_REQUEST];
    }
    else if(code >= 500 && code < 600)
    {
        if([response objectForKey:@"error"] != nil)
        {
            error = [self setErrorObject:response
                           withErrorCode:code];
        }
        else
            error = [OMObject createErrorWithCode:OMERR_OAUTH_SERVER_ERROR];
    }
    else
    {
        if([response objectForKey:@"error"] != nil)
        {
            error = [self setErrorObject:response withErrorCode:code];
        }
    }
    return error;
}

- (NSDictionary *)parseFrontChannelResponse:(NSURL *)url
{
    self.frontChannelRequestDone = true;
    NSString *queryString = url.query;
    if (!queryString)
    {
        queryString = [url fragment];
    }
    NSMutableDictionary *urlQueryDict = [NSMutableDictionary dictionary];
    
    if (queryString != nil)
    {
        if ([NSURLQueryItem class] && ![self.grantFlow
                                        isKindOfClass:[OMImplicitGrant class]])
        {
                // If NSURLQueryItem is available, use it for deconstructing the new URL. (iOS 8+)
            NSURLComponents *components =
            [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            NSArray<NSURLQueryItem *> *queryItems = components.queryItems;
            
            for (NSURLQueryItem *queryItem in queryItems)
            {
                [urlQueryDict setObject:queryItem.value
                                 forKey:queryItem.name];
            }
        }
        else
        {
            NSArray *params = [queryString componentsSeparatedByString:@"&"];
            for (NSString *param in params)
            {
                NSArray *arr = [param componentsSeparatedByString:@"="];
                if ([arr count] != 2)
                {
                    self.error = [OMObject
                                  createErrorWithCode:OMERR_INVALID_APP_RESPONSE];
                }
                else
                {
                    [urlQueryDict setObject:[arr objectAtIndex:1]
                                     forKey:[arr objectAtIndex:0]];
                }
            }
        }
    }
    else
    {
        self.error = [OMObject createErrorWithCode:OMERR_INVALID_APP_RESPONSE];
    }
    return urlQueryDict.count?urlQueryDict:nil;
}

@end
