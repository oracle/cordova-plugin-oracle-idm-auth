/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMIDCSClientRegistrationService.h"
#import "OMOAuthConfiguration.h"
#import "OMAuthorizationGrant.h"
#import "OMIDCSClientRegistrationGrant.h"
#import "OMURLProtocol.h"
#import "OMIDCSClientRegistrationToken.h"
#import "OMCredential.h"
#import "OMCredentialStore.h"
#import "OMOIDCConfiguration.h"
#import "OMErrorCodes.h"

@implementation OMIDCSClientRegistrationService

- (id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
              authenticationRequest:(OMAuthenticationRequest *)authReq
                           delegate:(id<OMAuthenticationDelegate>)delegate
{
    self = [super initWithMobileSecurityService:mss authenticationRequest:authReq
                                       delegate:delegate];
    if (self)
    {
        self.grantFlow = [[OMIDCSClientRegistrationGrant alloc] init];
        self.grantFlow.oauthService = self;
    }
    return self;
}

-(void)performAuthenticationInBackground:(NSMutableDictionary *)authData
{
    [NSURLProtocol registerClass:[OMURLProtocol class]];
    [OMURLProtocol setOMAObject:self];
    
    if ([self isClientRegistred])
    {
        [self prepareForNextAuthentication:[self clientRegistrationToken]];
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:self.error
                waitUntilDone:true];
    }
    else
    {
        NSURL *frontChannelURL = [self.grantFlow frontChannelRequestURL];
        if (frontChannelURL && !self.frontChannelRequestDone)
        {
            [self.authData setObject:frontChannelURL forKey:@"frontChannelURL"];
            [self.grantFlow performSelector:@selector(sendFrontChannelChallenge)
                                   onThread:self.callerThread
                                 withObject:nil
                              waitUntilDone:false];
        }
        else if (self.frontChannelRequestDone && !self.backChannelRequestDone)
        {
            NSDictionary *backChannelRequest = [self.grantFlow
                                                backChannelRequest:authData];
            if (backChannelRequest)
            {
                [self performBackChannelRequest:backChannelRequest];
            }
        }
        else if (self.backChannelRequestDone)
        {
            [self performDeviceRegistration];
        }

    }
    
}

- (BOOL)isClientRegistred
{
    BOOL registred = NO;
    
       OMIDCSClientRegistrationToken *token =  [self clientRegistrationToken];
    
        if ([[token clientID] length] && [token isTokenValid])
        {
            registred = YES;
        }

    return registred;
}

- (OMIDCSClientRegistrationToken*)clientRegistrationToken
{
    OMIDCSClientRegistrationToken *token = nil;
    
    OMCredential *cred = [[OMCredentialStore sharedCredentialStore]
                          getCredential:[self clientRegistrationKey]];
    
    if (cred.properties)
    {
        token = [[OMIDCSClientRegistrationToken alloc]
                initWithInfo:cred.properties];
    }
    
    return token;
    
}

- (void)performDeviceRegistration
{
    
    NSMutableURLRequest *urlRequest = [NSMutableURLRequest
                                       requestWithURL:self.config.clientRegistrationEndpoint];
    [urlRequest setAllHTTPHeaderFields:[(OMIDCSClientRegistrationGrant*)self.grantFlow registrationHeader]];
    [urlRequest setHTTPBody:[(OMIDCSClientRegistrationGrant*)self.grantFlow registrationBody]];
    [urlRequest setHTTPMethod:@"POST"];
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
          
          if (!error)
          {
              NSError *jsonError = nil;
              
              NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
              NSInteger statusCode = [httpResponse statusCode];
              
              NSDictionary *responceJson = [NSJSONSerialization
                                            JSONObjectWithData:data
                                            options:0
                                            error:&jsonError];

              if (!jsonError)
              {
                  self.error = [OMOAuthAuthenticationService
                                oauthErrorFromResponse:responceJson
                                andStatusCode:statusCode];
                
                  if (!self.error)
                  {
                      [self handleRegistrationResponse:responceJson];
                  }
              }
              else
              {
                  self.error = [OMObject createErrorWithCode:
                                OMERR_IDCS_CLIENT_REGISTRATION_PARSING_FAILED];
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

- (void)sendFinishAuthentication: (id)object
{
    if (object)
    {
        self.context = nil;
    }
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
    if (!error)
    {
        self.backChannelRequestDone = YES;
        self.nextStep = OM_NEXT_AUTH_STEP_DEVICE_REGISTRATION;
    }
    else
    {
        self.error = [OMObject createErrorWithCode:
                      OMERR_IDCS_CLIENT_REGISTRATION_UNABLE_TO_OBTAIN_AT];
        self.nextStep = OM_NEXT_AUTH_STEP_NONE;

    }
}

- (void)handleRegistrationResponse:(NSDictionary*)responceJson
{
    

        OMIDCSClientRegistrationToken *token = [[OMIDCSClientRegistrationToken alloc]
                                                initWithInfo:responceJson];
        
        if ([[token clientID] length] > 0)
        {
            [self saveToken:token forKey:[self clientRegistrationKey]];
            [self prepareForNextAuthentication:token];

        }
        else
        {
            self.error = [OMObject createErrorWithCode:
                          OMERR_IDCS_CLIENT_REGISTRATION_PARSING_FAILED];
        }
    
    [self performSelector:@selector(sendFinishAuthentication:)
                 onThread:self.callerThread
               withObject:self.error
            waitUntilDone:false];

}

- (void)prepareForNextAuthentication:(OMIDCSClientRegistrationToken*)token
{
    if([self.mss.configuration isMemberOfClass:[OMOAuthConfiguration class]])
    {
        self.nextStep = OM_NEXT_OAUTH_AUTHORIZATION;
    }
    else if([self.mss.configuration isMemberOfClass:[OMOIDCConfiguration class]])
    {
        self.nextStep = OM_NEXT_OPEN_ID_AUTHORIZATION;
    }
    
    OMOAuthConfiguration* config = self.mss.configuration;

    [config setClientId:token.clientID];
    [config setClientSecret:token.clientSecret];

}

- (BOOL)saveToken:(OMIDCSClientRegistrationToken*)token forKey:(NSString*)key
{
  OMCredential *tokenCred = [[OMCredential alloc] initWithUserName:nil
                                                  password:nil tenantName:nil
                                                properties:[token jsonInfo]];
    
    NSError *error = [[OMCredentialStore sharedCredentialStore]
                      saveCredential:tokenCred
                     forKey:key];
    
    return (!error) ? YES : NO;
}

- (NSString*)clientRegistrationKey
{
    OMOAuthConfiguration* config = self.mss.configuration;
    
   NSString *regKey = [NSString stringWithFormat:@"%@_%@",config.authEndpoint,
                       config.loginHint];
    
    return regKey;
}

@end
