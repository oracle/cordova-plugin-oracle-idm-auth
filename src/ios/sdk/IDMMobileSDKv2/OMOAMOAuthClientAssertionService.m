/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAMOAuthClientAssertionService.h"
#import "OMOAuthAuthenticationService.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"

@interface OMOAMOAuthClientAssertionService()<NSURLSessionDelegate>
@property (nonatomic, weak) NSThread *callerThread;
@property (nonatomic, strong) NSError *error;
@property (atomic) NSUInteger nextStep;
@end

@implementation OMOAMOAuthClientAssertionService
-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
             authenticationRequest:(OMAuthenticationRequest *)authReq
                          delegate:(id<OMAuthenticationDelegate>)delegate
{
    self = [super initWithMobileSecurityService:mss
                          authenticationRequest:authReq
                                       delegate:delegate];
    if (self)
    {
        self.config = (OMOAMOAuthConfiguration *)self.mss.configuration;
    }
    return self;
}

-(void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError *__autoreleasing *)error
{
    self.requestPauseSemaphore = dispatch_semaphore_create(0);
    self.authData = authData;
    self.callerThread = [NSThread currentThread];
    [self performSelectorInBackground:@selector(clientAssertion)
                           withObject:nil];
}

-(void)clientAssertion
{
    [self retrieveRememberCredentials:self.authData];
    NSString *username = [self.authData valueForKey:OM_USERNAME];
    NSString *password = [self.authData valueForKey:OM_PASSWORD];
    NSString *refreshToken = [self.authData valueForKey:
                              OM_OAUTH_CLIENT_ASSERTION_REFRESH_TOKEN];
    NSString *payload = nil;
    if (refreshToken.length)
    {
        payload = [self refreshPayloadWithToken:refreshToken];
    }
    else
    {
        if (![username length])
        {
            [self.authData setValue:[NSNull null] forKey:OM_USERNAME];
        }
        
        if (![password length])
        {
            [self.authData setValue:[NSNull null] forKey:OM_PASSWORD];
        }
        [self performSelector:@selector(sendChallenge:)
                     onThread:self.callerThread
                   withObject:nil
                waitUntilDone:false];
      
        dispatch_semaphore_wait(self.requestPauseSemaphore,
                                DISPATCH_TIME_FOREVER);
        
        username = [self.authData valueForKey:OM_USERNAME];
        password = [self.authData valueForKey:OM_PASSWORD];
        payload = [self twoLeggedPayload:username andPassword:password];
    }
    NSMutableURLRequest *request = [NSMutableURLRequest
                                    requestWithURL:self.config.tokenEndpoint];
    [request setHTTPMethod:@"POST"];
    NSData *payloadData = [payload dataUsingEncoding:NSUTF8StringEncoding];
    [request setHTTPBody:payloadData];
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration
                                                defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig
                                                          delegate:self
                                                     delegateQueue:nil];
    [[session dataTaskWithRequest:request
                completionHandler:^(NSData * _Nullable data,
                                    NSURLResponse * _Nullable response,
                                    NSError * _Nullable error)
      {
          if (error)
          {
              self.error = error;
          }
          else
          {
              
              self.authResponse = [NSJSONSerialization
                                   JSONObjectWithData:data
                                   options:0
                                   error:nil];
              self.error = [OMOAuthAuthenticationService
                            oauthErrorFromResponse:self.authResponse
                            andStatusCode:((NSHTTPURLResponse *)response).
                            statusCode];
          }
          if (self.error == nil)
          {
              NSDictionary *userAssertionResponse = [[self.authResponse
                                                      valueForKey:@"oracle_aux_tokens"]
                                                     valueForKey:@"user_assertion"];
              if(userAssertionResponse)
              {
                  OMToken *userToken = [self
                                        tokenFromResponse:userAssertionResponse];
                  self.config.userAssertion = userToken.tokenValue;
                  self.config.userAssertionType = userToken.tokenType;
                  self.config.userAssertionToken = userToken;
              }
              OMToken *clientToken = [self tokenFromResponse:self.authResponse];
              clientToken.tokenType = [self.authResponse
                                       valueForKey:
                                       @"oracle_client_assertion_type"];
              self.config.clientAssertion = clientToken.tokenValue;
              self.config.clientAssertionType = clientToken.tokenType;
              [self.mss.cacheDict setObject:clientToken
                                     forKey:[self clientTokenKey]];
              if(refreshToken != nil)
                  self.nextStep = OM_NEXT_OAUTH_USER_ASSERTION;
              else
                  self.nextStep = OM_NEXT_OAUTH_AUTHORIZATION;
          }
          [self performSelector:@selector(sendFinishAuthentication:)
                       onThread:self.callerThread
                     withObject:self.error
                  waitUntilDone:false];
          
      }] resume];
}

- (NSString *)refreshPayloadWithToken:(NSString *)refreshToken
{
    NSMutableString *payload = [[NSMutableString alloc] init];
    NSString *grant = @"grant_type=refresh_token";
    NSString *clientID = [NSString stringWithFormat:@"&client_id=%@",
                          self.config.clientId];
    NSString *rToken = [NSString stringWithFormat:@"&refresh_token=%@",
                        refreshToken];
    NSString *dProfile = [NSString stringWithFormat:@"&oracle_device_profile=%@"
                          ,self.config.deviceProfile];
    [payload appendString:grant];
    [payload appendString:clientID];
    [payload appendString:rToken];
    [payload appendString:dProfile];
    return payload;
}

- (NSString *)twoLeggedPayload:(NSString *)username andPassword:(NSString *)pwd
{
    NSMutableString *payload = [[NSMutableString alloc] init];
    NSString *grant = @"grant_type=password";
    NSString *cred = [NSString stringWithFormat:@"&username=%@&password=%@",
                      username,pwd];
    NSString *clientID = [NSString stringWithFormat:@"&client_id=%@",
                          self.config.clientId];
    NSString *preAuthz = [NSString stringWithFormat:@"&oracle_pre_authz_code=%@"
                          ,self.config.preAuthzCode.tokenValue];
    NSString *dProfile = [NSString stringWithFormat:@"&oracle_device_profile=%@"
                          ,self.config.deviceProfile];
    NSString *reqAst = @"&oracle_requested_assertions=urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    [payload appendString:grant];
    [payload appendString:cred];
    [payload appendString:clientID];
    [payload appendString:preAuthz];
    [payload appendString:dProfile];
    [payload appendString:reqAst];
    return payload;
}

- (OMToken *)tokenFromResponse:(NSDictionary *)response
{
    OMToken *token = [[OMToken alloc] init];
    token.tokenName = [response valueForKey:@"oracle_tk_context"];
    token.tokenValue = [response valueForKey:@"access_token"];
    token.tokenIssueDate = [NSDate date];
    token.expiryTimeInSeconds = [[response valueForKey:@"expires_in"] intValue];
    token.refreshToken = [response valueForKey:@"refresh_token"];
    return token;
    
}
- (NSString *)clientTokenKey
{
    return [NSString stringWithFormat:@"%@_%@_clientToken",
            self.config.oauthServiceEndpoint,self.config.clientId];
}
- (void)sendFinishAuthentication:(id)object
{
    NSString *clientRegistrationFlow =
    self.config.clientRegistrationType;
    [self.delegate didFinishCurrentStep:self
                               nextStep:self.nextStep
                           authResponse:self.authResponse
                                  error:(NSError *)object];
    
}

-(void)sendChallenge:(id)object
{
    self.challenge = [[OMAuthenticationChallenge alloc] init];
    NSMutableDictionary *challengeDict = [NSMutableDictionary
                                          dictionaryWithDictionary:self.authData];
    [challengeDict removeObjectForKey:OM_AUTH_SUCCESS];
    self.challenge.authData = challengeDict;
    self.challenge.challengeType = OMChallengeUsernamePassword;
    __block __weak OMOAMOAuthClientAssertionService *weakSelf = self;
    __block dispatch_semaphore_t blockSemaphore = self.requestPauseSemaphore;

    self.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                            OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            [weakSelf.authData addEntriesFromDictionary:dict];
            id username = [weakSelf.authData valueForKey:OM_USERNAME];
            id password = [weakSelf.authData valueForKey:OM_PASSWORD];
            
            if(![weakSelf.config isValidString:username] ||
               ![weakSelf.config isValidString:password])
            {
                [weakSelf.authData setValue:[NSNull null] forKey:OM_USERNAME];
                [weakSelf.authData setValue:[NSNull null] forKey:OM_PASSWORD];
                NSError *error = [OMObject createErrorWithCode:
                                  OMERR_INVALID_USERNAME_PASSWORD];
                [weakSelf.authData setObject:error
                                      forKey:OM_MOBILESECURITY_EXCEPTION];
                
                [weakSelf sendChallenge:nil];
            }
            else
            {
                if([weakSelf.authData objectForKey:OM_ERROR])
                {
                    [weakSelf.authData removeObjectForKey:OM_ERROR];
                }
            }
            
            [weakSelf.authData setObject:password forKey:OM_PASSWORD];
            [weakSelf storeRememberCredentialsPreference:weakSelf.authData];
        }
        else
        {
            NSError *error = [OMObject createErrorWithCode:
                              OMERR_USER_CANCELED_AUTHENTICATION];
            
            [weakSelf performSelector:@selector(sendFinishAuthentication:)
                             onThread:weakSelf.callerThread
                           withObject:error
                        waitUntilDone:YES];
            
        }
        dispatch_semaphore_signal(blockSemaphore);
    };
    
    [self.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                           authResponse:nil
                                  error:nil];
}

@end
