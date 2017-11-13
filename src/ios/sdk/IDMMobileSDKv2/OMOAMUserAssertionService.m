/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAMUserAssertionService.h"
#import "OMOAMOAuthConfiguration.h"
#import "OMOAuthAuthenticationService.h"

@interface OMOAMUserAssertionService ()
@property (nonatomic, weak) OMOAMOAuthConfiguration *config;
@property (nonatomic, weak) NSThread *callerThread;
@property (nonatomic, strong) NSError *error;
@property (atomic) NSUInteger nextStep;
@end

@implementation OMOAMUserAssertionService
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
    if ([self isUserAssertionValid])
    {
        [self.delegate didFinishCurrentStep:self
                                   nextStep:OM_NEXT_OAUTH_AUTHORIZATION
                               authResponse:nil
                                      error:nil];
        return;
    }
    self.callerThread = [NSThread currentThread];
    [self performSelectorInBackground:@selector(userAssertion)
                           withObject:nil];
    
}

-(void)userAssertion
{
    NSString *username = [self.authData valueForKey:OM_USERNAME];
    NSString *password = [self.authData valueForKey:OM_PASSWORD];
    NSMutableURLRequest *request = [NSMutableURLRequest
                                    requestWithURL:self.config.tokenEndpoint];
    NSMutableString *payload = [NSMutableString stringWithFormat:
                                @"grant_type=password&username=%@&password=%@",
                                username,password];
    NSString *clientAssertionString = [NSString stringWithFormat:
                                       @"&client_assertion_type=%@&client_assertion=%@",
                                       self.config.clientAssertionType,
                                       self.config.clientAssertion];
    NSString *deviceProfile = [NSString
                               stringWithFormat:@"&oracle_device_profile=%@",
                               self.config.deviceProfile];
    NSString *requestedAssertion =
    @"&oracle_requested_assertions=oracle-idm:/oauth/assertion-type/user-identity/jwt";
    [payload appendString:clientAssertionString];
    [payload appendString:deviceProfile];
    [payload appendString:requestedAssertion];
    [request setHTTPBody:[payload dataUsingEncoding:NSUTF8StringEncoding]];
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
          NSDictionary *authResponse = nil;
          if (error)
          {
              self.error = error;
          }
          else if (((NSHTTPURLResponse *)response).statusCode != 200)
          {
              authResponse= [NSJSONSerialization JSONObjectWithData:data
                                                            options:0
                                                              error:&error];
              self.error = [OMOAuthAuthenticationService
                            oauthErrorFromResponse:authResponse
                            andStatusCode:((NSHTTPURLResponse *)response).
                            statusCode];
          }
          if (self.error == nil)
          {
              OMToken *userToken = [self tokenFromResponse:self.authResponse];
              self.config.userAssertionToken = userToken;
              self.config.userAssertion = userToken.tokenValue;
              self.config.userAssertionType = userToken.tokenType;
              self.nextStep = OM_NEXT_OAUTH_AUTHORIZATION;
          }
          [self performSelector:@selector(sendFinishAuthentication:)
                       onThread:self.callerThread
                     withObject:nil
                  waitUntilDone:false];
          
      }] resume];
    
}

-(BOOL)isUserAssertionValid

{
    OMToken *assertion = self.config.userAssertionToken;
    if(assertion == nil)
        return FALSE;
    if([assertion isTokenValid])
    {
        self.config.userAssertion = assertion.tokenValue;
        self.config.userAssertionType = assertion.tokenType;
        return TRUE;
    }
    return FALSE;
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


@end
