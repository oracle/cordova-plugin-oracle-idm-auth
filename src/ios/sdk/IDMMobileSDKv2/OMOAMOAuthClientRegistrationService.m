/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAMOAuthClientRegistrationService.h"
#import "NSData+OMBase64.h"
#import "OMOAuthAuthenticationService.h"

@implementation OMOAMOAuthClientRegistrationService
-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
             authenticationRequest:(OMAuthenticationRequest *)authReq
                          delegate:(id<OMAuthenticationDelegate>)delegate
{
    self = [super initWithMobileSecurityService:mss
                          authenticationRequest:authReq
                                       delegate:delegate];
    if (self)
    {
        _config = (OMOAMOAuthConfiguration *)mss.configuration;
    }
    return self;
}

-(void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError *__autoreleasing *)error
{
    [self retrieveRememberCredentials:self.authData];
    self.callerThread = [NSThread currentThread];
    [self performSelectorInBackground:@selector(preAuthzCode) withObject:nil];
}

-(void)preAuthzCode
{
    NSMutableURLRequest *request = [[NSMutableURLRequest alloc]
                                    initWithURL:self.config.tokenEndpoint];
    [request setHTTPBody:[[self preAuthzCodePayload] dataUsingEncoding:NSUTF8StringEncoding]];
    //[request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPMethod:@"POST"];
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
          
          if (data)
          {
              authResponse = [NSJSONSerialization JSONObjectWithData:data
                                                             options:0
                                                               error:&error];
          }
          
          if (error)
          {
              self.error = error;
          }
          
          else if (((NSHTTPURLResponse *)response).statusCode != 200)
          {
              self.error = [OMOAuthAuthenticationService
                            oauthErrorFromResponse:authResponse
                            andStatusCode:((NSHTTPURLResponse *)response).
                            statusCode];
          }
          if (self.error == nil)
          {
              self.config.preAuthzCode = [self tokenFromResponse:authResponse];
          }
          [self performSelector:@selector(sendFinishAuthentication:)
                       onThread:self.callerThread
                     withObject:nil
                  waitUntilDone:false];
          
      }] resume];
    
}

-(NSString *)preAuthzCodePayload
{
    [self setDeviceProfile];
    NSString *payload = [NSString
                         stringWithFormat:@"grant_type=client_credentials&oracle_device_profile=%@&client_id=%@&oracle_requested_assertions=oracle-idm:/oauth/assertion-type/client-identity/mobile-client-pre-authz-code-client",
                         self.config.deviceProfile,self.config.clientId];
    return payload;
}

-(void)setDeviceProfile
{
    NSDictionary *deviceProfile = [self.config getIdentityClaims];
    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:deviceProfile
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    
    if (! jsonData) {
        self.error = error;
    } else {
        self.config.deviceProfile = [jsonData base64EncodedString];
    }
    
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

- (void)sendFinishAuthentication:(id)object
{
    [self.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_OAUTH_CLIENT_ASSERTION
                           authResponse:self.authResponse
                                  error:(NSError *)object];
    
}

@end
