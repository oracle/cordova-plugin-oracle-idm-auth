/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMClientCertAuthenticationService.h"
#import "OMDefinitions.h"
#import "OMClientCertConfiguration.h"
#import "OMObject.h"
#import "OMCertService.h"
#import "OMErrorCodes.h"
#import "OMURLProtocol.h"
#import "OMClientCertChallangeHandler.h"

@implementation OMClientCertAuthenticationService

-(BOOL)isInputRequired:(NSMutableDictionary *)authData
{
    return NO;
}
-(void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError *__autoreleasing *)error
{
    self.configuration = (OMClientCertConfiguration *)self.mss.configuration;
    self.callerThread = [NSThread currentThread];
    self.authData = authData;
    

        [self performSelectorInBackground:
         @selector(performAuthenticationInBackground:) withObject:authData];
}

-(void)performAuthenticationInBackground:(NSMutableDictionary *)authData
{

    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration
                                                defaultSessionConfiguration];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig
                                                 delegate:self
                                            delegateQueue:nil];
    
   self.sessionDataTask = [session dataTaskWithURL:self.configuration.loginURL
                 completionHandler:^(NSData * _Nullable data,
                                     NSURLResponse * _Nullable response,
                                     NSError * _Nullable error)
      {
          NSSet *requiredTokens = self.configuration.requiredTokens;
          NSError *authError = nil;
          if (error && self.maxRetryError)
          {
              return;
          }
          else if (error)
          {
              authError = error;
          }
          else if (![self isRequiredTokens:requiredTokens
                                presentFor:self.context.visitedHosts])
          {
              authError = [OMObject createErrorWithCode:
                           OMERR_USER_AUTHENTICATION_FAILED];
          }
          if (authError)
          {
              self.context = nil;
              [self.mss.cacheDict removeObjectForKey:self.mss.authKey];
          }
          else
          {
          }
          [self performSelector:@selector(sendFinishAuthentication:)
                       onThread:self.callerThread
                     withObject:authError
                  waitUntilDone:false];
      }];
    [self.sessionDataTask resume];
}

- (void)cancelAuthentication
{
    [self.sessionDataTask cancel];
}

-(void)sendFinishAuthentication:(id)object
{
    if (object)
    {
        self.context = nil;
    }
    else
    {
        [self resetMaxRetryCount];
    }
    
    [self.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_NONE
                           authResponse:nil
                                  error:object];

}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                             NSURLCredential *credential))completionHandler
{
    
    if (challenge.previousFailureCount > 0 &&
        challenge.previousFailureCount <
        self.configuration.authenticationRetryCount)
    {
        NSError *error = [OMObject createErrorWithCode:
                          OMERR_INVALID_CLIENT_CERTIFICATE];
        [self.authData setObject:error
                          forKey:OM_MOBILESECURITY_EXCEPTION];
        [self.authData setObject:[NSNumber numberWithInteger:
                                  challenge.previousFailureCount]
                          forKey:OM_RETRY_COUNT];
    }
    else if (challenge.previousFailureCount >=
             self.configuration.authenticationRetryCount)
    {
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:[OMObject createErrorWithCode:
                               OMERR_MAX_RETRIES_REACHED]
                waitUntilDone:false];
        [session invalidateAndCancel];
        self.maxRetryError = YES;
        [self resetMaxRetryCount];
        return;
    }
    NSString *challengeType = [[challenge protectionSpace]
                                 authenticationMethod];
    if ([challengeType isEqualToString:NSURLAuthenticationMethodClientCertificate ])
    {
        [[OMClientCertChallangeHandler sharedHandler]
         doClientTrustForAuthenticationChallenge:challenge
         challengeReciver:self completionHandler:completionHandler];
        
    }
    else if ([challengeType isEqualToString:NSURLAuthenticationMethodServerTrust ])
    {
        [[OMClientCertChallangeHandler sharedHandler]
         doServerTrustForAuthenticationChallenge:challenge
         challengeReciver:self completionHandler:completionHandler];
    }
    else
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                          nil);
    }
    
}

-(void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
       newRequest:(NSURLRequest *)request
completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler
{
    [self.context.visitedHosts addObject:request.URL];
    completionHandler(request);
}
@end
