/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMServiceDiscoveryHandler.h"
#import "OMObject.h"
#import "OMDefinitions.h"
#import "OMMobileSecurityService.h"
#import "OMClientCertChallangeHandler.h"
#import "OMAuthenticationManager.h"
#import "OMErrorCodes.h"

@interface OMServiceDiscoveryHandler ()

@property (nonatomic, strong) NSError *error;
@property (nonatomic, strong) NSThread *callerThread;
@property (nonatomic, weak) OMMobileSecurityService *mss;

@end

@implementation OMServiceDiscoveryHandler

+ (OMServiceDiscoveryHandler *)sharedHandler
{
    static OMServiceDiscoveryHandler *kSharedManger = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        kSharedManger = [[self alloc] init];
        
    });
    
    return kSharedManger;
}

- (void)discoverConfigurationWithURL:(NSURL * _Nonnull)discoveryURL
                             withMss:(OMMobileSecurityService*)mss
    completion:(OMServiceDiscoveryCallback _Null_unspecified)completion;
{
    self.callerThread = [NSThread currentThread];
    self.mss = mss;
    self.mss.authManager = [[OMAuthenticationManager alloc]
                        initWithMobileSecurityService:self.mss
                        authenticationRequest:nil];
    self.mss.authManager.curentAuthService = self;
    self.delegate = self.mss.authManager;
    
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration
                                                defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig
                                                          delegate:self delegateQueue:nil];
    [[session dataTaskWithURL:discoveryURL
            completionHandler:^(NSData *  data,
                                NSURLResponse *  response,
                                NSError * error)
      {
          if (error)
          {
              self.error = error;
          }
          else if (((NSHTTPURLResponse *)response).statusCode != 200)
          {
              self.error = [OMObject createErrorWithCode:
                            OMERR_OIC_SERVER_RETURNED_ERROR];
          }
          else
          {
              NSDictionary *appProfile = [NSJSONSerialization
                                          JSONObjectWithData:data
                                          options:0
                                          error:nil];
              completion(appProfile,self.error);
          }
          [self performSelector:@selector(sendSetupDone)
                       onThread:self.callerThread
                     withObject:self.error
                  waitUntilDone:false];
      }] resume];
    
}

-(void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    //we don't need to handle any other challenge type
    NSString *challengeType = challenge.protectionSpace.authenticationMethod;
    if ([challengeType isEqualToString:NSURLAuthenticationMethodServerTrust ])
    {
        self.authData = [NSMutableDictionary dictionary];
        self.delegate = self.mss.authManager;
        [[OMClientCertChallangeHandler sharedHandler]
         doServerTrustForAuthenticationChallenge:challenge
         challengeReciver:self completionHandler:completionHandler];
    }
    else if ([challengeType isEqualToString:NSURLAuthenticationMethodClientCertificate])
    {
        self.authData = [NSMutableDictionary dictionary];
        self.delegate = self.mss.authManager;
        
        [[OMClientCertChallangeHandler sharedHandler]
         doClientTrustForAuthenticationChallenge:challenge
         challengeReciver:self completionHandler:completionHandler];
    }
    else
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                          nil);
    }
    
}


-(void)sendSetupDone
{
    if ([self.mss.delegate respondsToSelector:@selector(mobileSecurityService:completedSetupWithConfiguration:error:)])
    {
        if (self.error)
        {
            [self.mss.delegate mobileSecurityService:self.mss
                     completedSetupWithConfiguration:nil
                                               error:self.error];
        }
        else
        {
            [self.mss.delegate mobileSecurityService:self.mss
                     completedSetupWithConfiguration:self
                                               error:nil];
        }
    }
}

@end
