/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMClientCertLogoutService.h"
#import "OMClientCertConfiguration.h"

@implementation OMClientCertLogoutService

-(void)performLogout:(BOOL)clearRegistrationHandles
{
    self.callerThread = [NSThread currentThread];
    OMClientCertConfiguration *config = (OMClientCertConfiguration *)
    self.mss.configuration;
    NSURLSession *session = [NSURLSession sharedSession];
    [[session dataTaskWithURL:config.logoutURL
            completionHandler:^(NSData * _Nullable data,
                                NSURLResponse * _Nullable response,
                                NSError * _Nullable error)
      {
          long status = ((NSHTTPURLResponse *)response).statusCode;
          if (status == 401 || !error)
          {
              [self performSelector:@selector(sendFinishLogout:)
                           onThread:self.callerThread withObject:nil
                      waitUntilDone:false];
          }
          else
          {
              [self performSelector:@selector(sendFinishLogout:)
                           onThread:self.callerThread withObject:error
                      waitUntilDone:false];
          }
      }] resume];
}

-(void)sendFinishLogout:(NSError *)error
{
    self.mss.authManager.curentAuthService.context = nil;
    [self.mss.delegate mobileSecurityService:self.mss
                             didFinishLogout:error];
}

@end
