/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMHTTPBasicLogoutService.h"
#import "OMHTTPBasicConfiguration.h"
#import "OMAuthenticationContext.h"
#import "OMCredentialStore.h"
#import "OMAuthenticationManager.h"

@interface OMHTTPBasicLogoutService ()
@property (nonatomic, assign) BOOL clearPersistentCookies;
@end

@implementation OMHTTPBasicLogoutService

-(void)performLogout:(BOOL)clearRegistrationHandles
{
    self.callerThread = [NSThread currentThread];
    self.clearPersistentCookies = clearRegistrationHandles;
    OMHTTPBasicConfiguration *config = (OMHTTPBasicConfiguration *)
                                                self.mss.configuration;
    OMAuthenticationContext *context = [self.mss.cacheDict
                                        valueForKey:self.mss.authKey];

    NSURLSession *session = [NSURLSession sharedSession];
    NSMutableURLRequest *request = [NSMutableURLRequest
                                    requestWithURL:config.logoutURL];
    NSDictionary *logoutHeaders = [self.mss logoutHeaders:context];
    request.allHTTPHeaderFields = logoutHeaders;
    [[session dataTaskWithRequest:request completionHandler:
      ^(NSData * _Nullable data, NSURLResponse * _Nullable response,
        NSError * _Nullable error)
      {
        if (clearRegistrationHandles)
        {
            [self.mss.cacheDict removeObjectForKey:self.mss.authKey];
        }
        else
        {
            context.isLogoutFalseCalled = true;
        }
        [context clearCookies:clearRegistrationHandles];
        long status = ((NSHTTPURLResponse *)response).statusCode;
        if (status == 401 || !error)
        {
            [self performSelector:@selector(sendFinishLogout:)
                         onThread:self.callerThread
                       withObject:nil
                    waitUntilDone:false];
        }
        else
        {
            [self performSelector:@selector(sendFinishLogout:)
                         onThread:self.callerThread
                       withObject:error
                    waitUntilDone:false];
        }

    }] resume];
}

-(void)sendFinishLogout:(NSError *)error
{
    if (self.clearPersistentCookies)
    {
        self.mss.authManager.curentAuthService.context = nil;
    }
    if (self.mss.configuration.sessionActiveOnRestart)
    {
        [[OMCredentialStore sharedCredentialStore]
         deleteAuthenticationContext:self.mss.authKey];
    }

    [self.mss.delegate mobileSecurityService:self.mss
                             didFinishLogout:error];
}
@end
