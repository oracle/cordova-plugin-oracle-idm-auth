/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAuthLogoutService.h"
#import "OMOAuthConfiguration.h"
#import "OMAuthenticationContext.h"
#import <UIKit/UIKit.h>
#import "OMObject.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"
#import "OMWebViewClient.h"
#import "OMCredentialStore.h"

@interface OMOAuthLogoutService()<UIWebViewDelegate>
@property (nonatomic, strong) OMAuthenticationChallenge *challenge;
@property (nonatomic, strong) OMWebViewClient *webViewClient;
@property (nonatomic, assign) BOOL clearPersistentCookies;
@end

@implementation OMOAuthLogoutService
-(void)performLogout:(BOOL)clearRegistrationHandles
{
    self.callerThread = [NSThread currentThread];
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)
    self.mss.configuration;
    __block __weak OMOAuthLogoutService *weakself = self;
    self.clearPersistentCookies = clearRegistrationHandles;
    if (config.grantType == OMOAuthImplicit ||
        config.grantType == OMOAuthAuthorizationCode)
    {
        OMAuthenticationChallenge *challenge = [[OMAuthenticationChallenge
                                                 alloc] init];
        NSMutableDictionary *challengeDict = [NSMutableDictionary dictionary];
        if (config.browserMode == OMBrowserModeExternal)
        {
            [challengeDict setObject:config.logoutURL
                              forKey:OM_PROP_LOGOUT_URL];
            challenge.challengeType = OMChallengeExternalBrowser;
        }
        else if(config.browserMode == OMBrowserModeEmbedded)
        {
            [challengeDict setObject:[NSNull null] forKey:OM_PROP_AUTH_WEBVIEW];
            challenge.challengeType = OMChallengeEmbeddedBrowser;
        }
        else if(config.browserMode == OMBrowserModeSafariVC)
        {
            [challengeDict setObject:config.logoutURL
                              forKey:OM_PROP_LOGOUT_URL];
            challenge.challengeType = OMChallengeEmbeddedSafari;
        }
        
        challenge.authData = challengeDict;
        challenge.authChallengeHandler = ^(NSDictionary *dict,
                                           OMChallengeResponse response)
        {
            if (response == OMProceed)
            {
                self.authData = [NSMutableDictionary
                                 dictionaryWithDictionary:dict];
                if (config.browserMode == OMBrowserModeEmbedded)
                {
                    [weakself proceedWithChallengeResponse];
                }
                else
                {
                    [self performSelector:@selector(sendFinishLogout:)
                                 onThread:weakself.callerThread
                               withObject:nil
                            waitUntilDone:false];
                }
            }
        };
        if ([self.mss.delegate
             respondsToSelector:@selector(mobileSecurityService:
                                    didReceiveLogoutAuthenticationChallenge:)])
        {
            [self.mss.delegate mobileSecurityService:self.mss
             didReceiveLogoutAuthenticationChallenge:challenge];
        }
    }
    else
    {
        [self sendFinishLogout:nil];
    }
}

-(void)sendFinishLogout:(NSError *)error
{
    [self.webViewClient stopRequest];
    
    OMAuthenticationContext *context = [self.mss.cacheDict
                                        valueForKey:self.mss.authKey];
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)
    self.mss.configuration;

    [context clearCookies:self.clearPersistentCookies];

    if (self.clearPersistentCookies)
    {
        [self.mss.cacheDict removeObjectForKey:self.mss.authKey];
        
        if ([config isClientRegistrationRequired])
        {
            [self removeClientRegistrationToken];
        }
    }
    else
    {
        context.isLogoutFalseCalled = true;
    }
    
    if (self.clearPersistentCookies)
    {
        context = nil;
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

- (void)proceedWithChallengeResponse
{
    UIWebView *webView = [self.authData valueForKey:OM_PROP_AUTH_WEBVIEW];
    
    if ([webView isKindOfClass:[UIWebView class]])
    {
        
        NSURLRequest *request =
        [NSURLRequest
         requestWithURL:[(OMOAuthConfiguration *)self.mss.configuration logoutURL]
         cachePolicy:NSURLRequestUseProtocolCachePolicy
         timeoutInterval:10.0f];
        
        self.webViewClient = [[OMWebViewClient alloc] initWithWebView:webView
                                                     callBackDelegate:self];
        [self.webViewClient loadRequest:request];
    }
    else
    {
        NSError *error = [OMObject createErrorWithCode:OMERR_INVALID_INPUT];
        [self performSelector:@selector(sendFinishLogout:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:YES];
        
    }
}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
    [self performSelector:@selector(sendFinishLogout:)
                 onThread:self.callerThread
               withObject:nil
            waitUntilDone:YES];
}

- (void)webView:(UIWebView *)webView
didFailLoadWithError:(NSError *)error
{
    [self performSelector:@selector(sendFinishLogout:)
                 onThread:self.callerThread
               withObject:error
            waitUntilDone:YES];
}

- (void)removeClientRegistrationToken
{
    NSError *error = [[OMCredentialStore sharedCredentialStore]
                      deleteCredential:[self clientRegistrationKey]];
    
}

- (NSString*)clientRegistrationKey
{
    OMOAuthConfiguration* config = self.mss.configuration;
    
    NSString *regKey = [NSString stringWithFormat:@"%@_%@",config.authEndpoint,
                        config.loginHint];
    
    return regKey;
}

@end
