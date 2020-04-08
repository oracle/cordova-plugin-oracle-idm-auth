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
#import "OMCredentialStore.h"
#import "OMWKWebViewClient.h"

@interface OMOAuthLogoutService()
@property (nonatomic, strong) OMAuthenticationChallenge *challenge;
@property (nonatomic, strong) OMWKWebViewClient *wkWebViewClient;
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
    WKWebView *webView = [self.authData valueForKey:OM_PROP_AUTH_WEBVIEW];
    
    if ([webView isKindOfClass:[WKWebView class]])
    {
        
        NSURLRequest *request =
        [NSURLRequest
         requestWithURL:[(OMOAuthConfiguration *)self.mss.configuration logoutURL]
         cachePolicy:NSURLRequestUseProtocolCachePolicy
         timeoutInterval:10.0f];
    
        self.wkWebViewClient = [[OMWKWebViewClient alloc] initWithWKWebView:webView callBackDelegate:self];
        [self.wkWebViewClient loadRequest:request];

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

- (void)stopRequest
{
    [self.wkWebViewClient stopRequest];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    [self performSelector:@selector(sendFinishLogout:)
                 onThread:self.callerThread
               withObject:nil
            waitUntilDone:YES];
    [self stopRequest];

}

-(void)webView:(WKWebView *)webView
    didFailProvisionalNavigation:(null_unspecified WKNavigation *)navigation
     withError:(nonnull NSError *)error
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
