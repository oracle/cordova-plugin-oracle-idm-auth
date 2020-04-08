/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMOIDCLogoutService.h"
#import "OMOIDCConfiguration.h"
#import "OMErrorCodes.h"
#import "OMCryptoService.h"
#import "OMCredentialStore.h"
#import "OMWKWebViewClient.h"

@interface OMOIDCLogoutService()
@property (nonatomic, strong) OMAuthenticationChallenge *challenge;
@property (nonatomic, assign) BOOL clearPersistentCookies;
@property (nonatomic, strong) NSURL *logoutURL;
@property (nonatomic, weak) OMOIDCConfiguration *config;
@property (nonatomic) BOOL redirectURLHit;
@property (nonatomic, strong) NSString *state;
@property (nonatomic, strong) NSError *error;
@property (nonatomic, strong) OMWKWebViewClient *wkWebViewClient;
@end

@implementation OMOIDCLogoutService
-(void)performLogout:(BOOL)clearRegistrationHandles
{
    self.callerThread = [NSThread currentThread];
    self.config = (OMOIDCConfiguration *)self.mss.configuration;
    __block __weak OMOIDCLogoutService *weakself = self;
    self.clearPersistentCookies = clearRegistrationHandles;
    if (self.config.grantType == OMOAuthImplicit ||
        self.config.grantType == OMOAuthAuthorizationCode)
    {
        OMAuthenticationContext *context = [self.mss.cacheDict
                                            valueForKey:self.mss.authKey];
        self.state = [NSString stringWithFormat:@"%ld",
                           [OMCryptoService secureRandomNumberOfDigits:6]];
        
        NSString *logoutURLString = [NSString stringWithFormat:@"%@?post_logout_redirect_uri=%@&state=%@&id_token_hint=%@",
                                self.config.endSessionEndpoint.absoluteString,
                                     self.config.redirectURI.absoluteString,
                                     self.state,context.idToken];
        NSURL *logoutURL = [NSURL URLWithString:logoutURLString];
        self.logoutURL = logoutURL;
        OMAuthenticationChallenge *challenge = [[OMAuthenticationChallenge
                                                 alloc] init];
        NSMutableDictionary *challengeDict = [NSMutableDictionary dictionary];
        if (self.config.browserMode == OMBrowserModeExternal)
        {
            [challengeDict setObject:logoutURL
                              forKey:OM_PROP_LOGOUT_URL];
            challenge.challengeType = OMChallengeExternalBrowser;
        }
        else if(self.config.browserMode == OMBrowserModeEmbedded)
        {
            [challengeDict setObject:[NSNull null] forKey:OM_PROP_AUTH_WEBVIEW];
            challenge.challengeType = OMChallengeEmbeddedBrowser;
        }
        else if(self.config.browserMode == OMBrowserModeSafariVC)
        {
            [challengeDict setObject:logoutURL
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
                if (self.config.browserMode == OMBrowserModeEmbedded)
                {
                    [weakself proceedWithChallengeResponse];
                }
                else
                {
                    NSURL *resposne = [dict valueForKey:OM_LOGOUT_RESPONSE];
                    [self parseLogoutResponse:resposne];
                    [self performSelector:@selector(sendFinishLogout:)
                                 onThread:self.callerThread
                               withObject:self.error
                            waitUntilDone:YES];
                }
                
            }
            else
            {
                [self performSelector:@selector(sendFinishLogout:)
                             onThread:self.callerThread
                           withObject:[OMObject createErrorWithCode:
                                       OMERR_USER_CANCELED_AUTHENTICATION]
                        waitUntilDone:YES];
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
    [self.wkWebViewClient stopRequest];
    OMAuthenticationContext *context = [self.mss.cacheDict
                                        valueForKey:self.mss.authKey];
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)
    self.mss.configuration;

    [context clearCookies:self.clearPersistentCookies];
    [self.mss.cacheDict removeObjectForKey:self.mss.authKey];

    if (self.clearPersistentCookies)
    {
        if ([config isClientRegistrationRequired])
        {
            [self removeClientRegistrationToken];
        }

    }
   
    if (self.mss.configuration.sessionActiveOnRestart)
    {
        [[OMCredentialStore sharedCredentialStore]
         deleteAuthenticationContext:self.mss.authKey];
    }
    
    context = nil;
    self.mss.authManager.curentAuthService.context = nil;
    
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
         requestWithURL:self.logoutURL
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
-(void)parseLogoutResponse:(NSURL *)url
{
    NSDictionary *dict = [OMOIDCConfiguration parseConfigurationURL:url
                                              persistInUserDefaults:false
                                                            withKey:nil];
    NSString *error = [dict valueForKey:@"error"];
    if ([error length])
    {
        self.error = [OMObject createErrorWithCode:-1
                                        andMessage:[dict valueForKey:error]];
    }
    else if ([self.state isEqualToString:[dict valueForKey:@"state"]])
    {
        self.error = [OMObject createErrorWithCode:OMERR_OAUTH_STATE_INVALID];
    }


}

- (void)stopRequest
{
    [self.wkWebViewClient stopRequest];
}


- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler
{
    NSURL *url = navigationAction.request.URL;
    NSLog(@"url = %@", url);
    NSString *urlScheme = navigationAction.request.URL.scheme;
    
    if ([urlScheme
         caseInsensitiveCompare:self.config.redirectURI.scheme]
        == NSOrderedSame)
    {
        self.redirectURLHit = true;
//        decisionHandler(WKNavigationActionPolicyCancel);
//        [self.wkWebViewClient stopRequest];
    }
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    [self performSelector:@selector(sendFinishLogout:)
                 onThread:self.callerThread
               withObject:nil
            waitUntilDone:YES];
}

-(void)webView:(WKWebView *)webView
    didFailProvisionalNavigation:(null_unspecified WKNavigation *)navigation
     withError:(nonnull NSError *)error
{
    if (!self.redirectURLHit)
    {
        [self performSelector:@selector(sendFinishLogout:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:YES];
    }
    else
    {
        [self performSelector:@selector(sendFinishLogout:)
                     onThread:self.callerThread
                   withObject:nil
                waitUntilDone:YES];
    }


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
