/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

#import "OMFedAuthLogoutService.h"
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMFedAuthConfiguration.h"
#import "OMAuthenticationChallenge.h"
#import "OMWebViewClient.h"
#import "OMErrorCodes.h"
#import "OMWKWebViewClient.h"
#import <WebKit/WebKit.h>

@interface OMFedAuthLogoutService ()<UIWebViewDelegate>

@property (nonatomic, strong) OMAuthenticationChallenge *challenge;
@property (nonatomic, strong) OMWebViewClient *webViewClient;
@property(nonatomic, strong) OMWKWebViewClient *wkWebViewClient;
@property (nonatomic,retain) NSTimer *timer;

@property (nonatomic, assign) BOOL clearPersistentCookies;
@end

@implementation OMFedAuthLogoutService

-(void)performLogout:(BOOL)clearRegistrationHandles
{
    if (self.mss.authenticationContext)
    {
        self.callerThread = [NSThread currentThread];
        self.clearPersistentCookies = clearRegistrationHandles;
        
        self.challenge = [[OMAuthenticationChallenge alloc] init];
        self.challenge.authData = [NSMutableDictionary dictionary];
        self.challenge.challengeType = OMChallengeEmbeddedBrowser;
        
        __block __weak OMFedAuthLogoutService *weakself = self;
        
        self.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                                OMChallengeResponse response)
        {
            if (response == OMProceed)
            {
                weakself.authData = [NSMutableDictionary
                                     dictionaryWithDictionary:dict];
                [weakself proceedWithChallengeResponce];
            }
            else
            {
                //no webview error
                NSError *error = [OMObject createErrorWithCode:
                                  OMERR_USER_CANCELED_AUTHENTICATION];
                
                [weakself performSelector:@selector(sendFinishLogout:)
                                 onThread:weakself.callerThread
                               withObject:error
                            waitUntilDone:YES];
                
            }
        };
        
        if ([self.mss.delegate respondsToSelector:@selector(mobileSecurityService:didReceiveLogoutAuthenticationChallenge:)]) {
            
            [self.mss.delegate mobileSecurityService:self.mss
             didReceiveLogoutAuthenticationChallenge:self.challenge];
        }
    }
    else
    {
        [self performSelector:@selector(sendFinishLogout:)
                         onThread:[NSThread currentThread]
                       withObject:nil
                    waitUntilDone:YES];

    }
}

-(void)sendFinishLogout:(NSError *)error
{
    if([(OMFedAuthConfiguration*)self.mss.configuration enableWKWebView])
    {
        [self clearWkWebViewCookies];
        [self.wkWebViewClient stopRequest];
    }
    else
    {
        [self clearWebViewCookies];
        [self.webViewClient stopRequest];
    }
    
    [self.mss.cacheDict removeAllObjects];
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

 - (void)proceedWithChallengeResponce
{
    NSError *error = nil;
    
    id webView = [self.authData valueForKey:OM_PROP_AUTH_WEBVIEW];

    if ([(OMFedAuthConfiguration*)self.mss.configuration enableWKWebView] &&
        [webView isKindOfClass:[WKWebView class]])
    {
        NSURLRequest *request = [NSURLRequest
                                 requestWithURL:
                                 [(OMFedAuthConfiguration*)self.mss.configuration
                                  logoutURL]
                                 cachePolicy:NSURLRequestUseProtocolCachePolicy
                                 timeoutInterval:10.0f];
        
        self.wkWebViewClient = [[OMWKWebViewClient alloc] initWithWKWebView:webView
                                                           callBackDelegate:self];
        [self.wkWebViewClient loadRequest:request];

    }
    else if (![(OMFedAuthConfiguration*)self.mss.configuration enableWKWebView]
             &&
             [webView isKindOfClass:[UIWebView class]])
    {
        
        NSURLRequest *request = [NSURLRequest
                                 requestWithURL:
                                 [(OMFedAuthConfiguration*)self.mss.configuration
                                  logoutURL] cachePolicy:NSURLRequestUseProtocolCachePolicy
                                 timeoutInterval:10.0f];
        
        self.webViewClient = [[OMWebViewClient alloc] initWithWebView:webView
                                                     callBackDelegate:self];
        [self.webViewClient loadRequest:request];
    }
    else
    {
        error = [OMObject createErrorWithCode:OMERR_INVALID_INPUT];
        
        [self performSelector:@selector(sendFinishLogout:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:YES];
    }
}

#pragma mark -
#pragma UIWebView Delegate Methods -

- (void)webViewDidStartLoad:(UIWebView *)webView
{
    if ([self.timer isValid])
    {
        [self.timer invalidate];
    }
}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{

    if (webView.isLoading)
        return;
    
    NSURL *URL = webView.request.URL;

    OMFedAuthConfiguration *fedauthconfig = (OMFedAuthConfiguration*)self.mss.configuration;

    if (fedauthconfig.autoConfirmLogout)
    {
        BOOL isAutoConfirmDone = NO;
        
        if ([fedauthconfig.confirmLogoutButtons count])
        {
            for (NSString *button in fedauthconfig.confirmLogoutButtons)
            {
               
                NSString *jsScript = [NSString stringWithFormat:
                                      @"document.getElementById('%@').value;",
                                      button];
                NSString *value = [webView stringByEvaluatingJavaScriptFromString:jsScript];

                if ([value length] > 0)
                {
                    jsScript = [NSString stringWithFormat:
                                          @"document.getElementById('%@').click()",
                                          button];
                    
                    [webView stringByEvaluatingJavaScriptFromString:
                     jsScript];
                    isAutoConfirmDone = YES;
                    break;
                }

            }
        }
        else
        {
        
            NSString *value = [webView stringByEvaluatingJavaScriptFromString:@"document.getElementById('Confirm').value;"];
            
            if ([value length] > 0)
            {
                [webView stringByEvaluatingJavaScriptFromString:
                 @"document.getElementById('Confirm').click()"];
                isAutoConfirmDone = YES;

            }

        }
        
        if (isAutoConfirmDone)
            return;
    }
    
    if (fedauthconfig.logoutFailureURL || fedauthconfig.logoutSuccessURL)
    {
        [self processLogoutWithUrl:URL];

    }
    else if (fedauthconfig.logoutSuccessURL == nil)
    {
        self.timer = [NSTimer scheduledTimerWithTimeInterval:3 target:self
                                                    selector:@selector(validatePageRedirects)
                                                    userInfo:nil
                                                     repeats:NO];
        
    }
    
}

- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
    OMFedAuthConfiguration *fedauthconfig = (OMFedAuthConfiguration*)self.mss.configuration;
    
    if (fedauthconfig.autoConfirmLogout && (error.code == NSURLErrorCancelled))
    {
        error = nil;
    }
    
    if ([self.timer isValid])
    {
        [self.timer invalidate];
    }

    [self performSelector:@selector(sendFinishLogout:)
                 onThread:self.callerThread
               withObject:error
            waitUntilDone:YES];
}

#pragma mark -
#pragma mark WKNavigation Delegates-

-(void)webView:(WKWebView *)webView
didFailProvisionalNavigation:(null_unspecified WKNavigation *)navigation
     withError:(nonnull NSError *)error
{
    OMFedAuthConfiguration *fedauthconfig = (OMFedAuthConfiguration*)self.mss.configuration;
    
    if (fedauthconfig.autoConfirmLogout && (error.code == NSURLErrorCancelled))
    {
        error = nil;
    }

    [self performSelector:@selector(sendFinishLogout:)
                 onThread:self.callerThread
               withObject:error
            waitUntilDone:YES];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    if (webView.isLoading)
        return;

    NSURL *URL = webView.URL;

    OMFedAuthConfiguration *fedauthconfig = (OMFedAuthConfiguration*)self.mss.configuration;
    
    if (fedauthconfig.autoConfirmLogout)
    {
       __block BOOL isAutoConfirmDone = NO;

        if ([fedauthconfig.confirmLogoutButtons count])
        {
            for (NSString *button in fedauthconfig.confirmLogoutButtons)
            {
                if (isAutoConfirmDone)
                    break;
                
                NSString *jsScript = [NSString stringWithFormat:
                                      @"document.getElementById('%@').click()",
                                      button];
                
                [webView evaluateJavaScript:jsScript
                          completionHandler:^(id result, NSError * _Nullable error) {
                              
                              if (!error)
                              {
                                  isAutoConfirmDone = YES;
                              }

                          }];
                
            }
        }
        else
        {
            [webView evaluateJavaScript:@"document.getElementById('Confirm').click()"
                      completionHandler:^(id result, NSError * _Nullable error) {
                          
                          if (!error)
                          {
                              isAutoConfirmDone = YES;
                          }

                      }];
            
        }
        
        if (isAutoConfirmDone)
            return;

    }

    if (fedauthconfig.logoutFailureURL || fedauthconfig.logoutSuccessURL)
    {
        [self processLogoutWithUrl:URL];
        
    }
    else
    {
        [self performSelector:@selector(sendFinishLogout:)
                     onThread:self.callerThread
                   withObject:nil
                waitUntilDone:YES];
        
    }
    

}

- (void)clearWkWebViewCookies
{
    NSSet *websiteDataTypes = [NSSet setWithArray:@[
                                                    WKWebsiteDataTypeMemoryCache,
                                                    WKWebsiteDataTypeCookies,
                                                    WKWebsiteDataTypeSessionStorage,
                                                    ]];
    NSMutableSet *visitedURLs = [self.mss.cacheDict
                                 valueForKey:OM_VISITED_HOST_URLS];
    
    [self.wkWebViewClient cookiesForVisitedHosts:visitedURLs
                               completionHandler:^(NSArray<WKWebsiteDataRecord *> * records)
     {
         if ([records count])
         {
             [[WKWebsiteDataStore defaultDataStore] removeDataOfTypes:websiteDataTypes
                                                       forDataRecords:records
                                                    completionHandler:^{
                                                        
                                                        NSLog(@"cleared");
                                                    }];
         }
         
     }];
    
}

- (void)clearWebViewCookies
{
    NSMutableSet *visitedURLs = [self.mss.cacheDict
                                 valueForKey:OM_VISITED_HOST_URLS];
    
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    for (NSURL *url in visitedURLs)
    {
        NSArray *cookies = [cookieStore cookiesForURL:url];
        for (NSHTTPCookie *cookie in cookies)
        {
            if (_clearPersistentCookies)
            {
                [cookieStore deleteCookie:cookie];
            }
            if ([cookie isSessionOnly])
            {
                [cookieStore deleteCookie:cookie];
            }
        }
    }
    
}

- (void)processLogoutWithUrl:(NSURL*)logoutUrl
{
    OMFedAuthConfiguration *fedAuthConfig = (OMFedAuthConfiguration*)self.mss.configuration;
    
    if (YES == [OMObject isCurrentURL:logoutUrl EqualTo:fedAuthConfig.logoutSuccessURL])
    {
        [self performSelector:@selector(sendFinishLogout:)
                     onThread:self.callerThread
                   withObject:nil
                waitUntilDone:YES];
    }
    else if (YES == [OMObject isCurrentURL:logoutUrl EqualTo:fedAuthConfig.logoutFailureURL])
    {
        NSError *error = [OMObject createErrorWithCode:OMERR_LOGOUT_FAILED];
        [self performSelector:@selector(sendFinishLogout:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:YES];
    }

}

- (void)validatePageRedirects
{
    if ([self.timer isValid])
    {
        [self.timer invalidate];
    }
    
    [self performSelector:@selector(sendFinishLogout:)
                 onThread:self.callerThread
               withObject:nil
            waitUntilDone:YES];
}

@end
