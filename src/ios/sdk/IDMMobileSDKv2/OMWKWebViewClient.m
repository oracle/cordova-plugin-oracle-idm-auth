/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMWKWebViewClient.h"
#import "OMClientCertChallangeHandler.h"
#import "OMAuthenticationChallenge.h"
#import "OMAuthenticationService.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"

@interface OMWKWebViewClient ()<WKNavigationDelegate,WKScriptMessageHandler>

@property (nonatomic, weak) id<WKNavigationDelegate> clientWebViewDelegate;
@property (nonatomic, weak) id callBackDelegate;

@end
@implementation OMWKWebViewClient

- (instancetype)initWithWKWebView:(WKWebView *)webView callBackDelegate:(id)del
{
    
    self = [super init];
    
    if (self)
    {
        _clientWebView = webView;
        _clientWebViewDelegate =  webView.navigationDelegate;
        _callBackDelegate = del;
    }
    return self;
}

- (void)configUserScript
{
    
    WKUserContentController *userContentController = nil;
    
    if(!self.clientWebView.configuration.userContentController)
    {
        userContentController = [[WKUserContentController alloc] init];
        self.clientWebView.configuration.
        userContentController = userContentController;
        
    }
    else
    {
        WKUserContentController *userContentController = self.clientWebView.
                                            configuration.userContentController;

    }
    
    NSString *script =
    @"window.webkit.messageHandlers.updateCookies.postMessage(document.cookie);";
    
    WKUserScript *cookieOutScript = [[WKUserScript alloc] initWithSource:script
                            injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                        forMainFrameOnly:NO];

    [self.clientWebView.configuration.userContentController
     addUserScript:cookieOutScript];
    
    [self.clientWebView.configuration.userContentController
     addScriptMessageHandler:self name:@"updateCookies"];
}

- (void)loadRequest:(NSURLRequest*)request;
{
    _clientWebView.navigationDelegate = self;
//    [self configUserScript];
    [self.clientWebView loadRequest:request];
}

- (void)stopRequest
{
    [self.clientWebView stopLoading];
    self.clientWebView.navigationDelegate = self.clientWebViewDelegate;
}

#pragma mark -

// @abstract Decides whether to allow or cancel a navigation.

- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler
{
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:decidePolicyForNavigationAction:decisionHandler:)])
    {
        [self.callBackDelegate webView:webView
        decidePolicyForNavigationAction:navigationAction
                       decisionHandler:decisionHandler];
    }
    
    if ([self.clientWebViewDelegate
         respondsToSelector:
         @selector(webView:decidePolicyForNavigationAction:decisionHandler:)])
    {
        [self.clientWebViewDelegate webView:webView
            decidePolicyForNavigationAction:navigationAction
                            decisionHandler:decisionHandler];
    }
    else
    {
        decisionHandler(WKNavigationActionPolicyAllow);
    }
    
}

// @abstract Decides whether to allow or cancel a navigation after its

- (void)webView:(WKWebView *)webView
decidePolicyForNavigationResponse:(WKNavigationResponse *)navigationResponse
decisionHandler:(void (^)(WKNavigationResponsePolicy))decisionHandler
{
    
    NSDictionary *headders = [(NSHTTPURLResponse*)navigationResponse.response
                              allHeaderFields];
    
    NSArray *cookies = [NSHTTPCookie cookiesWithResponseHeaderFields:headders
                                                              forURL:webView.URL];
    for (NSHTTPCookie *cookie in cookies)
    {
        // Do something with the cookie
        NSLog(@" %@",cookie.name);
    }
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:decidePolicyForNavigationResponse:decisionHandler:)])
    {
        [self.callBackDelegate webView:webView
       decidePolicyForNavigationResponse:navigationResponse
                       decisionHandler:decisionHandler];
    }

    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webView:decidePolicyForNavigationResponse:decisionHandler:)])
    {
        [self.clientWebViewDelegate webView:webView
     decidePolicyForNavigationResponse:navigationResponse
                       decisionHandler:decisionHandler];
    }
    else
    {
        decisionHandler(WKNavigationResponsePolicyAllow);
    }

}

// @abstract Invoked when a main frame navigation starts.

- (void)webView:(WKWebView *)webView
didStartProvisionalNavigation:(null_unspecified WKNavigation *)navigation
{
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:didStartProvisionalNavigation:)])
    {
        [self.callBackDelegate webView:webView
     didStartProvisionalNavigation:navigation];
    }

    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webView:didStartProvisionalNavigation:)])
    {
        [self.clientWebViewDelegate webView:webView
         didStartProvisionalNavigation:navigation];
    }

}

//@abstract Invoked when a server redirect is received for the main
- (void)webView:(WKWebView *)webView
    didReceiveServerRedirectForProvisionalNavigation:
    (null_unspecified WKNavigation *)navigation
{
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:didStartProvisionalNavigation:)])
    {
        [self.callBackDelegate webView:webView
         didStartProvisionalNavigation:navigation];
    }
    
    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webView:didStartProvisionalNavigation:)])
    {
        [self.clientWebViewDelegate webView:webView
              didStartProvisionalNavigation:navigation];
    }

}

// @abstract Invoked when an error occurs while starting to load data for

- (void)webView:(WKWebView *)webView
    didFailProvisionalNavigation:(null_unspecified WKNavigation *)navigation
      withError:(NSError *)error
{
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:didFailProvisionalNavigation:withError:)])
    {
        [self.callBackDelegate webView:webView
         didFailProvisionalNavigation:navigation withError:error];
    }

    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webView:didFailProvisionalNavigation:withError:)])
    {
        [self.clientWebViewDelegate webView:webView
          didFailProvisionalNavigation:navigation withError:error];
    }

    
}

// @abstract Invoked when content starts arriving for the main frame.
- (void)webView:(WKWebView *)webView
        didCommitNavigation:(null_unspecified WKNavigation *)navigation
{
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:didCommitNavigation:)])
    {
        [self.callBackDelegate webView:webView
                   didCommitNavigation:navigation];
    }

    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webView:didCommitNavigation:)])
    {
        [self.clientWebViewDelegate webView:webView
                   didCommitNavigation:navigation];
    }

}

// @abstract Invoked when a main frame navigation completes.

- (void)webView:(WKWebView *)webView
    didFinishNavigation:(null_unspecified WKNavigation *)navigation
{
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:didFinishNavigation:)])
    {
        [self.callBackDelegate webView:webView
                   didFinishNavigation:navigation];
    }

    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webView:didFinishNavigation:)])
    {
        [self.clientWebViewDelegate webView:webView
                   didFinishNavigation:navigation];
    }
    
}

// @abstract Invoked when an error occurs during a committed main frame

- (void)webView:(WKWebView *)webView
    didFailNavigation:(null_unspecified WKNavigation *)navigation
      withError:(NSError *)error
{
    if ([self.callBackDelegate respondsToSelector:
         @selector(webView:didFailNavigation:withError:)])
    {
        [self.callBackDelegate webView:webView
                   didFailNavigation:navigation withError:error];
    }
    
    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webView:didFailNavigation:withError:)])
    {
        [self.clientWebViewDelegate webView:webView
                          didFailNavigation:navigation withError:error];
    }

}

// @abstract Invoked when the web view's web content process is terminated.

- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView
{

    if ([self.callBackDelegate respondsToSelector:
         @selector(webViewWebContentProcessDidTerminate:)])
    {
        [self.callBackDelegate webViewWebContentProcessDidTerminate:webView];
    }
    
    if ([self.clientWebViewDelegate respondsToSelector:
         @selector(webViewWebContentProcessDidTerminate:)])
    {
        [self.clientWebViewDelegate webViewWebContentProcessDidTerminate:webView];
    }
    
}
- (void)webView:(WKWebView *)webView
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                    NSURLCredential *__nullable credential))completionHandler
{
    NSString *challengeType = challenge.protectionSpace.authenticationMethod;
    
    if ([challengeType isEqual:NSURLAuthenticationMethodHTTPBasic] ||
        [challengeType isEqual:NSURLAuthenticationMethodNTLM] ||
        [challengeType isEqual:NSURLAuthenticationMethodNegotiate] ||
        [challengeType isEqual:NSURLAuthenticationMethodDefault])
    {
        
            [self sendBasicAuthChallenge:challenge
                       completionHandler:completionHandler];

        
    }
    else if ([challengeType
              isEqualToString:NSURLAuthenticationMethodClientCertificate] &&
             [[(OMMobileSecurityService*)self.callBackDelegate configuration]
              presentClientCertIdentityOnDemand])
    {
        [[OMClientCertChallangeHandler sharedHandler]
         doClientTrustSynchronouslyForAuthenticationChallenge:challenge
         challengeReciver:self.callBackDelegate
         completionHandler:completionHandler];
        
    }
    else if ([challengeType isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        if (self.rejectSSLChallanges)
        {
            
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                              nil);
        }
        else
        {
            [[OMClientCertChallangeHandler sharedHandler]
             doServerTrustSynchronouslyForAuthenticationChallenge:challenge
             challengeReciver:self.callBackDelegate
             completionHandler:completionHandler];

        }
    }
    else
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                          nil);

    }
    
}

- (void)userContentController:(WKUserContentController *)userContentController
      didReceiveScriptMessage:(WKScriptMessage *)message
{
    NSArray<NSString *> *cookies = [message.body
                                    componentsSeparatedByString:@"; "];

    for (NSString *cookie in cookies)
    {
        // Get this cookie's name and value
        NSArray<NSString *> *comps = [cookie componentsSeparatedByString:@"="];
        if (comps.count < 2)
        {
            continue;
        }
        
        // Get the cookie in shared storage with that name
        NSHTTPCookie *localCookie = nil;
        NSArray *cookiesList = [[NSHTTPCookieStorage sharedHTTPCookieStorage]
                                cookiesForURL:self.clientWebView.URL];
        
        for (NSHTTPCookie *exitngCookie in cookiesList)
        {
            if ([exitngCookie.name isEqualToString:comps[0]])
            {
                localCookie = exitngCookie;
                break;
            }
        }
        
        // If there is a cookie with a stale value, update it now.
        if (localCookie)
        {
        NSMutableDictionary *props = [localCookie.properties mutableCopy];
        props[NSHTTPCookieValue] = comps[1];
        NSHTTPCookie *updatedCookie = [NSHTTPCookie cookieWithProperties:props];
        [[NSHTTPCookieStorage sharedHTTPCookieStorage] setCookie:updatedCookie];
        }
    }
}

#pragma mark -
#pragma mark Auth challange methods -

- (void)sendBasicAuthChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                    NSURLCredential *__nullable credential))completionHandler
{
    
    __block __weak OMAuthenticationService *currentAuthService = self.callBackDelegate;
    
    currentAuthService.challenge = [[OMAuthenticationChallenge alloc] init];
    
    NSMutableDictionary *challengeDict = [NSMutableDictionary
                                          dictionaryWithDictionary:
                                          currentAuthService.authData];
   
    [challengeDict removeObjectForKey:OM_AUTH_SUCCESS];
    [challengeDict setValue:[NSNull null] forKey:OM_USERNAME];
    [challengeDict setValue:[NSNull null] forKey:OM_PASSWORD];
    
    currentAuthService.challenge.authData = challengeDict;
    currentAuthService.challenge.challengeType = OMChallengeUsernamePassword;
  
    __block __weak OMAuthenticationService *weakOms = currentAuthService;
    
    currentAuthService.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                           OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            NSMutableDictionary *inDict = [NSMutableDictionary
                                           dictionaryWithDictionary:dict];
            [inDict removeObjectForKey:OM_IDENTITY_DOMAIN];
            
            NSString * userName = [inDict valueForKey:OM_USERNAME];
            NSString * password = [inDict valueForKey:OM_PASSWORD];
            
            if(![weakOms.mss.configuration isValidString:userName] ||
               ![weakOms.mss.configuration isValidString:password])
            {
                [weakOms.authData setValue:[NSNull null] forKey:OM_USERNAME];
                [weakOms.authData setValue:[NSNull null] forKey:OM_PASSWORD];
                NSError *error = [OMObject createErrorWithCode:
                                  OMERR_INVALID_USERNAME_PASSWORD];
                [weakOms.authData setObject:error
                                     forKey:OM_MOBILESECURITY_EXCEPTION];
                
                
                [self sendBasicAuthChallenge:challenge completionHandler:
                 completionHandler];
            }
            else
            {
                
                [weakOms.authData addEntriesFromDictionary:inDict];
                
                if([weakOms.authData objectForKey:OM_ERROR])
                {
                    [weakOms.authData removeObjectForKey:OM_ERROR];
                }
                
                NSString * userName = [currentAuthService.authData valueForKey:OM_USERNAME];
                NSString * password = [currentAuthService.authData valueForKey:OM_PASSWORD];
                
                if (userName && password)
                {
                    NSURLCredential *credential =  [NSURLCredential
                                                    credentialWithUser:userName
                                                    password:password
                                                    persistence:
                                                    NSURLCredentialPersistenceForSession];
                    
                    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
                    
                }
                else
                {
                    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                                      nil);
                }

            }
            
        }
        else
        {
            
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge,
                              nil);
            [self stopRequest];
            
            [weakOms.delegate didFinishCurrentStep:weakOms
                                          nextStep:OM_NEXT_AUTH_STEP_NONE
                                      authResponse:nil
                                             error:[OMObject createErrorWithCode:
                                            OMERR_USER_CANCELED_AUTHENTICATION]];
        }
       
    };
    
        [currentAuthService.delegate didFinishCurrentStep:currentAuthService
                                                 nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                                             authResponse:nil
                                                    error:nil];
    
}

@end
