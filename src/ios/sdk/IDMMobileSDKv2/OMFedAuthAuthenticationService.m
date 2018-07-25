/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMFedAuthAuthenticationService.h"
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMFedAuthConfiguration.h"
#import "OMWebViewClient.h"
#import "OMURLProtocol.h"
#import "OMErrorCodes.h"
#import "OMToken.h"
#import "OMWKWebViewClient.h"
#import <WebKit/WebKit.h>

@interface OMFedAuthAuthenticationService  ()<UIWebViewDelegate,WKNavigationDelegate>

@property(nonatomic, assign) BOOL isFirstAccess;
@property(nonatomic, strong) NSURL *previousPostURL;
@property(nonatomic, assign) NSUInteger numVisitsToPostURL;
@property(nonatomic, strong) OMWebViewClient *webViewClient;
@property(nonatomic, strong) OMWKWebViewClient *wkWebViewClient;

@end

@implementation OMFedAuthAuthenticationService

-(BOOL)isInputRequired:(NSMutableDictionary *)authData
{
    BOOL isRequired = false;
   id webview = [authData valueForKey:OM_PROP_AUTH_WEBVIEW];
    
    if (!webview || (webview == [NSNull null]))
    {
        
        [authData setObject:[NSNull null] forKey:OM_PROP_AUTH_WEBVIEW];
        isRequired = true;
        
    }
    
    return isRequired;
}
-(void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError *__autoreleasing *)error
{
    self.configuration = (OMFedAuthConfiguration *)self.mss.configuration;
    self.callerThread = [NSThread currentThread];
    self.authData = authData;
    [self sendChallenge];
}

-(void)sendChallenge
{
    
    self.challenge = [[OMAuthenticationChallenge alloc] init];
    self.challenge.authData = self.authData;
    self.challenge.challengeType = OMChallengeEmbeddedBrowser;
    
    __block __weak OMFedAuthAuthenticationService *weakself = self;
    
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
            NSError *error = [OMObject createErrorWithCode:OMERR_USER_CANCELED_AUTHENTICATION];
            
            [weakself performSelector:@selector(sendFinishAuthentication:)
                         onThread:weakself.callerThread
                       withObject:error
                    waitUntilDone:YES];
            

        }
    };
    
    [self.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                           authResponse:nil
                                  error:nil];
}

- (void)proceedWithChallengeResponce
{
    id webView = [self.authData valueForKey:OM_PROP_AUTH_WEBVIEW];
    NSError *error = nil;
    
    if (self.configuration.enableWKWebView &&
        [webView isKindOfClass:[WKWebView class]])
    {
        NSURLRequest *request = [NSURLRequest
                                 requestWithURL:self.configuration.loginURL
                                 cachePolicy:NSURLRequestUseProtocolCachePolicy
                                 timeoutInterval:30.0f];
        
        self.wkWebViewClient = [[OMWKWebViewClient alloc] initWithWKWebView:webView
                                                     callBackDelegate:self];
        [self.wkWebViewClient loadRequest:request];
        
    }
    else if (!self.configuration.enableWKWebView &&
             [webView isKindOfClass:[UIWebView class]])
    {
        
        [NSURLProtocol registerClass:[OMURLProtocol class]];
        [OMURLProtocol setOMAObject:self];
        NSURLRequest *request = [NSURLRequest
                                 requestWithURL:self.configuration.loginURL
                                 cachePolicy:NSURLRequestUseProtocolCachePolicy
                                             timeoutInterval:30.0f];
        
        self.webViewClient = [[OMWebViewClient alloc] initWithWebView:webView
                                                     callBackDelegate:self];
        [self.webViewClient loadRequest:request];
    }
    else
    {
        if (nil == webView)
        {
            error = [OMObject createErrorWithCode:OMERR_WEBVIEW_REQUIRED];

        }
        else
        {
            error = [OMObject createErrorWithCode:OMERR_WKWEBVIEW_REQUIRED];
            
        }
        
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:YES];

    }
}

#pragma mark -
#pragma mark Cancel and complete Authentication-

- (void)cancelAuthentication
{
    [self stopRequest];
    
    if ([self.mss isNSURLProtocolActive])
    {
        [NSURLProtocol unregisterClass:[OMURLProtocol class]];
        [OMURLProtocol setOMAObject:nil];
    }
    
    NSError *error = [OMObject
                      createErrorWithCode:OMERR_USER_CANCELED_AUTHENTICATION];
    
    [self performSelector:@selector(sendFinishAuthentication:)
                 onThread:self.callerThread
               withObject:error
            waitUntilDone:YES];

}

- (void)stopRequest
{
    if (self.configuration.enableWKWebView)
    {
        [self.wkWebViewClient stopRequest];
    }
    else
    {
        [self.webViewClient stopRequest];
    }

}

- (void)completedAuthentication
{
    [self stopRequest];
    [self.authData setObject:self.context.visitedHosts forKey:OM_VISITED_HOST_URLS];
    
    NSError *error = [self.authData objectForKey:OM_ERROR];
    
    if (error)
    {
        if (self.configuration.enableWKWebView)
        {
            [self clearWkWebViewCookies];
        }
        else
        {
            [self clearVisitedHostCookies];
        }
        
    }
    else
    {
        [self processRequiredTokens];
    }
    
    [self performSelector:@selector(sendFinishAuthentication:)
                 onThread:self.callerThread
               withObject:error
            waitUntilDone:YES];

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
    
    [self.context startTimers];
    
    [OMURLProtocol setOMAObject:nil];
    [NSURLProtocol unregisterClass:[OMURLProtocol class]];

    [self.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_NONE
                           authResponse:nil
                                  error:object];

}

#pragma mark -
#pragma mark UIWebViewDelegate Delegates-

///////////////////////////////////////////////////////////////////////////////
// UIWebViewDelegate implementation
- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)
                request navigationType:(UIWebViewNavigationType)navigationType
{
    NSURL *successURL =  self.configuration.loginSuccessURL;
    NSURL *failureURL = self.configuration.loginFailureURL;
    NSURL *loginURL   = self.configuration.loginURL;
    
    NSURL *url = request.URL;
    [self.context.visitedHosts addObject:url];
    
    NSString *httpType = [request HTTPMethod];
    NSData *bodyData = [request HTTPBody];

    [self processNavgation:httpType httpData:bodyData url:url];
    
    if (YES == [OMObject isCurrentURL:url EqualTo:successURL])
    {
        if (self.isFirstAccess &&
            YES == [OMObject isCurrentURL:successURL EqualTo:loginURL])
        {
            self.isFirstAccess = FALSE;
        }
    }
    else if (YES == [OMObject isCurrentURL:url EqualTo:failureURL] ||
             self.numVisitsToPostURL > 5)
    {
        NSError *error = [OMObject createErrorWithCode:OMERR_USER_AUTHENTICATION_FAILED];
        [self.authData setValue:error forKey:OM_ERROR];
        [self completedAuthentication];
        return NO;
    }
    
    if (![url.scheme isEqualToString:@"http"] &&
        ![url.scheme isEqualToString:@"https"])
    {
        if ([[UIApplication sharedApplication]canOpenURL:url])
        {
            [[UIApplication sharedApplication]openURL:url];
            return NO;
        }
    }

    return YES;
}

- (void)webViewDidStartLoad:(UIWebView *)webView
{
    [WKWebsiteDataStore defaultDataStore];
    
}
- (void)webViewDidFinishLoad:(UIWebView *)webView
{
    NSURL *URL = webView.request.URL;
    
    if (YES == [OMObject isCurrentURL:URL EqualTo:self.configuration.loginSuccessURL])
    {
        NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        NSArray *cookies = [cookieStore cookiesForURL:URL];
        
        if ([cookies count] > 0)
        {
            NSString *queryParams = [URL query];
            NSDictionary *headers = [webView.request allHTTPHeaderFields];
            [self.authData setValue:queryParams forKey:OM_FED_AUTH_QUERY_PARAMS];
            [self.authData setValue:headers forKey:OM_FED_AUTH_HEADERS];
        }
        if (self.configuration.parseTokenRelayResponse)
        {
            NSString *pageContent = [webView
                                     stringByEvaluatingJavaScriptFromString:
                        @"document.getElementsByTagName('pre')[0].innerHTML"];
            NSData *pageData = [pageContent
                                dataUsingEncoding:NSUTF8StringEncoding];
            id ssoTokens = [NSJSONSerialization JSONObjectWithData:pageData
                                                           options:0
                                                             error:nil];
            if (!ssoTokens)
            {
                pageContent = [webView stringByEvaluatingJavaScriptFromString:
                               @"document.body.innerHTML"];
                pageData = [pageContent dataUsingEncoding:NSUTF8StringEncoding];
                ssoTokens = [NSJSONSerialization JSONObjectWithData:pageData
                                                            options:0
                                                              error:nil];
            }
            if ([ssoTokens isKindOfClass:[NSDictionary class]])
            {
                [self.authData setValue:ssoTokens forKey:OM_TOKENS];
            }
        }
        [self completedAuthentication];

    }
    else if (YES == [OMObject isCurrentURL:URL EqualTo:self.configuration.loginFailureURL])
    {
        NSError *error = [OMObject createErrorWithCode:OMERR_USER_AUTHENTICATION_FAILED];
        [self.authData setValue:error forKey:OM_ERROR];
        [self completedAuthentication];

    }
}
- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error;
{
    [self.authData setValue:error forKey:OM_ERROR];
    [self completedAuthentication];

}

#pragma mark - 
#pragma mark WKNavigation Delegates-

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler
{
    NSURL *successURL =  self.configuration.loginSuccessURL;
    NSURL *failureURL = self.configuration.loginFailureURL;
    NSURL *loginURL   = self.configuration.loginURL;
    
    NSURL *url = webView.URL;
    [self.context.visitedHosts addObject:url];

    NSString *httpType = [navigationAction.request HTTPMethod];
    NSData *bodyData = [navigationAction.request HTTPBody];
    
    [self processNavgation:httpType httpData:bodyData url:url];
    
    if (YES == [OMObject isCurrentURL:url EqualTo:successURL])
    {
        if (self.isFirstAccess &&
            YES == [OMObject isCurrentURL:successURL EqualTo:loginURL])
        {
            self.isFirstAccess = FALSE;
        }
    }
    else if (YES == [OMObject isCurrentURL:url EqualTo:failureURL] ||
             self.numVisitsToPostURL > 5)
    {
        NSError *error = [OMObject createErrorWithCode:OMERR_USER_AUTHENTICATION_FAILED];
        [self.authData setValue:error forKey:OM_ERROR];
        [self completedAuthentication];
        decisionHandler(WKNavigationActionPolicyCancel);
    }
    
    if (![url.scheme isEqualToString:@"http"] &&
        ![url.scheme isEqualToString:@"https"])
    {
        if ([[UIApplication sharedApplication]canOpenURL:url])
        {
            [[UIApplication sharedApplication]openURL:url];
            decisionHandler(WKNavigationActionPolicyCancel);
        }
    }
    
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    NSURL *URL = webView.URL;
    
    if (YES == [OMObject isCurrentURL:URL EqualTo:self.configuration.loginSuccessURL])
    {
        if (self.configuration.parseTokenRelayResponse)
        {
            
            [webView evaluateJavaScript:@"document.getElementsByTagName('pre')[0].innerHTML"
                    completionHandler:^(id _Nullable result, NSError * _Nullable error)
            {
                id ssoTokens = nil;
                
                if (!error)
                {
                    NSData *pageData = [result
                                        dataUsingEncoding:NSUTF8StringEncoding];
                    ssoTokens = [NSJSONSerialization JSONObjectWithData:pageData
                                                                options:0
                                                                  error:nil];;

                }
                
                if (!ssoTokens)
                {
                    
                    [webView evaluateJavaScript:@"document.body.innerHTML"
                              completionHandler:^(id _Nullable result,
                                                  NSError * _Nullable error)
                    {
                        
                        if (!error)
                        {
                            NSData *pageData = [result
                                                dataUsingEncoding:NSUTF8StringEncoding];
                            
                            id ssoTokens = [NSJSONSerialization
                                            JSONObjectWithData:pageData
                                            options:0
                                            error:nil];
                            if ([ssoTokens isKindOfClass:[NSDictionary class]])
                            {
                                [self.authData setValue:ssoTokens forKey:OM_TOKENS];
                            }

                        }

                        [self completedAuthentication];
                        
                    }];
                }
                else
                {
                    if ([ssoTokens isKindOfClass:[NSDictionary class]])
                    {
                        [self.authData setValue:ssoTokens forKey:OM_TOKENS];
                    }
                   
                    [self completedAuthentication];
                    
                }
                

            }];
            
        }
        else
        {
            [self completedAuthentication];

        }
        
    }
    else if (YES == [OMObject isCurrentURL:URL EqualTo:self.configuration.loginFailureURL])
    {
        NSError *error = [OMObject createErrorWithCode:OMERR_USER_AUTHENTICATION_FAILED];
        [self.authData setValue:error forKey:OM_ERROR];
        [self completedAuthentication];
    }
    
}

-(void)webView:(WKWebView *)webView
    didFailProvisionalNavigation:(null_unspecified WKNavigation *)navigation
     withError:(nonnull NSError *)error
{
    NSLog(@" Challenge received = %@",error);
    
    [self.authData setValue:error forKey:OM_ERROR];
    [self completedAuthentication];
}

- (void)processNavgation:(NSString*)httpType httpData:(NSData*)bodyData
                       url:(NSURL*)url
{
    __block BOOL usernameFound = FALSE;
    __block BOOL passwordFound = FALSE;
    NSArray *usernameTokens = [NSArray arrayWithObjects:@"username",
                               @"uname", @"email", @"uid", @"userid", nil];
    // add app provided tokens
    NSSet *usernameParamName = self.configuration.fedAuthUsernameParamName;
    if ([usernameParamName count])
    {
        NSSet *moreUsernameTokens =
        [usernameParamName objectsPassingTest:^(id obj, BOOL *stop)
         {
             if ([obj isKindOfClass:[NSString class]])
             {
                 NSString *value = obj;
                 return (BOOL)[value length];
             }
             else
                 return NO;
         }];
        usernameTokens = [usernameTokens
                          arrayByAddingObjectsFromArray:[moreUsernameTokens
                                                         allObjects]];
    }
    
    if (bodyData != nil &&
        NSOrderedSame == [httpType caseInsensitiveCompare:@"POST"])
    {
        if (self.previousPostURL == nil ||
            FALSE == [OMObject isCurrentURL:self.previousPostURL EqualTo:url])
        {
            self.previousPostURL = url;
            self.numVisitsToPostURL = 1;
        }
        else
        {
            self.numVisitsToPostURL += 1;
        }
        
        NSString *body = [[NSString alloc] initWithData:bodyData
                                               encoding:NSUTF8StringEncoding];
        
        NSArray *components = [body componentsSeparatedByString:@"&"];
        
        for (NSString *component in components)
        {
            NSArray *namevalue = [component componentsSeparatedByString:@"="];
            if (namevalue.count == 2)
            {
                NSString *name = [namevalue objectAtIndex:0];
                NSString *value = [namevalue objectAtIndex:1];
                
                if (!usernameFound)
                {
                    usernameFound = [self checkForPresenceOfTokens:usernameTokens
                                                          inString:name];
                    if (usernameFound)
                    {
                        NSString *username = [value
                                              stringByRemovingPercentEncoding];
                        /* Do not populate username if its value is not present.
                         This will lead to SDK retry logic for username cannot
                         be empty */
                        if([username length] > 0)
                        {
                            [self.authData setObject:username
                                              forKey:OM_USERNAME];
                        }
                    }
                }
                if (!passwordFound)
                {
                    //disabling code for password extraction
                    // can be useful for debugging
                    passwordFound = true;
                }
            }
            if (usernameFound && passwordFound)
                break;
        }
    }
    else if (self.configuration.enableWKWebView &&
             NSOrderedSame == [httpType caseInsensitiveCompare:@"POST"])
    {
        
        for (NSString *token in usernameTokens)
        {
            NSString*js = [NSString
                           stringWithFormat:@"document.getElementById('%@').value",
                           token];
            
            [self.wkWebViewClient.clientWebView evaluateJavaScript:js
                      completionHandler:^(id _Nullable result,
                                          NSError * _Nullable error)
             {
                 if ([result isKindOfClass:[NSString class]] && [result length] > 0)
                 {
                     [self.authData setObject:result
                                       forKey:OM_USERNAME];
                     usernameFound = YES;
                 }
                 
             }];
            
            if (usernameFound)
            {
                break;
            }
            
        }

    }
}
    


#pragma mark -
#pragma mark Private methods -

- (void)clearVisitedHostCookies
{
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    for (NSURL *url in self.context.visitedHosts)
    {
        NSArray *cookies = [cookieStore cookiesForURL:url];
        for (NSHTTPCookie *cookie in cookies)
            [cookieStore deleteCookie:cookie];
    }
}

- (void)clearWkWebViewCookies
{
    NSSet *websiteDataTypes = [NSSet setWithArray:@[
                            WKWebsiteDataTypeMemoryCache,
                            WKWebsiteDataTypeCookies,
                            WKWebsiteDataTypeSessionStorage,
                            ]];
    
    [self.wkWebViewClient cookiesForVisitedHosts:self.context.visitedHosts
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

#pragma mark -
#pragma mark Tokens extracting methods -

- (void)processRequiredTokens
{
    NSError *error = nil;
    
    [self.mss.cacheDict setObject:self.context forKey:self.mss.authKey];
    [self.mss.cacheDict setValue:self.context.visitedHosts
                          forKey:OM_VISITED_HOST_URLS];
    
    NSMutableArray *requiredCookies = [NSMutableArray arrayWithArray:
                                       [self.configuration.requiredTokens
                                        allObjects]];
    
    if ([requiredCookies count] > 0)
    {
        if (!self.configuration.enableWKWebView)
        {
            [self extractTokensFromCookies:requiredCookies error:&error];
        }
    }
    
    if (self.configuration.parseTokenRelayResponse)
    {
        [self parseTokenRelayResponse:&error];
    }
    
    NSString *username = [self.authData objectForKey:OM_USERNAME];
    
    if (username)
    {
        self.context.userName = username;
    }
    
}


- (void)extractTokensFromDataRecord:(NSMutableArray*)requiredCookies
                               error:(NSError**)error
{
    [self.wkWebViewClient cookiesForVisitedHosts:self.context.visitedHosts completionHandler:
     ^(NSArray<WKWebsiteDataRecord *> * dataRecords)
    {
        for (WKWebsiteDataRecord *record in dataRecords)
        {
            NSLog(@"name = %@ data = %@", record.displayName,record.dataTypes);
        }
        
    }];
    
}

- (void)extractTokensFromCookies:(NSMutableArray*)requiredCookies
                           error:(NSError**)error
{
    NSMutableDictionary *tokensDict = [[NSMutableDictionary alloc] init];
    NSUInteger numCookiesFound = 0;
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    NSUInteger numCookiesRequired = [requiredCookies count];

    OMAuthenticationContext *localContext = self.context;
    
    //Cache tokens of all visited URLs
    for (NSURL *url in self.context.visitedHosts)
    {
        NSArray *cookies = [cookieStore cookiesForURL:url];
        for (NSHTTPCookie *cookie in cookies)
        {
            //Cookie name is cookie name + ";" + cookie domain so that
            //it is unique
            NSString *cookieName = [[cookie name] stringByAppendingFormat:@";%@",
                                    [cookie domain]];
            [tokensDict setValue:[cookie value] forKey:cookieName];
            
            for (NSUInteger counter = 0; counter < [requiredCookies count];
                 counter++)
            {
                NSString *token = [requiredCookies objectAtIndex:counter];
                if (NSOrderedSame == [token compare:[cookie name]])
                {
                    numCookiesFound++;
                    [requiredCookies removeObjectAtIndex:counter];
                    break;
                } //if block
            } //for loop
        } //for (NSHTTPCookie *cookie in cookies)
    } //for (NSURL *url in visitedURLs)

    self.context.accessTokens= tokensDict;
    
    if (numCookiesFound < numCookiesRequired)
    {
        *error = [OMObject
                 createErrorWithCode:OMERR_USER_AUTHENTICATION_FAILED];
        OMLog(@"Expected number of tokens not available. Expected : %lu. Available :%lu",
              (unsigned long)numCookiesRequired,
              (unsigned long)numCookiesFound);
    }
    else
    {
        //One of the login URL's cookie value becomes the master token
        OMFedAuthConfiguration *mobConf = self.configuration;
        NSURL *loginURL = [mobConf loginURL];
        
        if (loginURL)
        {
            NSArray *cookies = [cookieStore cookiesForURL:loginURL];
            if ([cookies count] > 0)
            {
                NSHTTPCookie *masterCookie = [cookies objectAtIndex:0];
                localContext.tokenValue = [masterCookie value];
            }
        }
        
        NSString *authKey = [self.mss authKey];
        [self.mss.cacheDict setValue:localContext forKey:authKey];
        localContext.authMode = OMRemote;
    }

}

- (void)parseTokenRelayResponse:(NSError**)error
{
    NSDictionary *accessToken = [self.authData valueForKey:OM_TOKENS];
    NSString *tokenValue = [accessToken valueForKey:OM_ACCESS_TOKEN];
    NSString *principal = [accessToken valueForKey:OM_PRINCIPAL];
    if ([principal length])
    {
        self.context.userName = principal;
    }
    if ([tokenValue length])
    {
        OMToken *token = [[OMToken alloc] init];
        token.tokenName = OM_ACCESS_TOKEN;
        token.tokenValue = tokenValue;
        token.tokenIssueDate = [NSDate date];
        token.expiryTimeInSeconds = [[accessToken
                                      valueForKey:@"expires_in"]
                                     intValue];
        token.tokenType = [accessToken valueForKey:@"token_type"];
        [self.context.tokens addObject:token];
    }
    else
    {
        *error = [OMObject
                 createErrorWithCode:OMERR_USER_AUTHENTICATION_FAILED];
        OMLog(@"Did not receive access token after authentication");
    }
}

///////////////////////////////////////////////////////////////////////////////
//Checks for presence of a token in a string
//Used for checking presence of username or password token in a string mainly
//to identify username of authenticating user
///////////////////////////////////////////////////////////////////////////////
- (BOOL) checkForPresenceOfTokens: (NSArray *)tokens inString: (NSString *)string
{
    BOOL found = FALSE;
    
    for (NSString *token in tokens)
    {
        NSRange range = [string rangeOfString:token
                                      options:NSCaseInsensitiveSearch];
        if (range.location == NSNotFound && range.length == 0)
        {
            continue;
        }
        
        found = TRUE;
        break;
    }
    
    return found;
}

@end
