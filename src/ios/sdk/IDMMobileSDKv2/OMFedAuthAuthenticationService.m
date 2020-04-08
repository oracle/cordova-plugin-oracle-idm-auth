/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMFedAuthAuthenticationService.h"
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMFedAuthConfiguration.h"
#import "OMURLProtocol.h"
#import "OMErrorCodes.h"
#import "OMToken.h"
#import "OMWKWebViewClient.h"
#import <WebKit/WebKit.h>
#import "OMCredentialStore.h"
#import "OMWKWebViewCookieHandler.h"
#import "OMCSRFRequestHandler.h"

@interface OMFedAuthAuthenticationService  ()<WKNavigationDelegate>

@property(nonatomic, assign) BOOL isFirstAccess;
@property(nonatomic, strong) NSURL *previousPostURL;
@property(nonatomic, assign) NSUInteger numVisitsToPostURL;
@property(nonatomic, strong) OMWKWebViewClient *wkWebViewClient;
@property(nonatomic, strong) NSString *extractedUsername;

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
    self.isFirstAccess = YES;
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
            NSMutableSet *visitedURLs = [self.mss.cacheDict
                                         valueForKey:OM_VISITED_HOST_URLS];

            [OMWKWebViewCookieHandler clearWkWebViewCookiesForUrls:[visitedURLs allObjects] completionHandler:^{
                [self performSelector:@selector(sendFinishAuthentication:)
                             onThread:self.callerThread
                           withObject:error
                        waitUntilDone:YES];

            }];
        }
        else
        {
            [self clearVisitedHostCookies];
        }
        
    }
    else if (self.configuration.enableWKWebView)
    {
        
        [self syncCookiesToHTTPCookieStore];
    }
    else
    {
        [self processRequiredTokens:&error];
    }
    
    if (!self.configuration.enableWKWebView) {
        
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:YES];
    }

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
    
    if (self.configuration.rememberUsernameAllowed)
    {
        [self storeRememberCredentials:self.authData];
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
#pragma mark WKNavigation Delegates-

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler
{
    NSURL *successURL =  self.configuration.loginSuccessURL;
    NSURL *failureURL = self.configuration.loginFailureURL;
    NSURL *loginURL   = self.configuration.loginURL;
    
    NSURL *url = webView.URL;
    if (url == nil) //defence fix to void crash in Idle timout nil url in MAF
    {
        return;
    }
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
        [self completedAuthentication];

    }
    else if (YES == [OMObject isCurrentURL:URL EqualTo:self.configuration.loginFailureURL])
    {
        NSError *error = [OMObject createErrorWithCode:OMERR_USER_AUTHENTICATION_FAILED];
        [self.authData setValue:error forKey:OM_ERROR];
        [self completedAuthentication];
    }
    else
    {
        if (self.configuration.rememberUsernameAllowed)
        {
            [self injectUsernameToWebView:webView];
            
        }
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
    
    NSArray *usernameTokens = [self userNameTokensList];
    
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
                            self.extractedUsername = username;
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
                     self.extractedUsername = result;
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

#pragma mark -
#pragma mark Tokens extracting methods -

- (BOOL)processRequiredTokens:(NSError**)inerror
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
        if (!self.configuration.enableWKWebView) {
            [self extractTokensFromCookies:requiredCookies error:&error];
        }
        else
        {
            if(@available(iOS 11, *))
            {
                [self extractTokensFromCookies:requiredCookies error:&error];

            }
        }
    }
    
    if (self.configuration.parseTokenRelayResponse)
    {
        OMCSRFRequestHandler *handler = [[OMCSRFRequestHandler alloc] init];
        NSDictionary *jwtInfo = [handler extractTokenRelayTokensWithConfig:self.configuration error:&error];
        
        if (jwtInfo) {
            [self.authData setValue:jwtInfo forKey:OM_TOKENS];
            [self parseTokenRelayResponse:&error];
        }
        
        if (inerror && error)
            *inerror = error;

    }
    
    if (self.extractedUsername)
    {
        self.context.userName = self.extractedUsername;
        [self.authData setValue:self.extractedUsername forKey:OM_USERNAME];
    }
    

    return YES;
}


- (void)extractTokensFromDataRecord:(NSMutableArray*)requiredCookies
                               error:(NSError**)error
{
    [OMWKWebViewCookieHandler cookiesForVisitedHosts:self.context.visitedHosts completionHandler:
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
        self.extractedUsername = principal;
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

- (void)injectUsernameToWebView:(id)webView
{
    __block BOOL usernameInjected = NO;

    NSArray *tokenList = [self userNameTokensList];
    
    [self retrieveRememberCredentials:self.authData];
    NSString *username = [self.authData valueForKey:OM_USERNAME];

    if (!username)
    {
        return;
    }
    
    for (NSString *token in tokenList)
    {
        NSString *fillUsernameJS = [NSString
                                    stringWithFormat:
                                    @"document.getElementById('%@').value = '%@'",
                                    token,username];
        
        if (!self.configuration.enableWKWebView)
        {
            NSString *fillData = [webView stringByEvaluatingJavaScriptFromString:fillUsernameJS];
            
            NSLog(@"fillData = %@ token = %@",fillData,token);
            
            if (NSOrderedSame == [username caseInsensitiveCompare:fillData])
            {
                usernameInjected = YES;
            }

        }
        else
        {
            [webView evaluateJavaScript:fillUsernameJS
                      completionHandler:^(id _Nullable result,
                                          NSError * _Nullable error)
             {
                 if ([result isKindOfClass:[NSString class]] && [result length] > 0)
                 {
                     [self.authData setObject:result
                                       forKey:OM_USERNAME];
                     usernameInjected = YES;
                 }
                 
             }];

        }
        
        if (usernameInjected)
        {
            break;
        }
        
    }

}
- (NSArray*)userNameTokensList
{
    NSArray *usernameTokens = [NSArray arrayWithObjects:@"username",
                               @"uname", @"email", @"uid", @"userid",@"sso_username", nil];
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

    return usernameTokens;
}

- (void) storeRememberCredentials:(NSMutableDictionary *) authnData
{
    if (![authnData count])
    {
        return;
    }
    
    NSString *rememberCredKey = [self.mss rememberCredKey];
    if (![rememberCredKey length])
    {
        return;
    }
    OMMobileSecurityConfiguration *config = self.mss.configuration;
    
    NSString *username = [authnData valueForKey:OM_USERNAME];
    NSString *tenant = [authnData valueForKey:OM_IDENTITY_DOMAIN];
    
    
  if (config.rememberUsernameAllowed)
    {
        OMCredential *currentCredential = [[OMCredential alloc]
                                      initWithUserName:username
                                      password:nil tenantName:tenant
                                      properties:nil];
        [[OMCredentialStore sharedCredentialStore] saveCredential:currentCredential
                                                    forKey:rememberCredKey];
    }
}

- (void) retrieveRememberCredentials:(NSMutableDictionary *) authnData
{
        NSString *rememberCredKey = nil;
        
        rememberCredKey = [self.mss rememberCredKey];
        
        if (![rememberCredKey length] || !authnData)
        {
            return;
        }
        
        OMCredential *cred = [[OMCredentialStore sharedCredentialStore]
                              getCredential:rememberCredKey];
    if (cred.userName) {
        [authnData setValue:cred.userName forKey:OM_USERNAME];

    }
}

- (void)syncCookiesToHTTPCookieStoreProcessed
{
    NSError *errorObj = nil;
    [self processRequiredTokens:&errorObj];
    [self performSelector:@selector(sendFinishAuthentication:)
                 onThread:self.callerThread
               withObject:errorObj
            waitUntilDone:YES];

}

-(void)syncCookiesToHTTPCookieStore {
    
    if (@available(iOS 11, *)) {
        // Use iOS 11 APIs.
        [[[WKWebsiteDataStore defaultDataStore] httpCookieStore] getAllCookies:^(NSArray<NSHTTPCookie *> * cookies) {
            
            for (NSHTTPCookie *cookie in cookies) {
                [[NSHTTPCookieStorage sharedHTTPCookieStorage] setCookie:cookie];
            }
            
            [self syncCookiesToHTTPCookieStoreProcessed];
        }];
        
    } else {
        
        [self syncCookiesToHTTPCookieStoreProcessed];
    }
}

@end
