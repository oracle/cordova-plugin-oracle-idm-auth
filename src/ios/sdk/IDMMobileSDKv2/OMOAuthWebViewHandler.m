/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAuthWebViewHandler.h"
#import "OMDefinitions.h"
#import "OMAuthorizationCodeGrant.h"
#import "OMErrorCodes.h"
#import "OMWKWebViewClient.h"

@interface OMOAuthWebViewHandler ()

@property(nonatomic, strong) OMWKWebViewClient *wkwebViewClient;

@end

@implementation OMOAuthWebViewHandler

- (void)loadRequest:(NSURLRequest*)request;
{
    self.wkwebViewClient = [[OMWKWebViewClient alloc] initWithWKWebView:self.wkwebView callBackDelegate:self];
    [self.wkwebViewClient loadRequest:request];
}

- (void)stopRequest
{
    [self.wkwebViewClient stopRequest];
}

#pragma mark -
#pragma mark WKNavigation Delegates-

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler
{
    NSURL *url = navigationAction.request.URL;
    NSLog(@"url = %@", url);
    NSString *urlScheme = navigationAction.request.URL.scheme;
    
    if ([urlScheme isEqual:self.oauthService.config.redirectURI.scheme])
    {
        self.redirectURIHit = true;
        NSDictionary *responseDict = [self.oauthService
                                      parseFrontChannelResponse:
                                      navigationAction.request.URL];
        [self.oauthService.authData addEntriesFromDictionary:responseDict];
        if ([responseDict objectForKey:@"error"])
        {
            self.oauthService.error = [OMOAuthAuthenticationService
                                       oauthErrorFromResponse:responseDict
                                       andStatusCode:-1];
            self.oauthService.nextStep = OM_NEXT_AUTH_STEP_NONE;
        }
        else
        {
            NSString *authCode = [responseDict objectForKey:@"code"];
            if (authCode)
            {
                ((OMAuthorizationCodeGrant *)self.oauthService.grantFlow).
                authCode = authCode;
                self.oauthService.nextStep = OM_NEXT_EXCHANGE_AUTHZ_CODE;
            }
            else if([responseDict valueForKey:OM_ACCESS_TOKEN])
            {
                [self.oauthService.grantFlow processOAuthResponse:responseDict];
            }
            else
            {
                self.oauthService.error = [OMObject createErrorWithCode:
                                           OMERR_OAUTH_SERVER_ERROR];
                self.oauthService.nextStep = OM_NEXT_AUTH_STEP_NONE;
            }
        }
        [self.oauthService
         performSelector:@selector(sendFinishAuthentication:)
         onThread:self.oauthService.callerThread
         withObject:self.oauthService.error
         waitUntilDone:false];
        [self.wkwebViewClient stopRequest];
    }
}


-(void)webView:(WKWebView *)webView
    didFailProvisionalNavigation:(null_unspecified WKNavigation *)navigation
     withError:(nonnull NSError *)error
{
    NSLog(@" Challenge received = %@",error);
    if (!self.redirectURIHit)
    {
        self.oauthService.nextStep = OM_NEXT_REG_STEP_NONE;
        self.oauthService.error = error;
        [self.oauthService
         performSelector:@selector(sendFinishAuthentication:)
         onThread:self.oauthService.callerThread
         withObject:error
         waitUntilDone:false];
        
        [self.wkwebViewClient stopRequest];
    }

}

@end
