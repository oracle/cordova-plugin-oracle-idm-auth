/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOAuthWebViewHandler.h"
#import "OMDefinitions.h"
#import "OMAuthorizationCodeGrant.h"
#import "OMErrorCodes.h"

@implementation OMOAuthWebViewHandler

-(BOOL)webView:(UIWebView *)webView
shouldStartLoadWithRequest:(NSURLRequest *)request
navigationType:(UIWebViewNavigationType)navigationType
{
    NSString *urlScheme = request.URL.scheme;
    if ([urlScheme isEqual:self.oauthService.config.redirectURI.scheme])
    {
        self.redirectURIHit = true;
        NSDictionary *responseDict = [self.oauthService
                                      parseFrontChannelResponse:
                                      request.URL];
        [self.oauthService.authData addEntriesFromDictionary:responseDict];
        if ([responseDict objectForKey:@"error"])
        {
            self.oauthService.error = [OMOAuthAuthenticationService
                                       oauthErrorFromResponse:responseDict
                                       andStatusCode:0];
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
        webView.delegate = self.previousDelegate;
        return false;
    }
    return true;
}
- (void)webViewDidStartLoad:(UIWebView *)webView
{
    [self.previousDelegate webViewDidStartLoad:webView];
}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
    [self.previousDelegate webViewDidFinishLoad:webView];
}

- (void)webView:(UIWebView *)webView
didFailLoadWithError:(NSError *)error
{
    if (!self.redirectURIHit)
    {
        self.oauthService.nextStep = OM_NEXT_REG_STEP_NONE;
        self.oauthService.error = error;
        [self.oauthService
         performSelector:@selector(sendFinishAuthentication:)
         onThread:self.oauthService.callerThread
         withObject:error
         waitUntilDone:false];
        webView.delegate = self.previousDelegate;
        [self.previousDelegate webView:webView didFailLoadWithError:error];
    }
}
@end
