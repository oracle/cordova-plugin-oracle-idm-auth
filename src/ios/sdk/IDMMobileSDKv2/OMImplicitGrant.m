/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMImplicitGrant.h"
#import "OMOAuthConfiguration.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"

@implementation OMImplicitGrant
- (NSURL *)frontChannelRequestURL
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.oauthService.
    mss.configuration;
    NSString *authEndpoint = [config.authEndpoint absoluteString];
    NSString *clientID = config.clientId;
    NSMutableString *url = [NSMutableString stringWithFormat:
                            @"%@?client_id=%@&response_type=token",
                            authEndpoint,clientID];
    NSString *urlString = [self queryParameters:url];
    return [NSURL URLWithString:urlString];
}

- (void)processOAuthResponse:(NSDictionary *)urlQueryDict
{
    self.oauthService.frontChannelRequestDone = true;
    if([urlQueryDict objectForKey:@"error"] != nil)
    {
        self.oauthService.error = [OMAuthenticationService
                                   setErrorObject:urlQueryDict
                                   withErrorCode:-1];
        return;
    }
    self.oauthService.accessToken = [urlQueryDict objectForKey:@"access_token"];
    self.oauthService.expiryTimeInSeconds =
    [[urlQueryDict objectForKey:@"expires_in"] intValue];
    [self.oauthService setAuthContext];
}

-(void)sendFrontChannelChallenge
{
    OMAuthenticationChallenge *challenge = [[OMAuthenticationChallenge alloc] init];
    NSMutableDictionary *challengeDict = [NSMutableDictionary
                                          dictionaryWithDictionary:self.oauthService.authData];
    if (self.oauthService.config.browserMode == OMBrowserModeExternal)
    {
        [challengeDict setObject:[NSNull null] forKey:@"frontChannelResponse"];
        challenge.challengeType = OMChallengeExternalBrowser;
    }
    else if(self.oauthService.config.browserMode == OMBrowserModeEmbedded)
    {
        [challengeDict setObject:[NSNull null] forKey:OM_PROP_AUTH_WEBVIEW];
        challenge.challengeType = OMChallengeEmbeddedBrowser;
        OMOAuthWebViewHandler *handler = [[OMOAuthWebViewHandler
                                           alloc] init];
        handler.oauthService = self.oauthService;
        self.handler = handler;
    }
    else if(self.oauthService.config.browserMode == OMBrowserModeSafariVC)
    {
        [challengeDict setObject:[NSNull null] forKey:@"frontChannelResponse"];
        challenge.challengeType = OMChallengeEmbeddedSafari;
    }
    
    challenge.authData = challengeDict;
    __block __weak OMImplicitGrant *weakSelf = self;
    
    challenge.authChallengeHandler = ^(NSDictionary *dict,
                                       OMChallengeResponse response)
    {
        
        OMOAuthAuthenticationService *authService = weakSelf.oauthService;
        if (response == OMProceed)
        {
            NSError *error = nil;
            if (authService.config.browserMode == OMBrowserModeExternal)
            {
                NSURL *frontChannelResponse = [dict
                                        valueForKey:@"frontChannelResponse"];
                NSDictionary *responseDict = [weakSelf.oauthService
                                              parseFrontChannelResponse:
                                              frontChannelResponse];
                [weakSelf.oauthService.authData
                 addEntriesFromDictionary:responseDict];
                
                if ([responseDict objectForKey:@"error"])
                {
                    error = [OMAuthenticationService setErrorObject:responseDict
                                                      withErrorCode:-1];
                }
                else
                {
                    [weakSelf processOAuthResponse:responseDict];
                }
                [weakSelf.oauthService
                 performSelector:@selector(sendFinishAuthentication:)
                 onThread:weakSelf.oauthService.callerThread
                 withObject:error
                 waitUntilDone:YES];
            }
            else if (authService.config.browserMode == OMBrowserModeEmbedded)
            {
                WKWebView *webView = [dict valueForKey:OM_PROP_AUTH_WEBVIEW];
                if ([webView isKindOfClass:[WKWebView class]])
                {
                    
                    NSURLRequest *request =  [[NSURLRequest alloc]
                                              initWithURL:
                                              weakSelf.frontChannelRequestURL];
                    weakSelf.handler.wkwebView = webView;
                    [weakSelf.handler loadRequest:request];
                }
                else
                {
                    NSError *error = [OMObject createErrorWithCode:
                                      OMERR_WEBVIEW_REQUIRED];
                    
                    [weakSelf.oauthService
                     performSelector:@selector(sendFinishAuthentication:)
                     onThread:weakSelf.oauthService.callerThread
                     withObject:error
                     waitUntilDone:YES];
                    
                }
            }
        }
        else
        {
            NSError *error = [OMObject
                              createErrorWithCode:
                              OMERR_USER_CANCELED_AUTHENTICATION];
            
            [weakSelf.oauthService
            performSelector:@selector(sendFinishAuthentication:)
            onThread:weakSelf.oauthService.callerThread
            withObject:error
            waitUntilDone:YES];
        }
    };
    self.oauthService.challenge = challenge;
    [self.oauthService.delegate didFinishCurrentStep:self
                                            nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                                        authResponse:nil
                                               error:nil];
    
}

- (void)cancelAuthentication
{
    [self.handler stopRequest];
}

@end
