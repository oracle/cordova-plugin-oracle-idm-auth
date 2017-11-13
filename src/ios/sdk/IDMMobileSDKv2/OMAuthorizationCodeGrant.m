/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthorizationCodeGrant.h"
#import "OMOAuthConfiguration.h"
#import "OMDefinitions.h"
#import <libkern/OSAtomic.h>
#import "OMErrorCodes.h"
#import "OMCryptoService.h"
#import "NSData+OMBase64.h"


NSString *clientAssertionType = @"urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

@implementation OMAuthorizationCodeGrant
- (NSURL *)frontChannelRequestURL
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.oauthService.
                                                        mss.configuration;
    NSString *authEndpoint = [config.authEndpoint absoluteString];
    NSString *clientID = config.clientId;
    NSMutableString *url = [NSMutableString stringWithFormat:
                            @"%@?client_id=%@&response_type=code",
                            authEndpoint,clientID];
    if (config.enablePkce)
    {
        [url appendFormat:@"&code_challenge=%@&code_challenge_method=S256",
         self.codeChallenge];
    }
    NSString *urlString = [self queryParameters:url];
    return [NSURL URLWithString:urlString];
}

- (NSDictionary *)backChannelRequest:(NSDictionary *)authData
{
    OMOAuthConfiguration *config = (OMOAuthConfiguration *)self.oauthService.
                                                        mss.configuration;
    NSString *tokenEndpoint = [config.tokenEndpoint absoluteString];
    NSString *redirectURI = [config.redirectURI absoluteString];
    NSMutableString *requestString = [NSMutableString stringWithFormat:
                                      @"grant_type=authorization_code&code=%@&redirect_uri=%@",
                                      self.authCode,redirectURI];
    if (config.enablePkce)
    {
        [requestString appendFormat:@"&code_verifier=%@",self.codeVerifier];
    }
    
    if (config.isClientRegistrationRequired && [config.clientSecret length] > 0)
    {
        [requestString appendFormat:@"&client_id=%@",config.clientId];
        [requestString appendFormat:@"&client_assertion_type=%@&client_assertion=%@",clientAssertionType,config.clientSecret];
    }
    
    NSDictionary *headerDict = [self backChannelRequestHeader];
    NSString *requestBody = [self backChannelRequestBody:requestString];
    NSMutableDictionary *requestDict = [[NSMutableDictionary alloc] init];
    [requestDict setObject:tokenEndpoint
                    forKey:OM_OAUTH_BACK_CHANNEL_REQUEST_URL];
    [requestDict setObject:requestBody forKey:OM_OAUTH_BACK_CHANNEL_PAYLOAD];
    if(headerDict)
        [requestDict setObject:headerDict forKey:OM_OAUTH_BACK_CHANNEL_HEADERS];
    [requestDict setObject:@"POST" forKey:OM_OAUTH_BACK_CHANNEL_REQUEST_TYPE];
    return requestDict;
}

- (void)processOAuthResponse:(NSDictionary *)urlQueryDict
{
    self.oauthService.frontChannelRequestDone = true;
    if([urlQueryDict objectForKey:@"error"] != nil)
    {
        self.oauthService.error = [OMAuthenticationService
                                   setErrorObject:urlQueryDict
                                   withErrorCode:-1];
        [self.oauthService.delegate didFinishCurrentStep:self
                                                nextStep:OM_NEXT_AUTH_STEP_NONE
                                            authResponse:self.oauthService.authResponse
                                                   error:self.oauthService.error];
        return;
    }
    self.authCode = [urlQueryDict objectForKey:@"code"];
    if(self.authCode != nil)
    {
        [self.oauthService.delegate didFinishCurrentStep:self
                                                nextStep:OM_NEXT_EXCHANGE_AUTHZ_CODE
                                            authResponse:self.oauthService.authResponse
                                                   error:self.oauthService.error];
        return;
    }
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
    __block __weak OMAuthorizationCodeGrant *weakSelf = self;
    
    challenge.authChallengeHandler = ^(NSDictionary *dict,
                                       OMChallengeResponse response) {
        
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
                    weakSelf.authCode = [responseDict objectForKey:@"code"];
                    if (weakSelf.authCode)
                    {
                        weakSelf.oauthService.nextStep = OM_NEXT_EXCHANGE_AUTHZ_CODE;
                        [weakSelf.oauthService
                         performSelector:@selector(sendFinishAuthentication:)
                         onThread:weakSelf.oauthService.callerThread
                         withObject:nil
                         waitUntilDone:false];
                    }
                }
            }
            else if (authService.config.browserMode == OMBrowserModeEmbedded)
            {
                UIWebView *webView = [dict valueForKey:OM_PROP_AUTH_WEBVIEW];
                if ([webView isKindOfClass:[UIWebView class]])
                {
                    
                    NSURLRequest *request =  [[NSURLRequest alloc]
                                              initWithURL:
                                              weakSelf.frontChannelRequestURL];
                    weakSelf.handler.webView = webView;
                    weakSelf.handler.previousDelegate = webView.delegate;
                    webView.delegate = weakSelf.handler;
                    [webView loadRequest:request];
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
            else if (authService.config.browserMode == OMBrowserModeSafariVC)
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
                    weakSelf.authCode = [responseDict objectForKey:@"code"];
                    if (weakSelf.authCode)
                    {
                        weakSelf.oauthService.nextStep = OM_NEXT_EXCHANGE_AUTHZ_CODE;
                        [weakSelf.oauthService
                         performSelector:@selector(sendFinishAuthentication:)
                         onThread:weakSelf.oauthService.callerThread
                         withObject:nil
                         waitUntilDone:false];
                    }
                }
            }
            
            if (nil != error) {
                weakSelf.oauthService.error = error;
                weakSelf.oauthService.nextStep = OM_NEXT_AUTH_STEP_NONE;
                [weakSelf.oauthService
                 performSelector:@selector(sendFinishAuthentication:)
                 onThread:weakSelf.oauthService.callerThread
                 withObject:weakSelf.oauthService.error
                 waitUntilDone:false];
            }
        }
        else
        {
            NSError *error = [OMObject
                              createErrorWithCode:
                              OMERR_USER_CANCELED_AUTHENTICATION];
            
            [weakSelf performSelector:@selector(sendFinishAuthentication:)
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

-(NSString *)codeVerifier
{
    if (!_codeVerifier.length)
    {
        int strlen = rand()%85+43;
        uint8_t indices[strlen];
        char *lookup = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY0123456789-._~";
        int result = SecRandomCopyBytes(kSecRandomDefault, strlen, indices);
        NSMutableString *verifier = [[NSMutableString alloc] init];
        for (int i = 0; i < strlen; i++)
        {
            [verifier appendFormat:@"%c",lookup[indices[i]%66]];
        }
        _codeVerifier = verifier;
    }
    return _codeVerifier;
}

-(NSString *)codeChallenge
{
    if (!_codeChallenge.length)
    {
        NSData *hash = [OMCryptoService SHA256HashData:[self.codeVerifier
                                                        dataUsingEncoding:
                                                        NSUTF8StringEncoding]
                                              outError:nil];
        _codeChallenge = [hash base64EncodedString];
        _codeChallenge = [_codeChallenge stringByReplacingOccurrencesOfString:
                          @"=" withString:@""];
        _codeChallenge = [_codeChallenge stringByReplacingOccurrencesOfString:
                          @"/" withString:@"_"];
        _codeChallenge = [_codeChallenge stringByReplacingOccurrencesOfString:
                          @"+" withString:@"-"];
    }
    return _codeChallenge;
}
@end
