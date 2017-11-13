/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMResourceOwnerGrant.h"
#import "OMDefinitions.h"
#import "OMOAuthConfiguration.h"
#import "OMAuthenticationChallenge.h"
#import "OMAuthenticationService.h"
#import <libkern/OSAtomic.h>
#import "OMObject.h"
#import "OMCredential.h"
#import "OMCredentialStore.h"
#import "OMErrorCodes.h"
#import "OMAuthenticationContext.h"

@implementation OMResourceOwnerGrant
-(NSDictionary *)backChannelRequest:(NSDictionary *)authData
{
    
    [self.oauthService retrieveRememberCredentials:self.oauthService.authData];
    if (![[self.oauthService.authData valueForKey:OM_USERNAME] length])
    {
        [self.oauthService.authData setValue:[NSNull null] forKey:OM_USERNAME];
    }
    if (![[self.oauthService.authData valueForKey:OM_PASSWORD] length])
    {
        [self.oauthService.authData setValue:[NSNull null] forKey:OM_PASSWORD];
    }
    
    [self performSelector:@selector(sendChallenge:)
                 onThread:self.oauthService.callerThread
               withObject:nil
            waitUntilDone:false];
    while (false == OSAtomicCompareAndSwap32(1, 0, &_finished))
    {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate distantFuture]];
    }
    self.oauthService.userName = [self.oauthService.authData
                          valueForKey:OM_USERNAME];
    self.oauthService.password = [self.oauthService.authData
                          valueForKey:OM_PASSWORD];

    NSString *tokenEndpoint = [((OMOAuthConfiguration *)self.oauthService.mss.
                                configuration).tokenEndpoint absoluteString];
    NSMutableString *requestString = [NSMutableString stringWithFormat:
                                @"grant_type=password&username=%@&password=%@",
                                      self.oauthService.userName,
                                      self.oauthService.password];
    NSString *requestBody = [self backChannelRequestBody:requestString];
    NSDictionary *headerDict = [self backChannelRequestHeader];
    NSMutableDictionary *requestDict = [[NSMutableDictionary alloc] init];
    [requestDict setObject:tokenEndpoint
                    forKey:OM_OAUTH_BACK_CHANNEL_REQUEST_URL];
    [requestDict setObject:requestBody forKey:OM_OAUTH_BACK_CHANNEL_PAYLOAD];
    if(headerDict != nil)
    {
        [requestDict setObject:headerDict forKey:OM_OAUTH_BACK_CHANNEL_HEADERS];
    }
    [requestDict setObject:@"POST" forKey:OM_OAUTH_BACK_CHANNEL_REQUEST_TYPE];
    return requestDict;
}

-(void)OAuthBackChannelResponse:(NSURLResponse *)urlResponse
                           data:(id)data
                       andError:(NSError *)error
{
    [super OAuthBackChannelResponse:urlResponse data:data andError:error];
    if(!self.oauthService.error)
    {
        [self.oauthService storeRememberCredentials:self.oauthService.authData];
    }
    
}

-(void)sendChallenge:(id)object
{
    OMAuthenticationChallenge *challenge = [[OMAuthenticationChallenge alloc] init];
    NSMutableDictionary *challengeDict = [NSMutableDictionary
                                          dictionaryWithDictionary:self.oauthService.authData];
    challenge.challengeType = OMChallengeUsernamePassword;
    challenge.authData = challengeDict;
    __block __weak OMResourceOwnerGrant *weakSelf = self;
    challenge.authChallengeHandler = ^(NSDictionary *dict,
                                            OMChallengeResponse response)
    {
        OMOAuthAuthenticationService *authService = weakSelf.oauthService;
        
        if (response == OMProceed)
        {
            id username = [dict valueForKey:OM_USERNAME];
            id password = [dict valueForKey:OM_PASSWORD];
            
            if(![weakSelf.oauthService.config isValidString:username] ||
               ![weakSelf.oauthService.config isValidString:password])
            {
                [weakSelf.oauthService.authData setValue:[NSNull null]
                                                  forKey:OM_USERNAME];
                [weakSelf.oauthService.authData setValue:[NSNull null]
                                                  forKey:OM_PASSWORD];
                NSError *error = [OMObject createErrorWithCode:
                                  OMERR_INVALID_USERNAME_PASSWORD];
                [weakSelf.oauthService.authData setObject:error
                                      forKey:OM_MOBILESECURITY_EXCEPTION];
                
                [weakSelf sendChallenge:nil];
            }
            else
            {
                authService.authData = [NSMutableDictionary
                                        dictionaryWithDictionary:dict];

                if([weakSelf.oauthService.authData objectForKey:OM_ERROR])
                {
                    [weakSelf.oauthService.authData removeObjectForKey:OM_ERROR];
                }
            }

        }
        else
        {
            NSError *error = [OMObject createErrorWithCode:
                              OMERR_USER_CANCELED_AUTHENTICATION];
            [authService performSelector:@selector(sendFinishAuthentication:)
                             onThread:authService.callerThread
                           withObject:error
                        waitUntilDone:YES];
        }
        [authService storeRememberCredentialsPreference:dict];
        OSAtomicCompareAndSwap32(0, 1, &_finished);
    };
    self.oauthService.challenge = challenge;
    [self.oauthService.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                           authResponse:nil
                                  error:nil];
}

- (BOOL)doOfflineAuthentication:(NSURL *)offlineHost
{
    BOOL offlineAuth = false;
    NSUInteger connectivityMode = self.oauthService.request.connectivityMode ?
    self.oauthService.request.connectivityMode:
    self.oauthService.config.connectivityMode;
    switch (connectivityMode)
    {
            // Always authenticate with server
        case OMConnectivityOnline:
            offlineAuth = false;
            break;
            // Authenticate locally if available
        case OMConnectivityOffline:
            offlineAuth = true;
            break;
            // Authenticate with server if online
        case OMConnectivityAuto:
            // Fall Through
        default:
            if (![OMObject isHostReachable:offlineHost.host])
                offlineAuth = true;
    }
    if (offlineAuth)
    {
        OMAuthenticationContext *localContext = [self.oauthService.mss.cacheDict
                                                 objectForKey:self.oauthService.mss.authKey];
        if (localContext)
        {
            self.oauthService.userName = [self.oauthService.authData
                                          valueForKey:OM_USERNAME];
            self.oauthService.password = [self.oauthService.authData
                                          valueForKey:OM_PASSWORD];
            if (![self.oauthService.userName length] || ![self.oauthService.password length])
            {
                if (![self.oauthService.userName length])
                {
                    [self.oauthService.authData setValue:[NSNull null] forKey:OM_USERNAME];
                }
                if (![self.oauthService.password length])
                {
                    [self.oauthService.authData setValue:[NSNull null] forKey:OM_PASSWORD];
                }
                [self performSelector:@selector(sendChallenge:)
                             onThread:self.oauthService.callerThread
                           withObject:nil
                        waitUntilDone:false];
                while (false == OSAtomicCompareAndSwap32(1, 0, &_finished))
                {
                    [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                             beforeDate:[NSDate distantFuture]];
                }
            }
            self.oauthService.userName = [self.oauthService.authData
                                          valueForKey:OM_USERNAME];
            self.oauthService.password = [self.oauthService.authData
                                          valueForKey:OM_PASSWORD];
            if (![localContext.userName isEqualToString:self.oauthService.userName])
            {
                return false;
            }
            else
            {
                OMCredential *offlineCred = [[OMCredentialStore
                                              sharedCredentialStore]
                                             getCredential:
                                             self.oauthService.mss.offlineAuthKey];
                if ([self.oauthService.userName isEqual:offlineCred.userName] &&
                    [self.oauthService verifyPassword:self.oauthService.password
                   withProtectedPassword:offlineCred.userPassword
                                outError:nil])
                {
                    self.oauthService.context = localContext;
                    self.oauthService.context.authMode = OMLocal;
                    [self.oauthService.context resetTimer:OMIdleTimer]?
                                nil : [self.oauthService.context startTimers];
                    
                    return true;
                }
                else if ([self.oauthService isMaxRetryReached:
                          self.oauthService.config.authenticationRetryCount])
                {
                    [self.oauthService resetMaxRetryCount];
                    [[OMCredentialStore sharedCredentialStore]
                     deleteCredential:
                     self.oauthService.mss.offlineAuthKey];
                    [self.oauthService.mss.cacheDict
                     removeObjectForKey:self.oauthService.mss.authKey];
                    self.oauthService.error = [OMObject createErrorWithCode:
                                               OMERR_MAX_RETRIES_REACHED];
                    return true;
                }
                else
                {
                    [self.oauthService.authData removeObjectForKey:OM_PASSWORD];
                    return [self doOfflineAuthentication:offlineHost];
                    
                }
            }
        }
    }
    return false;
}
@end
