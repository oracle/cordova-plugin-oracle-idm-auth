/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMHTTPBasicAuthenticationService.h"
#import "OMMobileSecurityConfiguration.h"
#import "OMHTTPBasicConfiguration.h"
#import "OMAuthenticationContext.h"
#import "OMObject.h"
#import "OMMobileSecurityService.h"
#import "OMAuthenticationManager.h"
#import "OMAuthenticationChallenge.h"
#import "OMDefinitions.h"
#import "OMCredentialStore.h"
#import "OMCredential.h"
#import "OMCryptoService.h"
#import "OMErrorCodes.h"
#import "OMClientCertChallangeHandler.h"

@implementation OMHTTPBasicAuthenticationService
-(void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError *__autoreleasing *)error
{    
    self.requestPauseSemaphore = dispatch_semaphore_create(0);
    self.usePreviousCredential = NO;
    self.configuration = (OMHTTPBasicConfiguration *)self.mss.configuration;
    self.callerThread = [NSThread currentThread];
    [self performSelectorInBackground:
     @selector(performAuthenticationInBackground:)
                           withObject:authData];
}

-(void)performAuthenticationInBackground:(NSMutableDictionary *)authData
{
    self.authData = authData;
    [self retrieveRememberCredentials:self.authData];
    
    if (![self shouldPerformAutoLogin:self.authData])
 {
     NSString *masked  = [self maskPassword:
                          [self.authData valueForKey:OM_PASSWORD]];
     if ([masked length])
     {
         [self.authData setObject:masked forKey:OM_PASSWORD];
     }
}
    
    if (self.configuration.offlineAuthAllowed &&
        [self performOfflineAuthentication])
    {
        NSError *error = nil;
        
        if (self.maxRetryError)
        {
            error = [OMObject createErrorWithCode:OMERR_MAX_RETRIES_REACHED];
            self.maxRetryError = NO;
        }
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:false];
    }
    else
    {
        [self performOnlineAuthentication:authData];
    }
}
-(BOOL)performOfflineAuthentication
{
    OMConnectivityMode connectivityMode = self.request.connectivityMode?
    self.request.connectivityMode:
    self.configuration.connectivityMode;
    BOOL offlineAuth = false;
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
            if ((![OMObject checkConnectivityToHost:self.configuration.loginURL]))
                offlineAuth = true;
    }
    
    if (!offlineAuth)
    {
        OMAuthenticationContext *localContext = [self.mss.cacheDict
                                                 objectForKey:self.mss.authKey];
        if(localContext)
        {
            NSURLResponse *response= nil;
            NSError *error = nil;
            
            NSMutableURLRequest *urlRequest = [[NSMutableURLRequest alloc]
                                        initWithURL:self.configuration.loginURL];
            [urlRequest setCachePolicy:
             NSURLRequestReloadIgnoringLocalAndRemoteCacheData];
            [urlRequest setAllHTTPHeaderFields:[self requestHeaders]];
            [urlRequest setHTTPMethod:@"GET"];
            [urlRequest setTimeoutInterval:20];
            
            [OMHTTPBasicAuthenticationService
                                        sendSynchronousRequest:urlRequest
                                        returningResponse:&response
                                        error:&error];
            
            /* If cookies are valid do offline auth */
            if(([(NSHTTPURLResponse*)response statusCode] / 100) == 2)
            {
                offlineAuth = true;
            }

        }
        
    }

    if (offlineAuth)
    {
        if (![self.mss.authManager isAuthRequestInProgress])
        {
            return NO;
        }
        OMAuthenticationContext *localContext = [self.mss.cacheDict
                                                 objectForKey:self.mss.authKey];
        if (!localContext)
        {
            localContext = [[OMAuthenticationContext alloc]
                            initWithMss:self.mss];
        }
        if (![self shouldPerformAutoLogin:self.authData])
        {
            self.userName = [self.authData valueForKey:OM_USERNAME];
            self.password = [self.authData valueForKey:OM_PASSWORD];
            self.identityDomain = [self.authData
                                   valueForKey:OM_IDENTITY_DOMAIN];
            if (![self.userName length])
            {
                [self.authData setValue:[NSNull null] forKey:OM_USERNAME];
            }
            
            if (![self.password length])
            {
                [self.authData setValue:[NSNull null] forKey:OM_PASSWORD];
            }
            else
            {
                [self.authData setValue:[self maskPassword:
                                         [self.authData valueForKey:OM_PASSWORD]]
                                 forKey:OM_PASSWORD];
                
            }
            if (![self.identityDomain length] &&
                self.configuration.collectIdentityDomain)
            {
                [self.authData setValue:[NSNull null]
                                 forKey:OM_IDENTITY_DOMAIN];
            }
            if (![self shouldPerformAutoLogin:self.authData])
            {
                [self performSelector:@selector(sendChallenge:)
                             onThread:self.callerThread
                           withObject:nil
                        waitUntilDone:false];
                dispatch_semaphore_wait(self.requestPauseSemaphore,
                                        DISPATCH_TIME_FOREVER);

            }
            
        }
        if (![self.mss.authManager isAuthRequestInProgress])
        {
            return NO;
        }

        self.userName = [self.authData valueForKey:OM_USERNAME];
        self.password = [self unMaskPassword:[self.authData
                                              valueForKey:OM_PASSWORD]];
        self.identityDomain = [self.authData
                               valueForKey:OM_IDENTITY_DOMAIN];
        NSString *key = [self.mss
                         offlineAuthenticationKeyWithIdentityDomain:
                         self.identityDomain
                         username:self.userName];
        OMCredential *offlineCred = [[OMCredentialStore
                                      sharedCredentialStore]
                                     getCredential:key];
        // if there are no offline creds(username did not match)
        // for the user then continue with online
        if (!offlineCred)
        {
            //clear session cookies before going online
            self.usePreviousCredential = YES;
            [localContext clearCookies:false];
            return false;
        }
        // if creds match then populate auth context
        else if ([self.userName isEqual:offlineCred.userName] &&
                 [self verifyPassword:self.password
                withProtectedPassword:offlineCred.userPassword
                             outError:nil])
        {
            [self resetMaxRetryCount];
            self.context = localContext;
            self.context.userName = self.userName;
            self.context.authMode = OMLocal;
            self.context.offlineCredentialKey = key;
            [self.mss.cacheDict setObject:self.context
                                   forKey:self.mss.authKey];
            [self storeRememberCredentials:self.authData];
            return true;
        }
        //creds did not match and we max retries has happened
        else if([self isMaxRetryReached:
                 self.configuration.authenticationRetryCount])
        {
            self.maxRetryError = YES;
            [self.context clearCookies:FALSE];
            [self resetMaxRetryCount];
            [[OMCredentialStore sharedCredentialStore]
             deleteCredential:key];
            [self.mss.cacheDict removeObjectForKey:self.mss.authKey];
            self.usePreviousCredential = YES;
            return false;
        }
        else
        {
            NSError *error = [self invalidCredsError];
            [self.authData setObject:error
                              forKey:OM_MOBILESECURITY_EXCEPTION];
            [self.authData setValue:@"" forKey:OM_PASSWORD];
            return [self performOfflineAuthentication];
        }
    }
    return false;
}

-(void)performOnlineAuthentication:(NSMutableDictionary *)authData
{
    if (![self.mss.authManager isAuthRequestInProgress])
    {
        return;
    }

    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration
                                                defaultSessionConfiguration];
    sessionConfig.requestCachePolicy = NSURLRequestReloadIgnoringCacheData;

    NSDictionary *headersDict = [self requestHeaders];
    if (headersDict)
    {
        [sessionConfig setHTTPAdditionalHeaders:headersDict];
    }
    
    if (self.configuration.identityDomainInHeader
        && self.identityDomain == nil)
    {
        self.usePreviousCredential = YES;
        [self performSelector:@selector(sendChallenge:)
                     onThread:self.callerThread
                   withObject:nil
                waitUntilDone:false];
        dispatch_semaphore_wait(self.requestPauseSemaphore,
                                DISPATCH_TIME_FOREVER);
        NSString *identityDomain = [self.authData valueForKey:OM_IDENTITY_DOMAIN];

        if (identityDomain)
        {
            NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithDictionary:sessionConfig.HTTPAdditionalHeaders];
            
            NSString *headerName = (self.configuration.identityDomainHeaderName)
            ? self.configuration.identityDomainHeaderName :
            OM_DEFAULT_IDENTITY_DOMAIN_HEADER;
            
            [dict setObject:identityDomain forKey:headerName];
            [sessionConfig setHTTPAdditionalHeaders:dict];

        }

    }
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig
                                                          delegate:self
                                                     delegateQueue:nil];
    [self.context.visitedHosts addObject:self.configuration.loginURL];

    OMAuthenticationContext *localContext = [self.mss.cacheDict
                                             objectForKey:self.mss.authKey];

    [localContext stopTimers];
    
   self.sessionDataTask = [session dataTaskWithURL:self.configuration.loginURL
            completionHandler:^(NSData * _Nullable data,
                                NSURLResponse * _Nullable response,
                                NSError * _Nullable error)
    {
        NSSet *requiredTokens = self.configuration.requiredTokens;
        NSError *authError = nil;
        if (!self.authChallengeReceived)
        {
            authError = [OMObject
                         createErrorWithCode:OMERR_LOGIN_URL_IS_INVALID];
        }
        if (error && self.maxRetryError)
        {
            authError = [OMObject createErrorWithCode:
                                   OMERR_MAX_RETRIES_REACHED];
            if ([self shouldPerformAutoLogin:self.authData])
            {
                
                [[NSUserDefaults standardUserDefaults] setObject:[NSNumber numberWithBool:false]
                             forKey:[NSString stringWithFormat:@"%@_%@",
                                     self.mss.rememberCredKey,OM_AUTH_SUCCESS]];
                [[NSUserDefaults standardUserDefaults] synchronize];

            }

        }
        else if (error)
        {
            authError = error;

        }
        else if (![self isRequiredTokens:requiredTokens
                                presentFor:self.context.visitedHosts])
        {
            authError = [OMObject createErrorWithCode:
                         OMERR_USER_AUTHENTICATION_FAILED];
        }
        else if(([(NSHTTPURLResponse*)response statusCode] / 100) != 2)
        {
            authError = [self invalidCredsError];
        }
        
        if (authError)
        {
            self.context = nil;
            [self.mss.cacheDict removeObjectForKey:self.mss.authKey];
        }
        else
        {
            [self storeRememberCredentials:self.authData];
            self.context.userName = [self.authData valueForKey:OM_USERNAME];
            self.context.authMode = OMRemote;
            [self.mss.cacheDict setObject:self.context forKey:self.mss.authKey];
            if (self.configuration.offlineAuthAllowed)
            {
                self.userName = [self.authData valueForKey:OM_USERNAME];
                self.password = [self.authData valueForKey:OM_PASSWORD];
                self.identityDomain = [self.authData
                                       valueForKey:OM_IDENTITY_DOMAIN];
                NSString *key = [self.mss
                                 offlineAuthenticationKeyWithIdentityDomain:
                                 self.identityDomain
                                 username:self.userName];
                self.context.offlineCredentialKey = key;
                NSString *protectedPassword =
                                [self protectPassword:self.password
                                         cryptoScheme:self.configuration.cryptoScheme
                                             outError:nil];
                OMCredential *credential = [[OMCredential alloc]
                                            initWithUserName:self.userName
                                            password:protectedPassword
                                            tenantName:self.identityDomain
                                            properties:nil];
                [[OMCredentialStore sharedCredentialStore]
                 saveCredential:credential
                forKey:key];
                
            }
        }
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:authError
                waitUntilDone:false];
    }];
    [self.sessionDataTask resume];
    [session finishTasksAndInvalidate];
    
}


-(void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
       newRequest:(NSURLRequest *)request
completionHandler:(void (^)(NSURLRequest * _Nullable))completionHandler
{
    if ([response.URL.scheme isEqual:@"https"] &&
        [request.URL.scheme isEqual:@"http"])
    {
        __block __weak OMHTTPBasicAuthenticationService *weakself = self;
        __block dispatch_semaphore_t blockSemaphore = self.requestPauseSemaphore;

        self.challenge = [[OMAuthenticationChallenge alloc] init];
        NSMutableDictionary *challengeDict = [NSMutableDictionary
                                              dictionaryWithDictionary:self.authData];
        [challengeDict removeObjectForKey:OM_PASSWORD];
        [challengeDict setObject:[NSNumber numberWithInt:OMHttpsToHttpRedirect]
                          forKey:OM_INVALID_REDIRECT];
        self.challenge.authData = challengeDict;
        self.challenge.challengeType = OMChallengeInvalidRedirect;
        self.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                               OMChallengeResponse response)
        {
            if (response == OMProceed)
            {
                // as of now just unlock the thread
            }
            else
            {
                [weakself.sessionDataTask cancel];
                //Cancels an asynchronous load of a request. After this method is called,
                //the connection makes no further delegate method calls.
                //So release connection to complete stop
                [weakself.delegate didFinishCurrentStep:weakself
                                              nextStep:OM_NEXT_AUTH_STEP_NONE
                                          authResponse:nil
                                                 error:[OMObject createErrorWithCode:
                                                        OMERR_USER_CANCELED_AUTHENTICATION]];
            }
            dispatch_semaphore_signal(blockSemaphore);

        };
        [self.delegate didFinishCurrentStep:self
                                   nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                               authResponse:nil
                                      error:nil];

        dispatch_semaphore_wait(self.requestPauseSemaphore,
                                DISPATCH_TIME_FOREVER);
    }
    [self.context.visitedHosts addObject:request.URL];
    completionHandler(request);
}

-(void)sendFinishAuthentication:(id)object
{
    if (object)
    {
        self.context = nil;
    }
    [self.context setIsLogoutFalseCalled:NO];
    [self.context startTimers];
    self.context.identityDomain = self.identityDomain;
    [self.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_NONE
                           authResponse:nil
                                  error:object];
}

-(void)sendChallenge:(id)object
{
    self.challenge = [[OMAuthenticationChallenge alloc] init];
    NSMutableDictionary *challengeDict = [NSMutableDictionary
                                        dictionaryWithDictionary:self.authData];
    [challengeDict setObject:[NSNumber numberWithBool:self.request.forceAuth]
                      forKey:OM_FORCE_AUTH];
    [challengeDict removeObjectForKey:OM_AUTH_SUCCESS];
    self.challenge.authData = challengeDict;
    self.challenge.challengeType = OMChallengeUsernamePassword;
    __block __weak OMHTTPBasicAuthenticationService *weakSelf = self;
    __block dispatch_semaphore_t blockSemaphore = self.requestPauseSemaphore;

    self.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                            OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            if (weakSelf.configuration.collectIdentityDomain)
            {
                [weakSelf.authData addEntriesFromDictionary:dict];
            }
            else
            {
                NSMutableDictionary *inDict = [NSMutableDictionary
                                               dictionaryWithDictionary:dict];
                [inDict removeObjectForKey:OM_IDENTITY_DOMAIN];
                [weakSelf.authData addEntriesFromDictionary:inDict];
            }
                id username = [weakSelf.authData valueForKey:OM_USERNAME];
                id password = [weakSelf.authData valueForKey:OM_PASSWORD];
                id tenant = [weakSelf.authData valueForKey:OM_IDENTITY_DOMAIN];
                
                if(![weakSelf.configuration isValidString:username] ||
                   ![weakSelf.configuration isValidString:password])
                {
                    [weakSelf.authData setValue:[NSNull null] forKey:OM_USERNAME];
                    [weakSelf.authData setValue:[NSNull null] forKey:OM_PASSWORD];
                    NSError *error = [OMObject createErrorWithCode:
                                      OMERR_INVALID_USERNAME_PASSWORD];
                    [weakSelf.authData setObject:error
                                          forKey:OM_MOBILESECURITY_EXCEPTION];
                    
                    [weakSelf sendChallenge:nil];
                    return;
                }
                else if(weakSelf.configuration.collectIdentityDomain &&
                        ![weakSelf.configuration isValidString:tenant])
                {
                    NSError *error = [OMObject createErrorWithCode:
                                      OMERR_NO_IDENTITY];
                    [weakSelf.authData setValue:[NSNull null] forKey:OM_IDENTITY_DOMAIN];

                    [weakSelf.authData setObject:error
                                          forKey:OM_MOBILESECURITY_EXCEPTION];
                    
                    [weakSelf sendChallenge:nil];
                    return;

                }
                else
                {
                    if([weakSelf.authData objectForKey:OM_ERROR])
                    {
                        [weakSelf.authData removeObjectForKey:OM_ERROR];
                    }
                }
      
            if (tenant == [NSNull null])
            {
                [weakSelf.authData removeObjectForKey:OM_IDENTITY_DOMAIN];
            }
            NSString *unmask = [weakSelf unMaskPassword:[weakSelf.authData
                                                    valueForKey:OM_PASSWORD]];
            [weakSelf.authData setObject:unmask forKey:OM_PASSWORD];
            [weakSelf storeRememberCredentialsPreference:weakSelf.authData];
        }
        else
        {
            [weakSelf cancelAuthentication];
        }
        dispatch_semaphore_signal(blockSemaphore);

    };
    
    [self.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                           authResponse:nil
                                  error:nil];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                             NSURLCredential *credential))completionHandler
{
    NSString *challengeType = challenge.protectionSpace.authenticationMethod;
    if ([challengeType isEqual:NSURLAuthenticationMethodHTTPBasic] ||
        [challengeType isEqual:NSURLAuthenticationMethodDefault])
    {
        self.authChallengeReceived = true;
        
        if (challenge.previousFailureCount > 0 &&
            challenge.previousFailureCount <
            self.configuration.authenticationRetryCount)
        {
            NSError *error = [self invalidCredsError];
            [self.authData setObject:error
                              forKey:OM_MOBILESECURITY_EXCEPTION];
            [self.authData setObject:[NSNumber numberWithInteger:
                                      challenge.previousFailureCount]
                              forKey:OM_RETRY_COUNT];
            
        }
        else if (challenge.previousFailureCount >=
                 self.configuration.authenticationRetryCount)
        {
            self.maxRetryError = YES;
            [self resetMaxRetryCount];
            [task cancel];
            return;
        }
        if (![self shouldPerformAutoLogin:self.authData])
        {
            if (![[self.authData valueForKey:OM_USERNAME] length])
            {
                [self.authData setValue:[NSNull null] forKey:OM_USERNAME];
            }
            
            if (![[self.authData valueForKey:OM_PASSWORD] length])
            {
                [self.authData setValue:[NSNull null] forKey:OM_PASSWORD];
            }
            
            if (![[self.authData valueForKey:OM_IDENTITY_DOMAIN] length] &&
                self.configuration.collectIdentityDomain)
            {
                [self.authData setValue:[NSNull null] forKey:OM_IDENTITY_DOMAIN];
            }
        
            if (!self.usePreviousCredential)
            {
                [self performSelector:@selector(sendChallenge:)
                             onThread:self.callerThread
                           withObject:nil
                        waitUntilDone:false];
                
                dispatch_semaphore_wait(self.requestPauseSemaphore,
                                        DISPATCH_TIME_FOREVER);
            }
            else
            {
                self.usePreviousCredential = NO; //Used so reset it
            }

        }
        else
        {
            self.password = [self unMaskPassword:[self.authData
                                                  valueForKey:OM_PASSWORD]];
            [self.authData setObject:self.password forKey:OM_PASSWORD];
            
        }
        
        NSString *userName = [self.authData
                              valueForKey:OM_USERNAME];
        self.password = [self.authData valueForKey:OM_PASSWORD];
        
        if (self.configuration.collectIdentityDomain && !
            self.configuration.identityDomainInHeader)
        {
            NSString *idDomain = [self.authData valueForKey:OM_IDENTITY_DOMAIN];
            
            if (idDomain)
            {
                userName =  [NSString stringWithFormat:@"%@.%@",
                             idDomain,userName];
            }
            
        }
        
        NSURLCredential *credential = [NSURLCredential
                                       credentialWithUser:userName
                                       password:self.password
                                       persistence:NSURLCredentialPersistenceNone];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        
    }
    else if ([challengeType isEqualToString:NSURLAuthenticationMethodClientCertificate ])
    {
        [[OMClientCertChallangeHandler sharedHandler]
         doClientTrustForAuthenticationChallenge:challenge
         challengeReciver:self completionHandler:completionHandler];
        
    }
    else if ([challengeType isEqualToString:NSURLAuthenticationMethodServerTrust ])
    {
        [[OMClientCertChallangeHandler sharedHandler]
         doServerTrustForAuthenticationChallenge:challenge
         challengeReciver:self completionHandler:completionHandler];
    }
    else
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                          nil);
    }

    
}

+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request
                 returningResponse:(__autoreleasing NSURLResponse **)responsePtr
                             error:(__autoreleasing NSError **)errorPtr {
    dispatch_semaphore_t    sem;
    __block NSData *        result;
    
    result = nil;
    
    sem = dispatch_semaphore_create(0);
    
    [[[NSURLSession sharedSession] dataTaskWithRequest:request
                                     completionHandler:^(NSData *data,
                                                         NSURLResponse *response,
                                                         NSError *error)
    {
                     if (errorPtr != NULL)
                     {
                         *errorPtr = error;
                     }

                     if (responsePtr != NULL)
                     {
                         *responsePtr = response;
                     }
        
                     if (error == nil)
                     {
                         result = data;  
                     }  
                    dispatch_semaphore_signal(sem);
    }] resume];
    
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);  
    
    return result;  
}

- (NSDictionary *)requestHeaders
{
    NSMutableDictionary *headerDict = [NSMutableDictionary
                                       dictionaryWithDictionary:
                                       self.configuration.customHeaders];
   
    if (self.configuration.identityDomainInHeader &&
        self.configuration.identityDomain)
    {
        NSString *headerName = (self.configuration.identityDomainHeaderName)
        ? self.configuration.identityDomainHeaderName :
        OM_DEFAULT_IDENTITY_DOMAIN_HEADER;
        [headerDict setObject:self.configuration.identityDomain forKey:headerName];
    }
    
    return headerDict;
}

- (void)cancelAuthentication
{
    if (self.sessionDataTask && self.sessionDataTask.state == NSURLSessionTaskStateRunning)
    {
        [self.sessionDataTask cancel];
    }
    else
    {
        NSError *error = [OMObject
                          createErrorWithCode:OMERR_USER_CANCELED_AUTHENTICATION];
        
        [self performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.callerThread
                   withObject:error
                waitUntilDone:YES];
    }
    dispatch_semaphore_signal(self.requestPauseSemaphore);

}

- (NSError *)invalidCredsError
{
    NSError *error = nil;
    
    if (self.configuration.collectIdentityDomain)
    {
        error = [OMObject createErrorWithCode:
                 OMERR_INVALID_USERNAME_PASSWORD_IDENTITY];
    }
    else
    {
        error = [OMObject createErrorWithCode:
                 OMERR_INVALID_USERNAME_PASSWORD];
    }
    
    return error;
}
@end
