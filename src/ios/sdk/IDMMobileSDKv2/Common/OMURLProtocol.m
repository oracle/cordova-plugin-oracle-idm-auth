/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMURLProtocol.h"
#import "OMCertService.h"
#import "OMDefinitions.h"
#import "OMCertInfo.h"
#import "OMObject.h"
#import "OMAuthenticationService.h"
#import <objc/runtime.h>
#import "OMErrorCodes.h"

static OMAuthenticationService *oms = nil;

@interface OMURLProtocol()<NSURLConnectionDelegate, NSURLConnectionDataDelegate>

@property (nonatomic, retain) NSURLConnection *connection;
@property (nonatomic, strong) NSArray *certInfoList;
@property (nonatomic, strong) NSArray *clientIdentitiesList;


@end

@implementation OMURLProtocol

static NSString *recursiveRequestFlagProperty = @"OMURLProtocolHandledKey";

+(BOOL)canInitWithRequest:(NSURLRequest *)request
{
    
    if ([NSURLProtocol propertyForKey:recursiveRequestFlagProperty
                            inRequest:request])
    {
        return NO;
    }
    return YES;
}

-(id)initWithRequest:(NSURLRequest *)request
      cachedResponse:(NSCachedURLResponse *)cachedResponse
              client:(id<NSURLProtocolClient>)client
{
    self = [super initWithRequest:request cachedResponse:cachedResponse
                           client:client];
    return self;
}

+(NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request
{
    return request;
}

+(BOOL)requestIsCacheEquivalent:(NSURLRequest *)a
                      toRequest:(NSURLRequest *)b
{
    return [super requestIsCacheEquivalent:a toRequest:b];
}

-(void)startLoading
{
    
    NSMutableURLRequest *newRequest = [self.request mutableCopy];
    [NSURLProtocol setProperty:@YES forKey:recursiveRequestFlagProperty
                     inRequest:newRequest];
    self.connection = [NSURLConnection connectionWithRequest:newRequest
                                                    delegate:self];
}

-(void)stopLoading
{
    [self.connection cancel];
    self.connection = nil;
}

-(NSURLRequest *)connection:(NSURLConnection *)connection
            willSendRequest:(NSURLRequest *)request
           redirectResponse:(NSURLResponse *)response
{
    if (response)
    {
        NSLog(@"%@ -> %@",response.URL, request.URL);
        if ([response.URL.scheme isEqual:@"https"] &&
            [request.URL.scheme isEqual:@"http"])
        {
            [self sendInsecureRedirectChallenge:nil];
            dispatch_semaphore_wait(oms.requestPauseSemaphore,
                                    DISPATCH_TIME_FOREVER);
        }
        NSMutableURLRequest *newReq = nil;
        newReq = [request mutableCopy];
        [NSURLProtocol removePropertyForKey:recursiveRequestFlagProperty
                                  inRequest:newReq];
        [self.client URLProtocol:self
          wasRedirectedToRequest:newReq
                redirectResponse:response];
        [self.connection cancel];
        [[self client] URLProtocol:self
                  didFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain
                                                       code:NSUserCancelledError
                                                   userInfo:nil]];
        /* Returning nil as request was getting fired twice in iOS7.1.
         NSURLProtocol will get control back when client starts loading the
         request*/
        return nil;
    }
    else
    {
        return request;
    }
}

-(void) connection:(NSURLConnection *)connection
didReceiveResponse:(NSURLResponse *)response
{
    [self.client URLProtocol:self
          didReceiveResponse:response
          cacheStoragePolicy:NSURLCacheStorageAllowed];
}

-(void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    [self.client URLProtocol:self didLoadData:data];
}

-(void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    [self.client URLProtocolDidFinishLoading:self];
}

-(void)connection:(NSURLConnection *)connection
 didFailWithError:(NSError *)error
{
    
    [self.client URLProtocol:self didFailWithError:error];
}

-(BOOL)connection:(NSURLConnection *)connection
canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    return true;
}

-(void)connection:(NSURLConnection *)connection
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    NSURLProtectionSpace *protectionSpace = [challenge protectionSpace];

    if ([[protectionSpace authenticationMethod]
         isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        [self doServerTrustForAuthenticationChallenge:challenge];
    }
    else if ([[protectionSpace authenticationMethod]
              isEqualToString:NSURLAuthenticationMethodClientCertificate] &&
             [oms.mss.configuration presentClientCertIdentityOnDemand])
    {
        
        self.clientIdentitiesList = [OMCertService allClientIdentities];
        NSArray *clientCerts = [OMCertService getCertInfoForIdentities:
                                self.clientIdentitiesList];
        
        if (![clientCerts count])
        {
            if (clientCerts == nil) {
                clientCerts = [NSArray array];
            }
            
            [oms.authData setObject:clientCerts forKey:OM_CLIENTCERTS];
        }
        else
        {
            [oms.authData setObject:clientCerts forKey:OM_CLIENTCERTS];
            self.certInfoList = clientCerts;
        }
        
        [oms.authData setObject:[NSNull null] forKey:OM_SELECTED_CERT];
        
        [self sendClientCertChallenge:nil];
        
        dispatch_semaphore_wait(oms.requestPauseSemaphore,
                                DISPATCH_TIME_FOREVER);
        
        id cert = [oms.authData valueForKey:OM_SELECTED_CERT];

        if ([cert isKindOfClass:[OMCertInfo class]])
        {
            NSUInteger index = [self.certInfoList indexOfObject:cert];
            
            SecIdentityRef currentIdentity = (__bridge SecIdentityRef)
            ([self.clientIdentitiesList objectAtIndex:index]);
            NSURLCredential *cred = [OMCertService
                                     getCretCredentialForIdentity:
                                     currentIdentity];
            
            [[challenge sender] useCredential:cred
                   forAuthenticationChallenge:challenge];
        }
        else
        {
            [[challenge sender]
             continueWithoutCredentialForAuthenticationChallenge:challenge];
        }

    }
    else if([[protectionSpace authenticationMethod]
             isEqualToString:NSURLAuthenticationMethodNTLM] ||
            [[protectionSpace authenticationMethod]
             isEqualToString:NSURLAuthenticationMethodHTTPBasic] ||
            [[protectionSpace authenticationMethod]
             isEqualToString:NSURLAuthenticationMethodNegotiate] ||
            [[protectionSpace authenticationMethod]
             isEqualToString:NSURLAuthenticationMethodDefault])
    {
        /* Notify client that a challenge is received. It will stop the
         webview to timeout while waiting for a response.
         REVISIT when using this class for NSURLSession or NSURLConnection */
       
        [[self client] URLProtocol:self
            didReceiveAuthenticationChallenge:challenge];

        [oms.authData setValue:[NSNull null] forKey:OM_USERNAME];
        [oms.authData setValue:[NSNull null] forKey:OM_PASSWORD];
        
        [self sendChallenge:nil];

        dispatch_semaphore_wait(oms.requestPauseSemaphore,
                                DISPATCH_TIME_FOREVER);
        
        NSString * userName = [oms.authData valueForKey:OM_USERNAME];
        NSString * password = [oms.authData valueForKey:OM_PASSWORD];

        if (userName && password)
        {
            NSURLCredential *credential =  [NSURLCredential
                                           credentialWithUser:userName
                                           password:password
                                           persistence:NSURLCredentialPersistenceForSession];
            
            [[challenge sender] useCredential:credential
                   forAuthenticationChallenge:challenge];

        }
        else
        {
            [[challenge sender]
             continueWithoutCredentialForAuthenticationChallenge:challenge];

        }
       
    }
    else
    {
        [[challenge sender]
         continueWithoutCredentialForAuthenticationChallenge:challenge];
        return;
    }
}

-(void)challengeFinished
{
    dispatch_semaphore_signal(oms.requestPauseSemaphore);
}

-(void)sendChallenge:(id)object
{
    oms.challenge = [[OMAuthenticationChallenge alloc] init];
    NSMutableDictionary *challengeDict = [NSMutableDictionary
                                          dictionaryWithDictionary:oms.authData];
    [challengeDict removeObjectForKey:OM_AUTH_SUCCESS];
    oms.challenge.authData = challengeDict;
    oms.challenge.challengeType = OMChallengeUsernamePassword;
    __block __weak OMAuthenticationService *weakOms = oms;
    __block __weak OMURLProtocol *weakProtocol = self;
    __block dispatch_semaphore_t blockSemaphore = oms.requestPauseSemaphore;

    oms.challenge.authChallengeHandler = ^(NSDictionary *dict,
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
                
                
                [self sendChallenge:nil];
            }
            else
            {

                [weakOms.authData addEntriesFromDictionary:inDict];
               
                if([weakOms.authData objectForKey:OM_ERROR])
                {
                    [weakOms.authData removeObjectForKey:OM_ERROR];
                }

            }
                
        }
        else
        {
            [weakProtocol.connection cancel];
            //Cancels an asynchronous load of a request. After this method is called,
            //the connection makes no further delegate method calls.
            //So release connection to complete stop
            weakProtocol.connection = nil;
            
            [weakOms.delegate didFinishCurrentStep:oms
                                      nextStep:OM_NEXT_AUTH_STEP_NONE
                                  authResponse:nil
                                         error:[OMObject createErrorWithCode:
                                            OMERR_USER_CANCELED_AUTHENTICATION]];
        }

        dispatch_semaphore_signal(blockSemaphore);

    };
    
    [oms.delegate didFinishCurrentStep:oms
                               nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                           authResponse:nil
                                  error:nil];
}

-(void)sendClientCertChallenge:(id)object
{
    oms.challenge = [[OMAuthenticationChallenge alloc] init];
    oms.challenge.authData = oms.authData;
    oms.challenge.challengeType = OMChallengeClientCert;
    
    __block __weak OMAuthenticationService *weakOms = oms;
    __block __weak OMURLProtocol *weakProtocol = self;
    __block dispatch_semaphore_t blockSemaphore = oms.requestPauseSemaphore;

    oms.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                                OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            weakOms.authData = [NSMutableDictionary
                                dictionaryWithDictionary:dict];
        }
        else
        {
            [weakProtocol.connection cancel];
            //Cancels an asynchronous load of a request. After this method is called,
            //the connection makes no further delegate method calls.
            //So release connection to complete stop
            weakProtocol.connection = nil;
            
            [weakOms.delegate didFinishCurrentStep:oms
                                          nextStep:OM_NEXT_AUTH_STEP_NONE
                                      authResponse:nil
                                             error:[OMObject createErrorWithCode:
                                                    OMERR_USER_CANCELED_AUTHENTICATION]];
        }
        dispatch_semaphore_signal(blockSemaphore);

    };
    
    [oms.delegate didFinishCurrentStep:self
                                   nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                               authResponse:nil
                                      error:nil];
}

-(void)sendServerTrustChallenge:(id)object
{
    oms.challenge = [[OMAuthenticationChallenge alloc] init];
    oms.challenge.authData = oms.authData;
    oms.challenge.challengeType = OMChallengeServerTrust;
    
    __block __weak OMAuthenticationService *weakOms = oms;
    __block __weak OMURLProtocol *weakProtocol = self;
    __block dispatch_semaphore_t blockSemaphore = oms.requestPauseSemaphore;

    oms.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                           OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            weakOms.authData = [NSMutableDictionary
                                dictionaryWithDictionary:dict];
        }
        else
        {
            [weakProtocol.connection cancel];
            //Cancels an asynchronous load of a request. After this method is called,
            //the connection makes no further delegate method calls.
            //So release connection to complete stop
            weakProtocol.connection = nil;
            
            [weakOms.delegate didFinishCurrentStep:oms
                                          nextStep:OM_NEXT_AUTH_STEP_NONE
                                      authResponse:nil
                                             error:[OMObject createErrorWithCode:
                                                    OMERR_USER_CANCELED_AUTHENTICATION]];
        }
        dispatch_semaphore_signal(blockSemaphore);
    };
    
    [oms.delegate didFinishCurrentStep:self
                              nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                          authResponse:nil
                                 error:nil];
}

- (void)doServerTrustForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    OSStatus err;
    BOOL trusted = NO;
    SecTrustRef trustRef = [[challenge protectionSpace]serverTrust];
    
    SecTrustResultType trustResult = [OMCertService evaluateTrustResultForChallenge:
                                      challenge withError:&err];
    
    // cert chain invalid - alert user and get confirmation
    if ( err == noErr &&
        trustResult == kSecTrustResultRecoverableTrustFailure)
    {
        // human-readable summary of certificate
        NSString *certDesc;
        certDesc = [OMCertService certSummaryInTrust:trustRef];
        
        if (nil != certDesc)
            [oms.authData setObject:certDesc forKey:OM_CERT_DESC];
        
        [oms.authData setObject:[NSNumber numberWithBool:NO]
                         forKey:OM_TRUST_SERVER_CHALLANGE];
        
        [self sendServerTrustChallenge:nil];
        
        dispatch_semaphore_wait(oms.requestPauseSemaphore,
                                DISPATCH_TIME_FOREVER);
        
        if ([[oms.authData objectForKey:OM_TRUST_SERVER_CHALLANGE] boolValue])
        {
            trusted = YES;
            [OMCertService addLeafCertificateFromTrust:trustRef];
            
        }
        else
        {
            trusted = NO;
        }
    }
    // cert chain ok
    else if ( err == noErr &&
             ((trustResult == kSecTrustResultProceed) ||
              (trustResult == kSecTrustResultUnspecified)))
    {
        trusted = YES;
    }
    // Failed: kSecTrustResultDeny, kSecTrustResultFatalTrustFailure,
    //         kSecTrustResultInvalid, kSecTrustResultOtherError
    //         kSecTrustResultConfirm - deprecated - iOS 7.0
    else
    {
        trusted = NO;
    }
    
    // add all certs
    if (trusted)
    {
        [[challenge sender]useCredential:
         [NSURLCredential credentialForTrust:trustRef]
              forAuthenticationChallenge:challenge];
    }
    else
    {
        // cancel or cert addition failed
        [[challenge sender]
         continueWithoutCredentialForAuthenticationChallenge:challenge];

    }
}

+ (void)setOMAObject:(OMAuthenticationService *)obj;
{
    oms = obj;
    
    if (nil == oms.requestPauseSemaphore)
    {
        oms.requestPauseSemaphore = dispatch_semaphore_create(0);
    }

}

+ (OMAuthenticationService *)currentOMAObject;
{
    return oms;
}

-(void)sendInsecureRedirectChallenge:(id)object
{
    oms.challenge = [[OMAuthenticationChallenge alloc] init];
    NSMutableDictionary *challengeDict = [NSMutableDictionary
                                          dictionaryWithDictionary:oms.authData];
    [challengeDict removeObjectForKey:OM_AUTH_SUCCESS];
    oms.challenge.authData = challengeDict;
    oms.challenge.challengeType = OMChallengeInvalidRedirect;
    [challengeDict setObject:[NSNumber numberWithInt:OMHttpsToHttpRedirect]
                      forKey:OM_INVALID_REDIRECT];
    __block __weak OMAuthenticationService *weakOms = oms;
    __block __weak OMURLProtocol *weakProtocol = self;
    __block dispatch_semaphore_t blockSemaphore = oms.requestPauseSemaphore;

    oms.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                           OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            // as of now just unlock the thread
        }
        else
        {
            [weakProtocol.connection cancel];
            //Cancels an asynchronous load of a request. After this method is called,
            //the connection makes no further delegate method calls.
            //So release connection to complete stop
            weakProtocol.connection = nil;
            [weakOms.delegate didFinishCurrentStep:oms
                                          nextStep:OM_NEXT_AUTH_STEP_NONE
                                      authResponse:nil
                                             error:[OMObject createErrorWithCode:
                                                    OMERR_USER_CANCELED_AUTHENTICATION]];
        }
        dispatch_semaphore_signal(blockSemaphore);
    };
    [oms.delegate didFinishCurrentStep:self
                              nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                          authResponse:nil
                                 error:nil];
}
@end
