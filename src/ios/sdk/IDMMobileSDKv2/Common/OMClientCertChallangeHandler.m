/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMClientCertChallangeHandler.h"
#import "OMCertService.h"
#import "OMAuthenticationService.h"
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMErrorCodes.h"

@interface OMClientCertChallangeHandler()

@property (nonatomic, weak) OMAuthenticationService *currentService;
@property (nonatomic, strong) NSArray *certInfoList;
@property (nonatomic, strong) NSArray *clientIdentitiesList;

@end

@implementation OMClientCertChallangeHandler

+ (OMClientCertChallangeHandler*)sharedHandler
{
    static OMClientCertChallangeHandler *kSharedHandler = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        kSharedHandler = [[self alloc] init];
    });
    
    return kSharedHandler;
}

-(void)sendServerTrustChallenge:(id)object
{
    self.currentService.challenge = [[OMAuthenticationChallenge alloc] init];
    self.currentService.challenge.authData = self.currentService.authData;
    self.currentService.challenge.challengeType = OMChallengeServerTrust;
    
    __block __weak OMAuthenticationService *weakself = self.currentService;
    __block dispatch_semaphore_t blockSemaphore = self.currentService.
                                                    requestPauseSemaphore;

    self.currentService.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                            OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            weakself.authData = [NSMutableDictionary
                                 dictionaryWithDictionary:dict];
        }
        else
        {
            [weakself cancelAuthentication];
            [weakself.delegate didFinishCurrentStep:weakself
                                          nextStep:OM_NEXT_AUTH_STEP_NONE
                                      authResponse:nil
                                             error:[OMObject createErrorWithCode:
                                                    OMERR_USER_CANCELED_AUTHENTICATION]];

        }
        dispatch_semaphore_signal(blockSemaphore);
    };
    
    [self.currentService.delegate didFinishCurrentStep:self
                               nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                           authResponse:nil
                                  error:nil];
}

-(void)sendClientCertChallenge:(id)object
{
    
    self.currentService.challenge = [[OMAuthenticationChallenge alloc] init];
    self.currentService.challenge.authData = self.currentService.authData;
    self.currentService.challenge.challengeType = OMChallengeClientCert;
    
    __block __weak OMAuthenticationService *weakself = self.currentService;
    __block dispatch_semaphore_t blockSemaphore = self.currentService.
    requestPauseSemaphore;

    self.currentService.challenge.authChallengeHandler = ^(NSDictionary *dict,
                                                           OMChallengeResponse response)
    {
        if (response == OMProceed)
        {
            weakself.authData = [NSMutableDictionary
                                 dictionaryWithDictionary:dict];
        }
        else
        {
            [weakself cancelAuthentication];
            [weakself.delegate didFinishCurrentStep:weakself
                                           nextStep:OM_NEXT_AUTH_STEP_NONE
                                       authResponse:nil
                                              error:[OMObject createErrorWithCode:
                                                     OMERR_USER_CANCELED_AUTHENTICATION]];
        }
        dispatch_semaphore_signal(blockSemaphore);

    };
    
    [self.currentService.delegate didFinishCurrentStep:self
                                              nextStep:OM_NEXT_AUTH_STEP_CHALLENGE
                                          authResponse:nil
                                                 error:nil];
}

- (void)doClientTrustForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                               challengeReciver:(id)reciver
                              completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                                          NSURLCredential *credential))completionHandler
{
    self.currentService = reciver;

    
    if (![OMCertService isClientIdentityInstalled])
    {
        [self.currentService  performSelector:@selector(sendFinishAuthentication:)
                     onThread:self.currentService.callerThread
                   withObject:[OMObject createErrorWithCode:
                               OMERR_NO_IDENTITY]
                waitUntilDone:false];
        [self.currentService cancelAuthentication];
        
        return;
    }
    else
    {
        if (nil == self.currentService.requestPauseSemaphore)
        {
            self.currentService.requestPauseSemaphore =
            dispatch_semaphore_create(0);
        }

        self.clientIdentitiesList = [OMCertService allClientIdentities];
        NSArray *clientCerts = [OMCertService getCertInfoForIdentities:
                                self.clientIdentitiesList];
        
        if (![clientCerts count])
        {
            if (clientCerts == nil) {
                clientCerts = [NSArray array];
            }
            
            [self.currentService.authData setObject:clientCerts forKey:OM_CLIENTCERTS];
        }
        else
        {
            [self.currentService.authData setObject:clientCerts forKey:OM_CLIENTCERTS];
            self.certInfoList = clientCerts;
        }
        
        [self.currentService.authData setObject:[NSNull null] forKey:OM_SELECTED_CERT];
        
        [self performSelector:@selector(sendClientCertChallenge:)
                     onThread:self.currentService.callerThread
                   withObject:nil
                waitUntilDone:false];
        
        dispatch_semaphore_wait(self.currentService.requestPauseSemaphore, DISPATCH_TIME_FOREVER);
        
        id cert = [self.currentService.authData valueForKey:OM_SELECTED_CERT];
        
        if ([cert isKindOfClass:[OMCertInfo class]])
        {
            NSUInteger index = [self.certInfoList indexOfObject:cert];
            
            SecIdentityRef currentIdentity = (__bridge SecIdentityRef)
            ([self.clientIdentitiesList objectAtIndex:index]);
            NSURLCredential *cred = [OMCertService
                                     getCretCredentialForIdentity:
                                     currentIdentity];
            
            completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
        }
        else
        {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                              nil);
        }
    }
}

- (void)doServerTrustForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                               challengeReciver:(id)reciver
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                NSURLCredential *credential))completionHandler
{
    self.currentService = reciver;
    OSStatus err;
    BOOL trusted = NO;
    
    if (nil == self.currentService.requestPauseSemaphore)
    {
      self.currentService.requestPauseSemaphore = dispatch_semaphore_create(0);
    }
    
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
        
        OMCertInfo *certInfo = [OMCertService infoForServerTrustRef:trustRef];
        
        if (nil != certDesc)
            [self.currentService.authData setObject:certDesc forKey:OM_CERT_DESC];
        
        if(nil != certInfo)
            [self.currentService.authData setObject:certInfo
                                             forKey:OM_SERVER_TRUST_INFO];

        [self.currentService.authData setObject:[NSNumber numberWithBool:NO]
                          forKey:OM_TRUST_SERVER_CHALLANGE];
        
        [self performSelector:@selector(sendServerTrustChallenge:)
                     onThread:self.currentService.callerThread
                   withObject:nil
                waitUntilDone:false];
        
        dispatch_semaphore_wait(self.currentService.requestPauseSemaphore, DISPATCH_TIME_FOREVER);
        
        if ([[self.currentService.authData objectForKey:OM_TRUST_SERVER_CHALLANGE] boolValue])
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
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:trustRef]);
        
    }
    else
    {
        // cancel or cert addition failed
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
                          nil);

    }
}

@end
