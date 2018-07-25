/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticationManager.h"
#import "OMHTTPBasicAuthenticationService.h"
#import "OMHTTPBasicConfiguration.h"
#import "OMMobileSecurityService.h"
#import "OMObject.h"
#import "OMAuthenticationChallenge.h"
#import "OMDefinitions.h"
#import "OMClientCertConfiguration.h"
#import "OMClientCertAuthenticationService.h"
#import "OMClientCertConfiguration.h"
#import "OMOAuthConfiguration.h"
#import "OMFedAuthConfiguration.h"
#import "OMFedAuthAuthenticationService.h"
#import "OMOpenIDCConfiguration.h"
#import "OMOpenIDCAuthenticationService.h"
#import "OMOIDCConfiguration.h"
#import "OMOIDCAuthenticationService.h"
#import "OMOAMOAuthConfiguration.h"
#import "OMOAMOAuthClientRegistrationService.h"
#import "OMOAMOAuthClientAssertionService.h"
#import "OMOAMUserAssertionService.h"
#import "OMIDCSClientRegistrationService.h"
#import "OMCredentialStore.h"
#import "OMErrorCodes.h"

@implementation OMAuthenticationManager
-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
             authenticationRequest:(OMAuthenticationRequest *)authReq
{
    self = [super init];
    if (self)
    {
        _mss = mss;
        _authData = [[NSMutableDictionary alloc] init];
        _request = authReq;
    }
    return self;
}

-(void)startAuthenticationProcess
{
    [self setIsAuthRequestInProgress:YES];
    if ([self.mss.configuration isKindOfClass:[OMHTTPBasicConfiguration class]])
    {
        self.curentAuthService = [[OMHTTPBasicAuthenticationService alloc]
                                  initWithMobileSecurityService:self.mss
                                  authenticationRequest:self.request
                                  delegate:self];
    }
    else if ([self.mss.configuration isKindOfClass:[OMClientCertConfiguration class]])
    {
        self.curentAuthService = [[OMClientCertAuthenticationService alloc]
                                  initWithMobileSecurityService:self.mss
                                  authenticationRequest:self.request
                                  delegate:self];
    }
    else if ([self.mss.configuration isMemberOfClass:
              [OMOAuthConfiguration class]])
    {
        if ([(OMOAuthConfiguration*)self.mss.configuration
             isClientRegistrationRequired])
        {
            self.curentAuthService = [[OMIDCSClientRegistrationService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];

        }
        else
        {
            self.curentAuthService = [[OMOAuthAuthenticationService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];

        }
    }
    else if ([self.mss.configuration isMemberOfClass:
              [OMOIDCConfiguration class]])
    {
        if ([(OMOIDCConfiguration*)self.mss.configuration
             isClientRegistrationRequired])
        {
            self.curentAuthService = [[OMIDCSClientRegistrationService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];
            
        }
        else
        {
            self.curentAuthService = [[OMOIDCAuthenticationService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];
            
        }

    }
    else if ([self.mss.configuration isMemberOfClass:[OMOAMOAuthConfiguration class]])
    {
        self.curentAuthService = [[OMOAMOAuthClientRegistrationService alloc]
                                  initWithMobileSecurityService:self.mss
                                  authenticationRequest:self.request
                                  delegate:self];
    }
    else if ([self.mss.configuration isKindOfClass:
              [OMFedAuthConfiguration class]])
    {
        self.curentAuthService = [[OMFedAuthAuthenticationService alloc]
                                  initWithMobileSecurityService:self.mss
                                  authenticationRequest:self.request
                                  delegate:self];
    }
    else
    {
        return;
    }
    [self performNextStep];
}

-(void)cancelAuthentication
{
    [self setIsAuthRequestInProgress:NO];

    [self.curentAuthService cancelAuthentication];
}
-(void)performNextStep
{
    if (!self.curentAuthService)
    {
        return;
    }
    [self.curentAuthService performAuthentication:self.authData error:nil];
}

-(void)didFinishCurrentStep:(id)object
                   nextStep:(NSUInteger)nextStep
               authResponse:(NSDictionary *)data
                      error:(NSError *)error
{
    switch (nextStep)
    {
        case OM_NEXT_AUTH_STEP_NONE:
            [self sendAuthenticationContext:self.curentAuthService.context
                                      error:error];
            break;
        case OM_NEXT_AUTH_STEP_CHALLENGE:
            [self sendAuthenticationChallenge:self.curentAuthService.challenge];
            break;
        case OM_NEXT_EXCHANGE_AUTHZ_CODE:
            [self.curentAuthService
             performAuthentication:self.authData error:nil];
            break;
        case OM_NEXT_OAUTH_CLIENT_ASSERTION:
            self.curentAuthService = [[OMOAMOAuthClientAssertionService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];
            [self.curentAuthService performAuthentication:self.authData
                                                    error:nil];
            break;
        case OM_NEXT_OAUTH_USER_ASSERTION:
            self.curentAuthService = [[OMOAMUserAssertionService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];
            [self.curentAuthService performAuthentication:self.authData
                                                    error:nil];
            break;
        case OM_NEXT_OAUTH_AUTHORIZATION:
            self.curentAuthService = [[OMOAuthAuthenticationService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];
            [self.curentAuthService performAuthentication:self.authData
                                                    error:nil];
            break;
        case OM_NEXT_OPEN_ID_AUTHORIZATION:
            self.curentAuthService = [[OMOIDCAuthenticationService alloc]
                                      initWithMobileSecurityService:self.mss
                                      authenticationRequest:self.request
                                      delegate:self];
            [self.curentAuthService performAuthentication:self.authData
                                                    error:nil];
        break;
        case OM_NEXT_AUTH_STEP_DEVICE_REGISTRATION:
            [self.curentAuthService
             performAuthentication:self.authData error:nil];
            break;

        default:
            break;
    }
}

-(void)sendAuthenticationContext:(OMAuthenticationContext *)context
                           error:(NSError *)error
{
    [self.mss saveAuthContext:context];
    [self setIsAuthRequestInProgress:NO];
    if (error)
    {
        error = [self mapOSErrorWithOMError:error];
    }
    [self.mss.delegate mobileSecurityService:self.mss
                     didFinishAuthentication:context error:error];
}

-(void)sendAuthenticationChallenge:(OMAuthenticationChallenge *)challenge
{
    [self.mss.delegate mobileSecurityService:self.mss
           didReceiveAuthenticationChallenge:self.curentAuthService.challenge];
}

- (NSError*)mapOSErrorWithOMError:(NSError*)currentError
{
    NSError *newError = nil;
    
    if (currentError.code == NSURLErrorCancelled)
    {
        newError = [OMObject createErrorWithCode:
                    OMERR_USER_CANCELED_AUTHENTICATION];
    }
    else
    {
        newError = currentError;
    }
    
    return newError;
}
@end
