/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMMobileSecurityService.h"
#import "OMMobileSecurityConfiguration.h"
#import "OMCredential.h"
#import "OMCredentialStore.h"
#import "OMCertInfo.h"
#import "OMCertService.h"
#import "OMAuthenticationContext.h"
#import "OMAuthenticationRequest.h"
#import "OMAuthenticationChallenge.h"
#import "OMObject.h"
#import "OMDefinitions.h"
#import "OMCryptoService.h"
#import "OMToken.h"
#import "OMOTPService.h"
#import "NSData+OMBase64.h"
#import "NSData+OMBase32.h"
#import "OMAuthenticator.h"
#import "OMPinAuthenticator.h"
#import "OMTouchIDAuthenticator.h"
#import "OMDefaultAuthenticator.h"
#import "OMAuthData.h"
#import "OMLocalAuthenticationManager.h"
#import "OMAuthenticationManager.h"
#import "OMErrorCodes.h"
#import "OMDataSerializationHelper.h"
#import "OMJailBrokenDetector.h"
#import "OMReachability.h"
#import "OMBiometricAuthenticator.h"

@interface IDMMobileSDKv2Library : NSObject

@end
