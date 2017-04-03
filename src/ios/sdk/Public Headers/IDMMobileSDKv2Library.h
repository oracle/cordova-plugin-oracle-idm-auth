/* Copyright (c) 2016, Oracle and/or its affiliates.
 All rights reserved. */

/*
 NAME
 IDMMobileSDKv2Library.h - IDM Mobile SDK headless static library header file
 
 DESCRIPTION
 Header file that will be made public by the SDK
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    07/26/16 - Creation
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
@interface IDMMobileSDKv2Library : NSObject

@end