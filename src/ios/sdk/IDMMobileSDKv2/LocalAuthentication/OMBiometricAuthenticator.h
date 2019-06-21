/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

/*BEGIN HISTORY----
 NAME
 OMBiometricAuthenticator - Oracle mobile Biometric Authenticator class
 
 DESCRIPTION
 OMBiometricAuthenticator - Oracle mobile Biometric Authenticator class
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 OMBiometricFallbackDelegate
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 shivap      04/29/19 - Creation
 ----END HISTORY*/

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import "OMAuthenticator.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^OMFallbackAuthenticationCompletionBlock)(BOOL authenticated);

@protocol OMBiometricFallbackDelegate <NSObject>

@required

- (void)didSelectFallbackAuthentication:(NSError *)fallBackReason completionHandler:
(OMFallbackAuthenticationCompletionBlock)handler;

@end

@interface OMBiometricAuthenticator : OMAuthenticator

@property (nonatomic, weak, nullable) id<OMBiometricFallbackDelegate> delegate;
@property (nonatomic, copy) NSString *localizedFallbackTitle;
@property (nonatomic, copy) NSString *localizedBiometricUsingReason;

+ (BOOL)canEnableBiometricAuthentication:(NSError **)error;
+ (BiometryType)biometricType;


@end

NS_ASSUME_NONNULL_END
