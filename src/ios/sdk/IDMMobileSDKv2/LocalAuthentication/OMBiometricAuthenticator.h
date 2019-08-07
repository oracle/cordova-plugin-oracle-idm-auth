/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


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
