/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticator.h"


typedef void (^OMFallbackAuthenticationCompletionBlock)(BOOL authenticated);

__attribute__ ((deprecated))
__deprecated_msg("This Protocol is deprecated Use OMBiometricFallbackDelegate class instead.")

@protocol OMTouchIDFallbackDelegate <NSObject>

@required

- (void)didSelectFallbackAuthentication:(NSError *)fallBackReason completionHandler:
    (OMFallbackAuthenticationCompletionBlock)handler;

@end

__attribute__ ((deprecated))
__deprecated_msg("This Class is deprecated Use OMBiometricAuthenticator class instead.")

@interface OMTouchIDAuthenticator : OMAuthenticator

@property (nonatomic, weak) id<OMTouchIDFallbackDelegate> delegate;
@property (nonatomic, copy) NSString *localizedFallbackTitle;
@property (nonatomic, copy) NSString *localizedTouchIdUsingReason NS_DEPRECATED_IOS(8.0, 11.0, "Use localizedBiometricUsingReason");;
@property (nonatomic, copy) NSString *localizedBiometricUsingReason;

+ (BOOL)canEnableTouchID:(NSError *__autoreleasing*)error NS_DEPRECATED_IOS(8.0, 11.0, "Use canEnableBiometricAuthentication");

+ (BOOL)canEnableBiometricAuthentication:(NSError **)error;
+ (BiometryType)biometricType;


@end
