/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>

@class OMKeyStore,OMAuthData,OMSecureStorage;

typedef enum : NSUInteger
{
    OMAuthenticationPolicyPin
} OMAuthenticationPolicy;

typedef NS_ENUM(NSInteger, BiometryType)
{
    /// The device does not support biometry.
    BiometryTypeNone,
    
    /// The device supports Touch ID.
    BiometryTypeTouchID,
    
    /// The device supports Face ID.
    BiometryTypeFaceID ,
};

@interface OMAuthenticator : NSObject

@property (nonatomic, strong) OMKeyStore *keyStore;
@property (nonatomic, strong) OMSecureStorage *secureStorage;
@property (nonatomic, assign) BOOL isAuthenticated;
@property (nonatomic, strong) NSString *instanceId;

- (id)initWithInstanceId:(NSString *)instanceId error:(NSError **)error;
- (void)setAuthData:(OMAuthData *)authData error:(NSError **)error;
- (void)deleteAuthData:(NSError **)error;
- (void)updateAuthData:(OMAuthData *)currentAuthData newAuthData:
                            (OMAuthData *)newAuthData error:(NSError **)error;
- (BOOL)authenticate:(OMAuthData*)authData error:(NSError**)error;
- (void)copyKeysFromKeyStore:(OMKeyStore*)keyStore;
- (BOOL)isAuthDataSet;
- (void)inValidate;
- (NSInteger)authDataLength;
@end
