/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@class OMAuthenticator;
@interface OMLocalAuthenticationManager : NSObject

+ (OMLocalAuthenticationManager *)sharedManager;

- (BOOL)registerAuthenticator:(NSString*)authenticatorName
                    className:(NSString*)className error:(NSError **)error;

- (BOOL)unRegisterAuthenticator:(NSString*)authenticatorName error:(NSError **)error;

- (BOOL)enableAuthentication:(NSString*)authenticatorName
                  instanceId:(NSString*)instanceId
                       error:(NSError **)error;

- (BOOL)disableAuthentication:(NSString*)instanceId
                        error:(NSError **)error;

- (OMAuthenticator*)authenticatorForInstanceId:(NSString*)instanceId
                                         error:(NSError **)error;

- (NSString *)authenticationTypeForInstanceId:(NSString*)instanceId;
- (BOOL)isAuthenticatorClassRegistered:(NSString*)className;
- (BOOL)isAuthenticatorRegistered:(NSString*)authenticatorName;
- (BOOL)isAuthKeyEnabled:(NSString*)key;
- (void)addAuthKeyToList:(NSString*)key;
- (void)removeAuthKeyFromList:(NSString*)key;

@end

@interface AuthenticatorInstanceIdInfo : NSObject<NSCoding>

@property (nonatomic, strong) NSString * authenticatorName;
@property (nonatomic, assign) BOOL isEnabled;

- (instancetype)initWithAuthenticatorName:(NSString *)authenticatorName
                                   enable:(BOOL)enable;

@end
