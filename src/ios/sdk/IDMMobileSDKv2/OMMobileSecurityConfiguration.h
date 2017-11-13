/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMDefinitions.h"


@interface OMMobileSecurityConfiguration : NSObject
@property (nonatomic) int idleTimeout;
@property (nonatomic) int sessionTimeout;
@property (nonatomic) int percentageToIdleTimeout;
@property (nonatomic) int authenticationRetryCount;
@property (nonatomic, strong) NSString *appName;
@property (nonatomic) BOOL rememberCredAllowed;
@property (nonatomic) BOOL rememberUsernameAllowed;
@property (nonatomic) BOOL autoLoginAllowed;
@property (nonatomic) BOOL autoLoginDefault;
@property (nonatomic) BOOL rememberCredDefault;
@property (nonatomic) BOOL rememberUsernameDefault;
@property (nonatomic, strong) NSString *identityDomain;
@property (nonatomic) BOOL identityDomainInHeader;
@property (nonatomic, strong) NSString  *identityDomainHeaderName;
@property (nonatomic, strong) NSDictionary *customHeaders;
@property (nonatomic) BOOL provideIdentityDomainToMobileAgent;
@property (nonatomic) BOOL presentIdentityOnDemand;
@property (nonatomic) BOOL presentClientCertIdentityOnDemand;
@property (nonatomic) OMCryptoScheme cryptoScheme;
@property (nonatomic) BOOL sendCustomHeadersLogout;
@property (nonatomic) BOOL sendAuthHeaderLogout;
@property (nonatomic, strong) NSString *localAuthenticatorIntanceId;

+ (NSDictionary *)parseConfigurationURL: (NSURL *)configURL
                  persistInUserDefaults: (BOOL)persist
                                withKey: (NSString *)key;

- (id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;
- (BOOL)isValidString:(NSString*)str;
- (BOOL)isValidUrl:(NSString *)url;
+ (BOOL)isValidNumber:(id)object inRange:(NSRange)range;
+ (BOOL)isValidUnsignedNumber:(id)object;
+ (BOOL)boolValue:(id)object;
- (NSDictionary *)getIdentityClaims;
+ (BOOL)isWKWebViewAvailable;
+ (NSDictionary *)initializationConfigurationForKey:(NSString *)key;
+ (BOOL)deleteInitializationConfigurationForKey:(NSString *)key;
@end
