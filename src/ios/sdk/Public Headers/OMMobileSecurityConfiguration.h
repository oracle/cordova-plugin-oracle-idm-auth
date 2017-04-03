/* Copyright (c) 2011, 2015, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMMobileSecurityConfiguration.h - Oracle Mobile Security Configuration
 
 DESCRIPTION
 Base class for all mobile configuration classes e.g. OMHTTPBasicConfiguration
 
 RELATED DOCUMENTS
 None
 
 INHERITS FROM
 NSObject
 
 PROTOCOLS IMPLEMENTED
 None
 
 EXTENSION FUNCTIONS
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    07/27/16 - Removed unused methods
 asashiss    07/03/16 - OMSS-29849
 asashiss    06/23/16 - OMSS-29780
 shivap      04/28/16 - OMSS 28260
 shivap      04/12/16 - Change the startSessionTimers api to startTimers
 asashiss    03/23/16 - OWSM MA APIs
 asashiss    03/11/16 - OAuth changes
 shivap      03/10/16 - Changes done to fix OMSS-28206
 asashiss    02/12/16 - Idle,sesion timeout
 shivap      02/10/16 - Added properties related to remember password
 asashiss    02/04/16 - Creation
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

+ (NSDictionary *)parseConfigurationURL: (NSURL *)configURL
                  persistInUserDefaults: (BOOL)persist
                                withKey: (NSString *)key;

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;
- (BOOL)isValidString:(NSString*)str;
- (BOOL)isValidUrl:(NSString *)url;
+ (BOOL)isValidNumber:(id)object inRange:(NSRange)range;
+ (BOOL)isValidUnsignedNumber:(id)object;
+ (BOOL)boolValue:(id)object;
+ (BOOL)isWKWebViewAvailable;

@end
