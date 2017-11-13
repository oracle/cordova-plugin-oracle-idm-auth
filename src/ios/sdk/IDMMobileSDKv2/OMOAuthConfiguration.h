/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMMobileSecurityConfiguration.h"
#import "OMObject.h"

enum{
    OMOAuthResourceOwner,
    OMOAuthAuthorizationCode,
    OMAOAuthClientCredential,
    OMOAuthImplicit,
    OMOAuthAssertion,
    OMOAuthOAMCredential
};
typedef NSUInteger OMOAuthGrantType;

enum
{
    OMBrowserModeEmbedded = 1,
    OMBrowserModeExternal = 2,
    OMBrowserModeSafariVC = 3
};
typedef NSUInteger OMBrowserMode;

@interface OMOAuthConfiguration : OMMobileSecurityConfiguration
@property (nonatomic) OMOAuthGrantType grantType;
@property (nonatomic, strong) NSURL *tokenEndpoint;
@property (nonatomic, strong) NSURL *authEndpoint;
@property (nonatomic, strong) NSString *clientSecret;
@property (nonatomic, strong) NSString *clientId;
@property (nonatomic, strong) NSSet *scope;
@property (nonatomic, strong) NSURL *redirectURI;
@property (nonatomic, strong) NSString *state;
@property (nonatomic, strong) NSString *clientAssertion;
@property (nonatomic, strong) NSString *clientAssertionType;
@property (nonatomic) BOOL includeClientHeader;
@property (nonatomic, strong) NSString *userAssertionType;
@property (nonatomic, strong) NSString *userAssertion;
@property (nonatomic, strong) NSURL *logoutURL;
@property (nonatomic,) BOOL offlineAuthAllowed;
@property (nonatomic) OMConnectivityMode connectivityMode;
@property (nonatomic) OMBrowserMode browserMode;
@property (nonatomic) BOOL enablePkce;
@property (nonatomic) BOOL isClientRegistrationRequired;
@property (nonatomic) NSURL *clientRegistrationEndpoint;
@property (nonatomic, strong) NSString *loginHint;
@property (nonatomic, strong) NSURL *discoverEndpoint;


- (NSInteger)setConfiguration:(NSDictionary *) properties;
-(void)parseConfigData:(NSDictionary *)json;

- (NSURL*)discoveryUrl;

@end
