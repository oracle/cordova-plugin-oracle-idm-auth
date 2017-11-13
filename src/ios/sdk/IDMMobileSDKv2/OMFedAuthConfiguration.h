/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMMobileSecurityConfiguration.h"

@interface OMFedAuthConfiguration : OMMobileSecurityConfiguration

@property (nonatomic, strong) NSSet *requiredTokens;
@property (nonatomic, strong) NSURL *loginSuccessURL;
@property (nonatomic, strong) NSURL *loginFailureURL;
@property (nonatomic, strong) NSURL *loginURL;
@property (nonatomic, strong) NSURL *logoutURL;
@property (nonatomic, strong) NSURL *logoutSuccessURL;
@property (nonatomic, strong) NSURL *logoutFailureURL;
@property (nonatomic, strong) NSSet *confirmLogoutButtons;

@property (nonatomic) BOOL parseTokenRelayResponse;
@property (nonatomic, readonly) BOOL enableWKWebView;
@property (nonatomic) BOOL autoConfirmLogout;

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;

@end
