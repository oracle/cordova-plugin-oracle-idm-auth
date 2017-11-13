/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMToken.h"

@interface OMIDCSClientRegistrationToken : OMToken

@property (nonatomic, strong) NSString *clientID;
@property (nonatomic, strong) NSString *clientName;
@property (nonatomic, strong) NSString *clientSecret;
@property (nonatomic, strong) NSArray *redirectUris;
@property (nonatomic, strong) NSArray *grantTypes;
@property (nonatomic, strong) NSString *scope;
@property (nonatomic, strong) NSString *deviceID;
@property (nonatomic, strong) NSString *appBundleID;
@property (nonatomic, strong) NSDate *clientSecretExpiryDate;

- (id)initWithInfo:(NSDictionary*)info;

- (NSDictionary*)jsonInfo;

@end


//
