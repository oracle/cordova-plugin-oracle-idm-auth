/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>
#import "OMOAuthAuthenticationService.h"

typedef void (^OMOpenIDCUserInfoCallback)(NSMutableDictionary *_Nullable userinfo,
                                          NSError *_Nullable error);

@interface OMOpenIDCAuthenticationService : OMOAuthAuthenticationService

@property (nonatomic, strong) NSString *_Nullable idToken;

- (void)userInfoWithCompletion:(OMOpenIDCUserInfoCallback _Null_unspecified)completion;

@end
