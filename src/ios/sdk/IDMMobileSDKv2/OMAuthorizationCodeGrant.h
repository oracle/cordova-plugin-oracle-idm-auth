/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthorizationGrant.h"
#import "OMOAuthWebViewHandler.h"

@interface OMAuthorizationCodeGrant : OMAuthorizationGrant
@property (nonatomic, strong) NSString *authCode;
@property (nonatomic) volatile int32_t finished;
@property (nonatomic, strong) OMOAuthWebViewHandler *handler;
@property (nonatomic, strong) NSString *codeChallenge;
@property (nonatomic, strong) NSString *codeVerifier;
@end
