/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthorizationGrant.h"
#import "OMOAuthWebViewHandler.h"

@interface OMImplicitGrant : OMAuthorizationGrant
@property (nonatomic, strong) OMOAuthWebViewHandler *handler;
@end
