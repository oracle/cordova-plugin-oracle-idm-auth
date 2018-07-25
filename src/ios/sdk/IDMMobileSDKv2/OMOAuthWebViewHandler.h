/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMOAuthConfiguration.h"
#import "OMOAuthAuthenticationService.h"

@interface OMOAuthWebViewHandler : NSObject<UIWebViewDelegate>
@property (nonatomic, weak) UIWebView *webView;
@property (nonatomic, weak) OMOAuthAuthenticationService *oauthService;
@property (nonatomic) BOOL redirectURIHit;

- (void)loadRequest:(NSURLRequest*)request;
- (void)stopRequest;

@end
