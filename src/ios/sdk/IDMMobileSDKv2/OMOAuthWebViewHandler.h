/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMOAuthConfiguration.h"
#import "OMOAuthAuthenticationService.h"
#import <WebKit/WebKit.h>

@interface OMOAuthWebViewHandler : NSObject
@property (nonatomic, weak) OMOAuthAuthenticationService *oauthService;
@property (nonatomic) BOOL redirectURIHit;
@property (nonatomic, weak) WKWebView *wkwebView;

- (void)loadRequest:(NSURLRequest*)request;
- (void)stopRequest;

@end
