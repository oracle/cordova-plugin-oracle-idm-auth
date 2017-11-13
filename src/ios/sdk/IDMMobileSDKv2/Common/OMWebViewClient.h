/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

#import <UIKit/UIKit.h>

@interface OMWebViewClient : NSObject

@property (nonatomic, weak) UIWebView *clientWebView;

- (instancetype)initWithWebView:(UIWebView *)webView callBackDelegate:(id)del;

- (void)loadRequest:(NSURLRequest*)request;
- (void)stopRequest;

@end
