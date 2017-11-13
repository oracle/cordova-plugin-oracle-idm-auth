/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

@interface OMWKWebViewClient : NSObject

@property (nonatomic, weak) WKWebView *clientWebView;

- (instancetype)initWithWKWebView:(WKWebView *)webView callBackDelegate:(id)del;

- (void)loadRequest:(NSURLRequest*)request;
- (void)stopRequest;


- (void)cookiesForVisitedHosts:(NSMutableArray*)visitedHosts completionHandler:
(void (^)(NSArray<WKWebsiteDataRecord *> *))completionHandler;

@end
