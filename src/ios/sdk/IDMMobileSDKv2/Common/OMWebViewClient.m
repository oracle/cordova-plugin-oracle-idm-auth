/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMWebViewClient.h"

@interface OMWebViewClient ()<UIWebViewDelegate>

@property (nonatomic, weak) id<UIWebViewDelegate> clientWebViewDelegate;
@property (nonatomic, weak) id<UIWebViewDelegate> callBackDelegate;

@end

@implementation OMWebViewClient

- (instancetype)initWithWebView:(UIWebView *)webView callBackDelegate:(id)del
{
    self = [super init];
    
    if (self) {
        
       _clientWebView = webView;
        _clientWebViewDelegate =  webView.delegate;
        _callBackDelegate = del;
    }
    return self;
}

- (void)loadRequest:(NSURLRequest*)request;
{
    _clientWebView.delegate = self;
    [self.clientWebView loadRequest:request];
}

- (void)stopRequest
{
    [self.clientWebView stopLoading];
    self.clientWebView.delegate = nil;

}

- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request
    navigationType:(UIWebViewNavigationType)navigationType;
{
    if ([self.callBackDelegate respondsToSelector:@selector(webView:shouldStartLoadWithRequest:navigationType:)]) {
        [self.callBackDelegate webView:webView shouldStartLoadWithRequest:request navigationType:navigationType];
    }

    if ([self.clientWebViewDelegate respondsToSelector:@selector(webView:shouldStartLoadWithRequest:navigationType:)]) {
        [self.clientWebViewDelegate webView:webView shouldStartLoadWithRequest:request navigationType:navigationType];
    }

    return YES;
}

- (void)webViewDidStartLoad:(UIWebView *)webView
{
    if ([self.callBackDelegate respondsToSelector:@selector(webViewDidStartLoad:)]) {
        [self.callBackDelegate webViewDidStartLoad:webView];
    }

    if ([self.clientWebViewDelegate respondsToSelector:@selector(webViewDidStartLoad:)]) {
        [self.clientWebViewDelegate webViewDidStartLoad:webView];
    }

}

- (void)webViewDidFinishLoad:(UIWebView *)webView
{
    if ([self.callBackDelegate respondsToSelector:@selector(webViewDidFinishLoad:)]) {
        [self.callBackDelegate webViewDidFinishLoad:webView];
    }

    if ([self.clientWebViewDelegate respondsToSelector:@selector(webViewDidFinishLoad:)]) {
        [self.clientWebViewDelegate webViewDidFinishLoad:webView];
    }
}
- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error
{
    if ([self.callBackDelegate respondsToSelector:@selector(webView:didFailLoadWithError:)]) {
        
        [self.callBackDelegate webView:webView didFailLoadWithError:error];
    }

    if ([self.clientWebViewDelegate respondsToSelector:@selector(webView:didFailLoadWithError:)]) {
        
        [self.clientWebViewDelegate webView:webView didFailLoadWithError:error];
    }
}

@end
