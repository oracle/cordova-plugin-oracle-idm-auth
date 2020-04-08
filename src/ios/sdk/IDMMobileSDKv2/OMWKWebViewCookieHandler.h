/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface OMWKWebViewCookieHandler : NSObject

+ (void)cookiesForVisitedHosts:(NSArray*)visitedHosts completionHandler:
(void (^)(NSArray<WKWebsiteDataRecord *> *))completionHandler;

+ (void)clearWkWebViewCashForUrls:(NSArray*)visitedUrls completionHandler:(void (^) (void))completionBlock;

+ (void)clearWkWebViewCookiesForUrls:(NSArray*)visitedUrls completionHandler:(void (^) (void))completionBlock;


+ (void)deleteCookieFromWKHTTPStore:(NSHTTPCookie*)cookie;


@end

NS_ASSUME_NONNULL_END
