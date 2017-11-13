/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

enum
{
    OMConnectivityAuto = 1,
    OMConnectivityOnline = 2,
    OMConnectivityOffline = 3,
};
typedef NSUInteger OMConnectivityMode;

enum
{
    OMHttpsToHttpRedirect
};
typedef NSUInteger OMInvalidRedirectTypes;

@interface OMObject : NSObject
{
@private
    NSString      *stringObj;
    
}

+ (NSError *)createErrorWithCode:(NSInteger)code, ...;
+ (NSString *)messageForCode: (NSUInteger)code, ...;
+ (NSError *)createErrorWithCode:(NSInteger)code andMessage:(NSString *)errorMessage;
+ (BOOL)isHostReachable:(NSString *)host;
+ (BOOL)isCurrentURL:(NSURL *)currentURL EqualTo:(NSURL *)expectedURL;
+ (NSString *)version;
+ (BOOL)isNetworkReachable;

@end
