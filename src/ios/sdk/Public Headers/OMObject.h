/* Copyright (c) 2013, 2015, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMObject.h - Oracle Mobile base object
 
 DESCRIPTION
 Base object for IDMMobileSDK
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    04/20/16 - Moved connectivity mode enum
 asashiss    02/04/16 - Creation
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

@end
