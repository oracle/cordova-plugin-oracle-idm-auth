/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@interface OMUtilities : NSObject

+ (NSString *)keystoreDirectoryName;
+ (NSString *)localAuthDirectoryName;
+ (NSString *)omaDirectoryPath;
+ (NSString *)secureDirectoryName;

+ (NSString *)filePathForfile:(NSString*)fileName inDirectory:(NSString*)directory
                        error:(NSError **)error;


@end
