/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@interface OMDataSerializationHelper : NSObject

+ (BOOL)serializeData:(id)data toFile:(NSString*)filePath;
+ (id)deserializeDataFromFile:(NSString*)filePath;

+ (id)serializeData:(id)data;
+ (id)deserializeData:(id)data;

@end
