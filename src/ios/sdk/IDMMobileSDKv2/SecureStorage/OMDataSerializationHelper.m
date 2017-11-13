/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMDataSerializationHelper.h"

@implementation OMDataSerializationHelper

+ (id)serializeData:(id)data
{
    return [NSKeyedArchiver archivedDataWithRootObject:data];
}

+ (id)deserializeData:(id)data
{
    return [NSKeyedUnarchiver unarchiveObjectWithData:data];
}

+ (BOOL)serializeData:(id)data toFile:(NSString*)filePath
{
    
    return [NSKeyedArchiver archiveRootObject:data toFile:filePath];
}

+ (id)deserializeDataFromFile:(NSString*)filePath
{
    return [NSKeyedUnarchiver unarchiveObjectWithFile:filePath];

}

@end
