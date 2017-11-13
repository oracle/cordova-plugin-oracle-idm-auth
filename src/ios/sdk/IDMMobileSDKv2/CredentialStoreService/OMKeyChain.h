/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@interface OMKeyChain : NSObject

+ (void)setItem:(id)item forKey:(NSString*)key
    accessGroup:(NSString *)accessGroup;

+ (void)setItem:(id)item forKey:(NSString*)key
    accessGroup:(NSString *)accessGroup dataAccessibleLevel:(CFTypeRef)protectionLevel;

+ (id)itemForKey:(NSString*)key accessGroup:(NSString *)accessGroup;

+ (void)deleteItemForKey:(NSString*)key accessGroup:(NSString *)accessGroup;


@end
