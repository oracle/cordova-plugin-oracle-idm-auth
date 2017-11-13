/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>

@interface OMAuthData : NSObject

- (instancetype)initWithData:(NSData*)data;

- (NSData *)data;
- (NSString*)authDataStr;
@end
