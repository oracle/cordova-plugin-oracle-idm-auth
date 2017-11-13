/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMAuthData.h"

@interface OMAuthData ()

@property (nonatomic, strong) NSData *data;

@end

@implementation OMAuthData

- (instancetype)initWithData:(NSData*)data;
{
    self = [super init];
    
    if (self)
    {
        _data = data;
    }
    
    return self;
}

- (NSData *)data
{
    return _data;
}
- (NSString*)authDataStr
{
    return [[NSString alloc] initWithData:self.data encoding:NSUTF8StringEncoding];
}

@end
