/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@interface OMASN1Node : NSObject
{
@private
    NSMutableArray *_childList;
    NSString *_tag;
    NSString *_value;
}
@property(nonatomic, retain) NSMutableArray *childList;
@property(nonatomic, retain) NSString *tag;
@property(nonatomic, retain) NSString *value;
-(id)initWithHexString:(NSString *)string;
-(id)init;
@end
