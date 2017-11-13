/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

void *OMBase32Decode(const char *inputBuffer,
                     size_t length,
                     size_t *outputLength);

char *OMBase32Encode(const void *inputBuffer,
                     size_t length,
                     bool separateLines,
                     size_t *outputLength);


@interface NSData (OMBase32)
{
    
}

+ (NSData *)dataFromBase32String:(NSString *)aString;
- (NSString *)base32EncodedString;

@end
