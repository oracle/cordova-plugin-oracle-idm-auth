/* Copyright (c) 2013, Oracle and/or its affiliates. All rights reserved.*/

/*
 NAME
   NSData+OMBase32.h - NSData Category to support Base32 encoding & decoding
 
 DESCRIPTION
   Base32 encoding methods to NSData object
 
 RELATED DOCUMENTS
   None
 
 PROTOCOLS
   None
 
 EXAMPLES
   None
 
 NOTES
   None
 
 MODIFIED   (MM/DD/YY)
 sativenk    09/23/13 - Creation
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
