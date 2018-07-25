/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "NSData+OMBase32.h"

///////////////////////////////////////////////////////////////////////////////
// Mapping from 6 bit pattern to ASCII character.
///////////////////////////////////////////////////////////////////////////////
static unsigned char base32EncodeLookup[33] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

///////////////////////////////////////////////////////////////////////////////
// Definition for "masked-out" areas of the base64DecodeLookup mapping
///////////////////////////////////////////////////////////////////////////////
#define xx 33
#define yy 34

///////////////////////////////////////////////////////////////////////////////
// Mapping from ASCII character to 6 bit pattern.
///////////////////////////////////////////////////////////////////////////////
static unsigned char base32DecodeLookup[256] =
{
  /*        0   1   2   3   4   5   6   7   8   9 */
  /*000*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*010*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*020*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*030*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*                                        0,  1 */
  /*040*/  xx, xx, xx, 62, xx, xx, xx, xx, xx, xx,
  /*        2,  3,  4,  5,  6,  7,  8,  9         */
  /*050*/  26, 27, 28, 29, 30, 31, xx, xx, xx, xx,
  /*                            A,  B,  C,  D,  E */
  /*060*/  xx, yy, xx, xx, xx,  0,  1,  2,  3,  4,
  /*        F,  G,  H,  I,  J,  K,  L,  M,  N,  O */
  /*070*/   5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  /*        P,  Q,  R,  S,  T,  U,  V,  W,  X,  Y */
  /*080*/  15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
  /*        Z,                          a,  b,  c */
  /*090*/  25, xx, xx, xx, xx, xx, xx,  0,  1,  2,
  /*        d,  e,  f,  g,  h,  i,  j,  k,  l,  m */
  /*100*/   3,  4,  5,  6,  7,  8,  9, 10, 11, 12,
  /*        n,  o,  p,  q,  r,  s,  t,  u,  v,  w */
  /*110*/  13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
  /*        x,  y,  z                             */
  /*120*/  23, 24, 25, xx, xx, xx, xx, xx, xx, xx,
  /*130*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*140*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*150*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*160*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*170*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*180*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*190*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*200*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*210*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*220*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*230*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*240*/  xx, xx, xx, xx, xx, xx, xx, xx, xx, xx,
  /*250*/  xx, xx, xx, xx, xx, xx,
};

///////////////////////////////////////////////////////////////////////////////
// Fundamental sizes of the binary and base32 encode/decode units in bytes
///////////////////////////////////////////////////////////////////////////////
#define BINARY_UNIT_SIZE 5
#define BASE32_UNIT_SIZE 8
#define OM_NUM_BITS      8

///////////////////////////////////////////////////////////////////////////////
// C function that decodes the base32 ASCII string in the inputBuffer to a
// newly malloced output buffer.
//
//  inputBuffer  - the source ASCII string for the decode
//	length       - the length of the string or -1 (to specify strlen should be
//                 used)
//	outputLength - if valid pointer is passed, upon funtion return, this
//                 argument will contain the decoded data's length
//
// Returns the decoded buffer. Memory must be released by caller by calling
// free() function. Length of decoded buffer is given by outputLength argument.
///////////////////////////////////////////////////////////////////////////////
void *OMBase32Decode(const char *inputBuffer,
                     size_t length,
                     size_t *outputLength)
{
    size_t   outputBufferSize    = 0;
    size_t   currentPos          = 0;
    size_t   inputBytesProcessed = 0;
    char    *outputBuffer        = nil;
    
	if (length == -1)
	{
		length = strlen(inputBuffer);
	}
    
    outputBufferSize = (((length+BASE32_UNIT_SIZE-1)/ BASE32_UNIT_SIZE)*BINARY_UNIT_SIZE)+1;
    outputBuffer = (char *)malloc(sizeof(char)*outputBufferSize);

    if (outputBuffer == nil)
        return nil;
    
    while (inputBytesProcessed < length)
    {
        size_t decodedlen = 0;
        char buffer[BASE32_UNIT_SIZE+1] = "";
        size_t  copysize = ((length - inputBytesProcessed) > BASE32_UNIT_SIZE) ?
                           BASE32_UNIT_SIZE : (length - inputBytesProcessed);
        strncpy(buffer, inputBuffer+inputBytesProcessed, copysize);
        buffer[copysize] = '\0';

        for (size_t cpos = 0; cpos < copysize; cpos++)
        {
            buffer[cpos] = base32DecodeLookup[inputBuffer[inputBytesProcessed+cpos]];
            if (buffer[cpos] == yy)
            {
                if ((length-inputBytesProcessed) != 8)
                {
                    free(outputBuffer);
                    outputBuffer = nil;
                    break;
                }
                else
                    buffer[cpos] = '\0';
            } //if block
            else if (buffer[cpos] == xx)
            {
                free(outputBuffer);
                outputBuffer = nil;
            }
            else
                decodedlen++;
        } //for loop

        inputBytesProcessed += copysize;
        if (outputBuffer == nil)
        {
            *outputLength = 0;
            break;
        }

        if (decodedlen >= 2)
        {
            outputBuffer[currentPos] = (buffer[0] << 3) | (buffer[1] >> 2);
            currentPos++;
        }
        
        if (decodedlen >= 4)
        {
            outputBuffer[currentPos] = (buffer[1] << 6) | (buffer[2] << 1) |
                                       (buffer[3]>>4);
            currentPos++;
        }
        
        if (decodedlen >= 5)
        {
            outputBuffer[currentPos] = (buffer[3]<<4) | (buffer[4]>>1);
            currentPos++;
        }
        
        if (decodedlen >= 7)
        {
            outputBuffer[currentPos] = (buffer[4] << 7) | (buffer[5] << 2) | (buffer[6]>>3);
            currentPos++;
        }
        
        if (decodedlen == 8)
        {
            outputBuffer[currentPos] = buffer[6] << 5 | buffer[7];
            currentPos++;
        }
    }

    if (outputBuffer)
    {
        //outputBuffer[currentPos] = '\0';
        *outputLength = currentPos;
    }
    return outputBuffer;
}


///////////////////////////////////////////////////////////////////////////////
// C function that encodes arbitrary date in the buffer as Base32 encoded ASCII
// string in a newly malloced output buffer.
//
//  buffer       - the source data to be encoded
//	length       - the length of the string or -1 (to specify strlen should be
//                 used)
//  addPadding   - Identifies if padding has to be added or not
//	outputLength - if valid pointer is passed, upon funtion return, this
//                 argument will contain the encoded string's length
//
// Returns the encoded buffer. Memory must be released by caller by calling
// free() function. Length of decoded buffer is given by outputLength argument.
///////////////////////////////////////////////////////////////////////////////
char *OMBase32Encode(const void *buffer,
                     size_t length,
                     bool addPadding,
                     size_t *outputLength)
{
    size_t outputSize           = 0;
    char   *outputBuffer        = nil;
    char   *currentInputBuffer  = (char *)buffer;
    char   *currentOutputBuffer = nil;
    size_t  remainingLength     = length;
    size_t  currentLoc          = 0;
    
    outputSize = (((length/BINARY_UNIT_SIZE) +
                   ((length%BINARY_UNIT_SIZE) ? 1 : 0)) * BASE32_UNIT_SIZE) + 1;
    outputBuffer = (char *)malloc(sizeof(char)*outputSize);

    if (outputBuffer == nil)
        return nil;
    
    currentOutputBuffer = outputBuffer;
    
    while (remainingLength > 0)
    {
        size_t currentLength = (remainingLength >= 5) ? 5 : remainingLength;
        remainingLength -= currentLength;
        
        switch (currentLength)
        {
            case 5:
                currentOutputBuffer[0] = base32EncodeLookup[(currentInputBuffer[0]&0xF8) >> 3];
                currentOutputBuffer[1] = base32EncodeLookup[((currentInputBuffer[0]&0x07) << 2) |
                                                            ((currentInputBuffer[1]&0xC0) >> 6)];
                currentOutputBuffer[2] = base32EncodeLookup[((currentInputBuffer[1]&0x3E) >> 1)];
                currentOutputBuffer[3] = base32EncodeLookup[((currentInputBuffer[1]&0x01) << 4) |
                                                            ((currentInputBuffer[2]&0xF0) >> 4)];
                currentOutputBuffer[4] = base32EncodeLookup[((currentInputBuffer[2]&0x0F) << 1) |
                                                            ((currentInputBuffer[3]&0x80) >> 7)];
                currentOutputBuffer[5] = base32EncodeLookup[((currentInputBuffer[3]&0x7C) >> 2)];
                currentOutputBuffer[6] = base32EncodeLookup[((currentInputBuffer[3]&0x03) << 3) |
                                                            ((currentInputBuffer[4]&0xE0) >> 5)];
                currentOutputBuffer[7] = base32EncodeLookup[(currentInputBuffer[4]&0x1F)];
                currentInputBuffer = currentInputBuffer+currentLength;
                currentOutputBuffer = currentOutputBuffer+BASE32_UNIT_SIZE;
                currentLoc += BASE32_UNIT_SIZE;
                break;
            case 4:
                currentOutputBuffer[0] = base32EncodeLookup[(currentInputBuffer[0]&0xF8) >> 3];
                currentOutputBuffer[1] = base32EncodeLookup[((currentInputBuffer[0]&0x07) << 2) |
                                                            ((currentInputBuffer[1]&0xC0) >> 6)];
                currentOutputBuffer[2] = base32EncodeLookup[((currentInputBuffer[1]&0x3E) >> 1)];
                currentOutputBuffer[3] = base32EncodeLookup[((currentInputBuffer[1]&0x01) << 4) |
                                                            ((currentInputBuffer[2]&0xF0) >> 4)];
                currentOutputBuffer[4] = base32EncodeLookup[((currentInputBuffer[2]&0x0F) << 1) |
                                                            ((currentInputBuffer[3]&0x80) >> 7)];
                currentOutputBuffer[5] = base32EncodeLookup[((currentInputBuffer[3]&0x7C) >> 2)];
                currentOutputBuffer[6] = base32EncodeLookup[((currentInputBuffer[3]&0x03) << 3)];
                if (addPadding)
                    currentOutputBuffer[7] = '=';
                currentLoc += (addPadding) ? BASE32_UNIT_SIZE : 7;
                break;
            case 3:
                currentOutputBuffer[0] = base32EncodeLookup[(currentInputBuffer[0]&0xF8) >> 3];
                currentOutputBuffer[1] = base32EncodeLookup[((currentInputBuffer[0]&0x07) << 2) |
                                                            ((currentInputBuffer[1]&0xC0) >> 6)];
                currentOutputBuffer[2] = base32EncodeLookup[((currentInputBuffer[1]&0x3E) >> 1)];
                currentOutputBuffer[3] = base32EncodeLookup[((currentInputBuffer[1]&0x01) << 4) |
                                                            ((currentInputBuffer[2]&0xF0) >> 4)];
                currentOutputBuffer[4] = base32EncodeLookup[((currentInputBuffer[2]&0x0F) << 1)];
                if (addPadding)
                {
                    currentOutputBuffer[5] = '=';
                    currentOutputBuffer[6] = '=';
                    currentOutputBuffer[7] = '=';
                }
                currentLoc += (addPadding) ? BASE32_UNIT_SIZE : 5;
                break;
            case 2:
                currentOutputBuffer[0] = base32EncodeLookup[(currentInputBuffer[0]&0xF8) >> 3];
                currentOutputBuffer[1] = base32EncodeLookup[((currentInputBuffer[0]&0x07) << 2) |
                                                            ((currentInputBuffer[1]&0xC0) >> 6)];
                currentOutputBuffer[2] = base32EncodeLookup[((currentInputBuffer[1]&0x3E) >> 1)];
                currentOutputBuffer[3] = base32EncodeLookup[((currentInputBuffer[1]&0x01) << 4)];
                if (addPadding)
                {
                    currentOutputBuffer[4] = '=';
                    currentOutputBuffer[5] = '=';
                    currentOutputBuffer[6] = '=';
                    currentOutputBuffer[7] = '=';
                }                
                currentLoc += (addPadding) ? BASE32_UNIT_SIZE : 4;
                break;
            case 1:
                currentOutputBuffer[0] = base32EncodeLookup[(currentInputBuffer[0]&0xF8) >> 3];
                currentOutputBuffer[1] = base32EncodeLookup[(currentInputBuffer[0]&0x07) << 2];
                if (addPadding)
                {
                    currentOutputBuffer[2] = '=';
                    currentOutputBuffer[3] = '=';
                    currentOutputBuffer[4] = '=';
                    currentOutputBuffer[5] = '=';
                    currentOutputBuffer[6] = '=';
                    currentOutputBuffer[7] = '=';
                }
                currentLoc += (addPadding) ? BASE32_UNIT_SIZE : 2;
                break;
            default:
                break;
        } //switch block
    } //while loop
	
    outputBuffer[currentLoc] ='\0';
    *outputLength = currentLoc;
    return outputBuffer;
}

@implementation NSData (OMBase32)

///////////////////////////////////////////////////////////////////////////////
// dataFromBase32String:
//
// Creates an NSData object containing the base32 decoded representation of
// the base64 string 'aString'
//
// Parameters:
//    aString - the base32 string to decode
//
// returns the autoreleased NSData representation of the base32 string
///////////////////////////////////////////////////////////////////////////////
+ (NSData *)dataFromBase32String:(NSString *)aString
{
	NSData *data        = [aString dataUsingEncoding:NSASCIIStringEncoding];
	size_t outputLength = 0;
	void *outputBuffer  = OMBase32Decode([data bytes], [data length], &outputLength);
	NSData *result      = nil;
    
    if (outputBuffer)
    {
        result = [NSData dataWithBytes:outputBuffer length:outputLength];
        free(outputBuffer);
    }

    return (result.length > 0) ? result : nil;
}

///////////////////////////////////////////////////////////////////////////////
// base32EncodedString
//
// Creates an NSString object that contains the base 32 encoding of the
// receiver's data
//
// returns an autoreleased NSString being the base 32 representation of the
//receiver.
///////////////////////////////////////////////////////////////////////////////
- (NSString *)base32EncodedString
{
	size_t outputLength = 0;
	char *outputBuffer = OMBase32Encode([self bytes], [self length], true,
                                        &outputLength);
	
	NSString *result = [[NSString alloc] initWithBytes:outputBuffer
                                                 length:outputLength
                                              encoding:NSASCIIStringEncoding];
	free(outputBuffer);
	return result ;
}

@end
