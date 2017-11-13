/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import "OMOTPService.h"
#import "NSData+OMBase64.h"
#import "OMErrorCodes.h"

@interface OMOTPService()

@property(nonatomic, readwrite, retain) NSData *sharedSecret;
@property(nonatomic, readwrite) uint64_t counter;
@property(nonatomic, readwrite) uint64_t incrementBy;
@property(nonatomic, readwrite) uint64_t baseTime;
@property(nonatomic, readwrite) uint64_t timeSteps;
@property(nonatomic, readwrite) uint64_t numDigitsInOTP;
@property(nonatomic, readwrite) BOOL     addCheckSum;
@property(nonatomic, readwrite) BOOL     isHOTP;
@property(nonatomic, readwrite) OMCryptoAlgorithm algorithm;

@end

@implementation OMOTPService

@synthesize sharedSecret = _sharedSecret;
@synthesize counter = _counter;
@synthesize incrementBy = _incrementBy;
@synthesize baseTime = _baseTime;
@synthesize timeSteps = _timeSteps;
@synthesize numDigitsInOTP = _numDigitsInOTP;
@synthesize addCheckSum = _addCheckSum;
@synthesize isHOTP = _isHOTP;
@synthesize algorithm = _algorithm;

///////////////////////////////////////////////////////////////////////////////
// Initializer for HMAC based One-Time Password (HOTP) using SHA1 hashing
// algorithm
///////////////////////////////////////////////////////////////////////////////
- (id) initForHOTPWithSharedKey: (NSData *)key
             andStartingCounter: (uint64_t)counter
                    incrementBy: (long)incrementValue
            requiredDigitsInOTP: (unsigned long)numDigits
               addCheckSumToOTP: (BOOL)addCheckSum
{
    return [self initForHOTPWithSharedKey:key
                       andStartingCounter:counter
                              incrementBy:incrementValue
                         hashingAlgorithm:OMAlgorithmSHA1
                      requiredDigitsInOTP:numDigits
                         addCheckSumToOTP:addCheckSum];
}

///////////////////////////////////////////////////////////////////////////////
// Initializer for HMAC based One-Time Password (HOTP) using app specified
// hashing algorithm
///////////////////////////////////////////////////////////////////////////////
- (id) initForHOTPWithSharedKey: (NSData *)key
             andStartingCounter: (uint64_t)counter
                    incrementBy: (long)incrementValue
               hashingAlgorithm: (OMCryptoAlgorithm)algorithm
            requiredDigitsInOTP: (unsigned long)numDigits
               addCheckSumToOTP: (BOOL)addCheckSum
{
    self = [super init];
    
    if (self)
    {
        _sharedSecret = key;
        _counter = counter;
        _incrementBy = incrementValue;
        if (_incrementBy < 1)
            _incrementBy = 1;
        _numDigitsInOTP = numDigits;
        if (_numDigitsInOTP < 1)
            _numDigitsInOTP = 6;
        _addCheckSum = addCheckSum;
        _isHOTP = TRUE;
        _algorithm = algorithm;
    }
    
    return self;
}

///////////////////////////////////////////////////////////////////////////////
// Initializer for Time-based One-Time Password
///////////////////////////////////////////////////////////////////////////////
- (id) initForTOTPWithSharedKey: (NSData *)key
              baseTimeInSeconds: (uint64_t)referenceTime
              timeStepInSeconds: (NSUInteger)timeSteps
               hashingAlgorithm: (OMCryptoAlgorithm)algorithm
            requiredDigitsInOTP: (NSUInteger)numDigits
                    useCheckSum: (BOOL)addCheckSum
{
    self = [super init];
    
    if (self)
    {
        _sharedSecret = key;
        _baseTime = referenceTime;
        _timeSteps = timeSteps;
        if (_timeSteps < 1)
            _timeSteps = 30;
        _numDigitsInOTP = numDigits;
        if (_numDigitsInOTP < 1)
            _numDigitsInOTP = 6;
        _addCheckSum = addCheckSum;
        _isHOTP = FALSE;
        _algorithm = algorithm;
    }
    
    return self;
}

///////////////////////////////////////////////////////////////////////////////
// Returns OTP for current counter or time as NSString object. In case of HOTP,
// it increases counter value too.
///////////////////////////////////////////////////////////////////////////////
- (NSString *) OTPAsStringReturningError: (NSError **)error
{
    uint64_t   otp       = [self OTPAsIntReturningError:error];
    
    NSString  *otpstring = nil;
    if (otp)
    {
        otpstring = [[NSString alloc] initWithFormat:@"%lld", otp];
    }
    
    return otpstring;
}

///////////////////////////////////////////////////////////////////////////////
// Returns OTP for current counter or time. In case of HOTP, it increases
// counter value too.
///////////////////////////////////////////////////////////////////////////////
- (uint64_t) OTPAsIntReturningError: (NSError **)error
{
    NSError       *lError = nil;
    uint64_t       otp    = 0;
    
    if (self.isHOTP)
    {
        otp = [OMOTPService OTPForCounter:self.counter
                    usingHashingAlgorithm:self.algorithm
                                   andKey:self.sharedSecret
                      requiredDigitsInOTP:(NSUInteger)self.numDigitsInOTP
                              addCheckSum:self.addCheckSum
                                 outError:&lError];
        if (lError)
        {
            if (error)
                *error =lError;
        }
        else
            self.counter += self.incrementBy;
    }
    else
    {
        NSDate *currentDate = [NSDate date];
        uint64_t timeSince1970 = (uint64_t)[currentDate timeIntervalSince1970];
        uint64_t counter = (timeSince1970 - self.baseTime)/self.timeSteps;
        
        otp = [OMOTPService OTPForCounter:counter
                    usingHashingAlgorithm:self.algorithm
                                   andKey:self.sharedSecret
                      requiredDigitsInOTP:(NSUInteger)self.numDigitsInOTP
                              addCheckSum:self.addCheckSum
                                 outError:&lError];
    }
    
    return otp;
}

#pragma mark class methods

///////////////////////////////////////////////////////////////////////////////
// Converts given byte array into hex formatted string
///////////////////////////////////////////////////////////////////////////////
+ (NSString *)convertByteAsHexFormattedString: (Byte *)byteData
                                       length: (NSUInteger)length
{
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:length];
    for (int counter = 0; counter < length; counter++)
    {
        [string appendFormat:@"%02x", byteData[counter]];
    }
    return string;
}

///////////////////////////////////////////////////////////////////////////////
// Converts given string into byte using NSUTF8StringEncoding and formats
// it as hex formatted string
///////////////////////////////////////////////////////////////////////////////
+ (NSString *)convertStringAsHexFormattedString: (NSString *)string
{
    NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [OMOTPService convertDataAsHexFormattedString:data];
}

///////////////////////////////////////////////////////////////////////////////
// Converts given NSData into byte and formats it as hex formatted string
///////////////////////////////////////////////////////////////////////////////
+ (NSString *)convertDataAsHexFormattedString: (NSData *)data
{
    return [OMOTPService convertByteAsHexFormattedString:(Byte *)[data bytes]
                                                  length:[data length]];
}

///////////////////////////////////////////////////////////////////////////////
// Computes OTP using alorithm defined in RFC 4226/6238
///////////////////////////////////////////////////////////////////////////////
+ (uint64_t) OTPForCounter: (uint64_t)counter
     usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                    andKey: (NSData *)secret
       requiredDigitsInOTP: (NSUInteger)numberOfDigits
               addCheckSum: (BOOL)useCheckSum
                  outError: (NSError **)error
{
    NSData *counterData = [OMOTPService convertInt64ToNSData:counter];
    return [OMOTPService OTPForData:counterData
              usingHashingAlgorithm:algorithm
                             andKey:secret
                requiredDigitsInOTP:numberOfDigits
                        addCheckSum:useCheckSum
                           outError:error];
}

///////////////////////////////////////////////////////////////////////////////
// Computes OTP using alorithm defined in RFC 4226/6238
///////////////////////////////////////////////////////////////////////////////
+ (uint64_t) OTPForText: (NSString *)text
  usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                 andKey: (NSData *)secret
    requiredDigitsInOTP: (NSUInteger)numberOfDigits
            addCheckSum: (BOOL)useCheckSum
               outError: (NSError **)error
{
    NSData *counterData = [text dataUsingEncoding:NSUTF8StringEncoding];
    return [OMOTPService OTPForData:counterData
              usingHashingAlgorithm:algorithm
                             andKey:secret
                requiredDigitsInOTP:numberOfDigits
                        addCheckSum:useCheckSum
                           outError:error];
}

///////////////////////////////////////////////////////////////////////////////
// Computes TOTP using alorithm defined in RFC 6238
///////////////////////////////////////////////////////////////////////////////
+ (uint64_t) TOTPForTime: (uint64_t)currentElapsedTimeSince1970
   usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                baseTime: (uint64_t)baseTime
                timeStep: (uint64_t)timeStep
                  andKey: (NSData *)secret
     requiredDigitsInOTP: (NSUInteger)numberOfDigits
             addCheckSum: (BOOL)useCheckSum
                outError: (NSError **)error
{
    uint64_t counter = (currentElapsedTimeSince1970 - baseTime)/timeStep;
    
    return [OMOTPService OTPForCounter:counter
                 usingHashingAlgorithm:algorithm
                                andKey:secret
                   requiredDigitsInOTP:numberOfDigits
                           addCheckSum:useCheckSum
                              outError:error];
}


+ (uint64_t) TOTPusingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                              timeStep: (uint64_t)timeStep
                                andKey: (NSData *)key
                   requiredDigitsInOTP: (NSUInteger)numberOfDigits
                           addCheckSum: (BOOL)useCheckSum
                              outError: (NSError **)error
                             expiresIn:(uint64_t *)validity
{
    uint64_t  otp = 0;
    NSDate *currentDate = [NSDate date];
    uint64_t timeSince1970 = (uint64_t)[currentDate timeIntervalSince1970];
    uint64_t counter = (timeSince1970 - 0)/timeStep;
    
    otp  = [OMOTPService OTPForCounter:counter
                 usingHashingAlgorithm:algorithm
                                andKey:key
                   requiredDigitsInOTP:numberOfDigits
                           addCheckSum:useCheckSum
                              outError:error];
    if (validity)
        *validity = timeStep - (timeSince1970%timeStep);
    
    
    return otp;
}


///////////////////////////////////////////////////////////////////////////////
// Computes OTP using alorithm defined in RFC 4226/6238
///////////////////////////////////////////////////////////////////////////////
+ (uint64_t) OTPForData: (NSData *)data
  usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                 andKey: (NSData *)secret
    requiredDigitsInOTP: (NSUInteger)numberOfDigits
            addCheckSum: (BOOL)useCheckSum
               outError: (NSError **)error
{
    NSError       *lError = nil;
    
    NSData *hmac = [OMOTPService computeHashMACForData:data
                                  usingHashingAlgoritm:algorithm
                                                andKey:secret
                                      base64EncodeHMAC:FALSE
                                              outError:&lError];
    
    if (lError)
    {
        if (error)
            *error = lError;
        return 0;
    }
    Byte *hmacByte = nil;
    if([hmac length] > 0)
    {
        hmacByte = (Byte *)malloc(sizeof(Byte)*[hmac length]);
    }
    if (nil == hmacByte)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_MEMORY_ALLOCATION_FAILURE];
        return 0;
    }
    [hmac getBytes:hmacByte length:[hmac length]];
    
    int  offsetloc = (int)(hmacByte[[hmac length] - 1] & 0xf);
    uint64_t truncatedVal   = (((hmacByte[offsetloc] & 0x7f) << 24) |
                               ((hmacByte[offsetloc+1] & 0xff) << 16) |
                               ((hmacByte[offsetloc+2] & 0xff) << 8) |
                               (hmacByte[offsetloc+3] & 0xff));
    
    uint64_t  divisor = pow(10, numberOfDigits);
    uint64_t  otp = truncatedVal % divisor;
    free(hmacByte);
    return otp;
}

///////////////////////////////////////////////////////////////////////////////
// Converts Byte to Binary format and stores it in NSString
///////////////////////////////////////////////////////////////////////////////
+ (NSString *)convertByteToBinaryString: (Byte)val
{
    NSMutableString *string = [[NSMutableString alloc] initWithCapacity:8];
    int array[] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    
    for (int i = 7; i >= 0; i--)
    {
        if ((val & array[i]) == array[i])
            [string appendFormat:@"%1d", 1];
        else
            [string appendFormat:@"%1d", 0];
    }
    return string;
}

///////////////////////////////////////////////////////////////////////////////
// Converts uint64_t data to Binary array
///////////////////////////////////////////////////////////////////////////////
+ (Byte *)convertInt64ToByte: (uint64_t)number
{
    int    size      = sizeof(uint64_t);
    Byte  *byteVal   = nil;
    
    byteVal = (Byte *)malloc(sizeof(Byte)*size);
    
    for (int counter = size-1; counter >= 0; counter--)
    {
        byteVal[counter] = (Byte)(number & 0xFF);
        number >>= 8;
    }
    
    return byteVal;
}

///////////////////////////////////////////////////////////////////////////////
// Converts uint64_t data to NSData
///////////////////////////////////////////////////////////////////////////////
+ (NSData *)convertInt64ToNSData: (uint64_t)number
{
    Byte *byteVal = [OMOTPService convertInt64ToByte:number];
    NSData *data = [[NSData alloc] initWithBytes:byteVal length:sizeof(uint64_t)];
    free(byteVal);
    return data;
}

///////////////////////////////////////////////////////////////////////////////
// Computes HMAC using algorithm given in RFC 2104
///////////////////////////////////////////////////////////////////////////////
+ (id) computeHashMACForData: (NSData *)data
        usingHashingAlgoritm: (OMCryptoAlgorithm)algorithm
                      andKey: (NSData *)key
            base64EncodeHMAC: (BOOL)encode
                    outError: (NSError **)error
{
    NSUInteger     blockLength         = 0;
    Byte          *opad                = nil;
    Byte          *ipad                = nil;
    NSData        *newKey              = nil;
    NSMutableData *hashData            = nil;
    NSError       *lError              = nil;
    
    //Step #1:
    //Get hash length for the chosen hashing algorithm
    switch (algorithm)
    {
        case OMAlgorithmMD5:
            blockLength = CC_MD5_BLOCK_BYTES;
            break;
        case OMAlgorithmSHA1:
            blockLength = CC_SHA1_BLOCK_BYTES;
            break;
        case OMAlgorithmSHA224:
            blockLength = CC_SHA224_BLOCK_BYTES;
            break;
        case OMAlgorithmSHA256:
            blockLength = CC_SHA256_BLOCK_BYTES;
            break;
        case OMAlgorithmSHA384:
            blockLength = CC_SHA384_BLOCK_BYTES;
            break;
        case OMAlgorithmSHA512:
            blockLength = CC_SHA512_BLOCK_BYTES;
            break;
        default:
            // unsupported algorithm
            if (error)
                *error = [OMObject
                          createErrorWithCode:OMERR_UNKNOWN_OR_UNSUPPORTED_ALGORITHM];
            return nil;
    }
    
    //Step #2:
    //Ensure key length is same as block size in bits
    //If key length is longer than block size, hash the key
    //If key length is shorter than hash length, pad it with '\0'
    //Padding with '\0' takes place later
    //Else if key length is same as hash length, use it as is
    if ([key length] > blockLength)
    {
        newKey = [OMCryptoService hashData:key
                                  withSalt:nil
                                 algorithm:algorithm
                        appendSaltToOutput:FALSE
                              base64Encode:FALSE
             prefixOutputWithAlgorithmName:FALSE
                                  outError:&lError];
        if (lError)
        {
            if (error)
                *error = lError;
            return nil;
        }
    }
    else
        newKey = key;
    
    //Step #3
    //Create inner pad and outer pad to be used in HMAC
    //Inner pad is XOR of new key and character 0x36
    //Outer pad is XOR of new key and character 0x5c
    ipad = (Byte *)malloc(sizeof(Byte)*blockLength);
    opad = (Byte *)malloc(sizeof(Byte)*blockLength);
    
    if (nil == ipad || nil == opad)
    {
        free(ipad);
        free(opad);
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_MEMORY_ALLOCATION_FAILURE];
        return nil;
    }
    
    //Fill allocated memory area with 0x0
    memset(ipad, 0x0, blockLength);
    memset(opad, 0x0, blockLength);
    
    //Extract key into inner pad and outer pad so that it can be XORed with
    //0x36 and 0x5c respectively. Since we are extracting key into pad before
    //XORing, we are fine even if key length is shorted than OM_HMAC_PAD_SIZE
    [newKey getBytes:ipad length:[newKey length]];
    [newKey getBytes:opad length:[newKey length]];
    
    for (int i = 0; i < blockLength; i++)
    {
        ipad[i] = ipad[i] ^ 0x36;
        opad[i] = opad[i] ^ 0x5c;
    }
    
    //Step #4 - hash(key XOR opad + hash(key XOR ipad + data_to_be_hashed))
    //Step #4a - hash(key XOR ipad + data_to_be_hashed)
    //Compute hash of inner pad computed in step 3 prefixed to data to be
    //hashed
    hashData = [[NSMutableData alloc] initWithBytes:ipad length:blockLength];
    [hashData appendData:data];
    NSData *innerhasheddata = [OMCryptoService hashData:hashData
                                               withSalt:nil
                                              algorithm:algorithm
                                     appendSaltToOutput:FALSE
                                           base64Encode:FALSE
                          prefixOutputWithAlgorithmName:FALSE
                                               outError:&lError];
    free(ipad);
    if (lError)
    {
        free(opad);
        if (error)
            *error = lError;
        return nil;
    }
    
    //Step #4b - hash(K XOR opad + data_hashed_in_step_4a)
    //Compute hash of outer pad computed in step 3 prefixed to hash obtained
    //in step 4a
    hashData = [[NSMutableData alloc] initWithBytes:opad length:blockLength];
    [hashData appendData:innerhasheddata];
    NSData *outerhasheddata = [OMCryptoService hashData:hashData
                                               withSalt:nil
                                              algorithm:algorithm
                                     appendSaltToOutput:FALSE
                                           base64Encode:FALSE
                          prefixOutputWithAlgorithmName:FALSE
                                               outError:&lError];
    
    free(opad);
    
    if (lError)
    {
        if (error)
            *error = lError;
        return nil;
    }
    
    //Done with computing HMAC
    if (encode)
    {
        NSString *base64HMAC = [outerhasheddata base64EncodedString];
        return base64HMAC;
    }
    
    return outerhasheddata;
}

@end
///////////////////////////////////////////////////////////////////////////////
// End
///////////////////////////////////////////////////////////////////////////////
