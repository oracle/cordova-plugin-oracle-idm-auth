/* Copyright (c) 2013, Oracle and/or its affiliates. All rights reserved.*/

/*
 NAME
 OMOTPService.h - Oracle Mobile One Time Password Service
 
 DESCRIPTION
 This class implements HMAC based OTP and Time based OTP as per RFC 4226 and
 RFC 6238 respectively.
 
 RELATED DOCUMENTS
 None
 
 INHERITS FROM
 NSObject
 
 PROTOCOLS
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 sativenk    09/12/13 - Oracle Mobile Authenticator Changes
 sativenk    04/25/13 - Creation
 */

#import <Foundation/Foundation.h>


#import "OMObject.h"
#import "OMCryptoService.h"

@interface OMOTPService : NSObject
{
@private
    NSData           *_sharedSecret;
    uint64_t          _counter;
    uint64_t          _incrementBy;
    uint64_t          _baseTime;
    uint64_t          _timeSteps;
    uint64_t          _numDigitsInOTP;
    BOOL              _addCheckSum;
    BOOL              _isHOTP;
    OMCryptoAlgorithm _algorithm;
}

/**
 * Initializer method for Hash MAC based One-Time Password (OTP) generation as
 * per RFC 4226. This initializer method uses SHA1 algorithm for hashing.
 *
 * @param key                 Shared secret that is used for generating Hashed
 *                            Message Authentication Code (HMAC)
 * @param counter             Starting counter value
 * @param incrementBy         Counter incremented by this value after
 *                            generating OTP
 * @param requiredDigitsInOTP Number of digits required in OTP
 * @param addCheckSumToOTP    Flag that indicates whether check sum shall be
 *                            calculated for OTP and added to OTP
 * @return OMOTPService object, if initialization is successful.
 */
- (id) initForHOTPWithSharedKey: (NSData *)key
             andStartingCounter: (uint64_t)counter
                    incrementBy: (long)incrementValue
            requiredDigitsInOTP: (unsigned long)numDigits
               addCheckSumToOTP: (BOOL)addCheckSum;

/**
 * Initializer method for Hash MAC based One-Time Password generation as per
 * RFC 4226. This initializer method allows the app to specify required
 * hashing algorithm.
 *
 * @param key                 Shared secret that is used for generating Hashed
 *                            Message Authentication Code (HMAC)
 * @param counter             Starting counter value
 * @param incrementBy         Counter incremented by this value after
 *                            generating OTP
 * @param hashingAlgorithm    Hashing algorithm that has to be used for
 *                            generating OTP. Refer OMCryptoAlgorithm for more
 *                            details. Supported hashing algorithms are
 *                            OMAlgorithmMD5,OMAlgorithmSHA1,OMAlgorithmSHA224,
 *                            OMAlgorithmSHA256,OMAlgorithmSHA384, and
 *                            OMAlgorithmSHA512
 * @param requiredDigitsInOTP Number of digits required in OTP
 * @param addCheckSumToOTP    Flag that indicates whether check sum shall be
 *                            calculated for OTP and added to OTP
 * @return OMOTPService object, if initialization is successful.
 */
- (id) initForHOTPWithSharedKey: (NSData *)key
             andStartingCounter: (uint64_t)counter
                    incrementBy: (long)incrementValue
               hashingAlgorithm: (OMCryptoAlgorithm)algorithm
            requiredDigitsInOTP: (unsigned long)numDigits
               addCheckSumToOTP: (BOOL)addCheckSum;

/**
 * Initializer method for Time based One-Time Password (OTP) generation as
 * per RFC 6238. This initializer method allows the app to specify required
 * hashing algorithm.
 *
 * @param key                 Shared secret that is used for generating Hashed
 *                            Message Authentication Code (HMAC)
 * @param referenceTime       Base Time - number of seconds elapse since 1st
 *                            Jan 1970 UTC time zone - to be used for
 *                            calculating OTP
 * @param timeStepInSeconds   Time step in seconds. If this value is zero,
 *                            it will be set to 30 seconds.
 * @param hashingAlgorithm    Hashing algorithm that has to be used for
 *                            computing HMAC. Refer OMCryptoAlgorithm for more
 *                            details. Supported hashing algorithms are
 *                            OMAlgorithmMD5,OMAlgorithmSHA1,OMAlgorithmSHA224,
 *                            OMAlgorithmSHA256,OMAlgorithmSHA384, and
 *                            OMAlgorithmSHA512
 * @param requiredDigitsInOTP Number of digits required in OTP
 * @param addCheckSumToOTP    Flag that indicates whether check sum shall be
 *                            calculated for OTP and added to OTP
 * @return OMOTPService object, if initialization is successful.
 */
- (id) initForTOTPWithSharedKey: (NSData *)key
              baseTimeInSeconds: (uint64_t)referenceTime
              timeStepInSeconds: (NSUInteger)timeSteps
               hashingAlgorithm: (OMCryptoAlgorithm)algorithm
            requiredDigitsInOTP: (NSUInteger)numDigits
                    useCheckSum: (BOOL)addCheckSum;
/**
 * Returns next One-Time Password as NSString object.
 *
 * @param  error  If OTP generation has failed, error message is returned
 *                through this parameter
 * @return One-Time Password in NSString Object
 */
- (NSString *) OTPAsStringReturningError: (NSError **)error;

/**
 * Returns next One-Time Password
 *
 * @param  error  If OTP generation has failed, error message is returned
 *                through this parameter
 * @return One-Time Password
 */
- (uint64_t) OTPAsIntReturningError: (NSError **)error;

/**
 * Class method to compute Hash Based Message Authentication Code (HMAC) as
 * per RFC 2104 given the data, key, and hashing algorithm.
 *
 * @param   data        Text for computing Hash Based Message Authentication
 *                      Code (HMAC)
 * @param   algorithm   Hashing algorithm that has to be used for computing
 *                      HMAC. Refer OMCryptoAlgorithm for more details.
 *                      Supported hashing algorithms are
 *                      OMAlgorithmMD5,OMAlgorithmSHA1,OMAlgorithmSHA224,
 *                      OMAlgorithmSHA256,OMAlgorithmSHA384, and
 *                      OMAlgorithmSHA512
 *  @param  key         Secret to compute HMAC
 *  @param  encode      Identifies whether HMAC has to be base64 encoded or not
 *  @param  outError    Returns NSError object in case of any error while
 *                      computing HMAC
 *  @return HMAC as NSData object
 */
+ (id) computeHashMACForData: (NSData *)data
        usingHashingAlgoritm: (OMCryptoAlgorithm)algorithm
                      andKey: (NSData *)key
            base64EncodeHMAC: (BOOL)encode
                    outError: (NSError **)error;

/**
 * Class method to compute One-Time Password given counter, secret, and hashing
 * algorithm.
 *
 * @param  counter             counter value using OTP has to be computed
 * @param  algorithm           Hashing algorithm that has to be used for
 *                             computing HMAC. Refer OMCryptoAlgorithm for
 *                             more details. Supported hashing algorithms are
 *                             OMAlgorithmMD5, OMAlgorithmSHA1,
 *                             OMAlgorithmSHA224, OMAlgorithmSHA256,
 *                             OMAlgorithmSHA384, and OMAlgorithmSHA512
 * @param  key                 Secret to compute OTP
 * @param  requiredDigitsInOTP Number of digits required in OTP
 * @param  addCheckSumToOTP    Flag that indicates whether check sum shall be
 *                             calculated for OTP and added to OTP
 * @param  outError            Returns NSError object in case of any error while
 *                             computing HMAC
 * @return One-Time Password
 */
+ (uint64_t) OTPForCounter: (uint64_t)counter
     usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                    andKey: (NSData *)secret
       requiredDigitsInOTP: (NSUInteger)numberOfDigits
               addCheckSum: (BOOL)useCheckSum
                  outError: (NSError **)error;

/**
 * Class method to compute One-Time Password given text as NSData, secret,
 * and hashing algorithm.
 *
 * @param  data                Text for computing HMAC and OTP
 * @param  algorithm           Hashing algorithm that has to be used for
 *                             computing HMAC. Refer OMCryptoAlgorithm for
 *                             more details. Supported hashing algorithms are
 *                             OMAlgorithmMD5, OMAlgorithmSHA1,
 *                             OMAlgorithmSHA224, OMAlgorithmSHA256,
 *                             OMAlgorithmSHA384, and OMAlgorithmSHA512
 * @param  key                 Secret to compute OTP
 * @param  requiredDigitsInOTP Number of digits required in OTP
 * @param  addCheckSum         Flag that indicates whether check sum shall be
 *                             calculated for OTP and added to OTP
 * @param  outError            Returns NSError object in case of any error
 *                             while computing OTP
 * @return One-Time Password
 */
+ (uint64_t) OTPForData: (NSData *)data
  usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                 andKey: (NSData *)secret
    requiredDigitsInOTP: (NSUInteger)numberOfDigits
            addCheckSum: (BOOL)useCheckSum
               outError: (NSError **)error;
/**
 * Class method to compute One-Time Password given text as NSString object,
 * secret, and hashing algorithm.
 *
 * @param  text                Text for computing HMAC and OTP
 * @param  algorithm           Hashing algorithm that has to be used for
 *                             computing HMAC. Refer OMCryptoAlgorithm for
 *                             more details. Supported hashing algorithms are
 *                             OMAlgorithmMD5, OMAlgorithmSHA1,
 *                             OMAlgorithmSHA224, OMAlgorithmSHA256,
 *                             OMAlgorithmSHA384, and OMAlgorithmSHA512
 * @param  key                 Secret to compute OTP
 * @param  requiredDigitsInOTP Number of digits required in OTP
 * @param  addCheckSum         Flag that indicates whether check sum shall be
 *                             calculated for OTP and added to OTP
 * @param  outError            Returns NSError object in case of any error
 *                             while computing OTP
 * @return One-Time Password
 */
+ (uint64_t) OTPForText: (NSString *)text
  usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                 andKey: (NSData *)secret
    requiredDigitsInOTP: (NSUInteger)numberOfDigits
            addCheckSum: (BOOL)useCheckSum
               outError: (NSError **)error;

/**
 * Class method to compute Time based One-Time Password given time, secret,
 * and hashing algorithm.
 *
 * @param  currentElpasedTimeSince1970  Time elapsed in seconds since 1st
 *                                      Jan 1970
 * @param  algorithm                    Hashing algorithm that has to be used
 *                                      for computing HMAC. Refer
 *                                      OMCryptoAlgorithm for more details.
 *                                      Supported hashing algorithms are
 *                                      OMAlgorithmMD5, OMAlgorithmSHA1,
 *                                      OMAlgorithmSHA224, OMAlgorithmSHA256,
 *                                      OMAlgorithmSHA384, and
 *                                      OMAlgorithmSHA512
 * @param  baseTime                     Base time to compute TOTP
 * @param  timeStep                     Time steps used to compute TOTP
 * @param  key                          Secret to compute OTP
 * @param  numberOfDigits               Number of digits required in OTP
 * @param  useCheckSum                  Flag that indicates whether check sum
 *                                      shall be calculated for OTP and added
 *                                      to OTP
 * @param  error                        Returns NSError object in case of any
 *                                      error while computing TOTP
 * @return One-Time Password
 */
+ (uint64_t) TOTPForTime: (uint64_t)currentElapsedTimeSince1970
   usingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                baseTime: (uint64_t)baseTime
                timeStep: (uint64_t)timeStep
                  andKey: (NSData *)key
     requiredDigitsInOTP: (NSUInteger)numberOfDigits
             addCheckSum: (BOOL)useCheckSum
                outError: (NSError **)error;

/**
 * Class method to compute Time based One-Time Password given time step,
 * secret, and hashing algorithm. It uses 1st Jan 1970 0000 hrs as base
 * time.
 *
 * @param  algorithm                    Hashing algorithm that has to be used
 *                                      for computing HMAC. Refer
 *                                      OMCryptoAlgorithm for more details.
 *                                      Supported hashing algorithms are
 *                                      OMAlgorithmMD5, OMAlgorithmSHA1,
 *                                      OMAlgorithmSHA224, OMAlgorithmSHA256,
 *                                      OMAlgorithmSHA384, and
 *                                      OMAlgorithmSHA512
 * @param  timeStep                     Time steps used to compute TOTP
 * @param  key                          Secret to compute OTP
 * @param  numberOfDigits               Number of digits required in OTP
 * @param  useCheckSum                  Flag that indicates whether check sum
 *                                      shall be calculated for OTP and added
 *                                      to OTP
 * @param  error                        Returns NSError object in case of any
 *                                      error while computing TOTP
 * @param  validity                     Returns how long this OTP is valid in
 *                                      seconds
 * @return One-Time Password
 */
+ (uint64_t) TOTPusingHashingAlgorithm: (OMCryptoAlgorithm)algorithm
                              timeStep: (uint64_t)timeStep
                                andKey: (NSData *)key
                   requiredDigitsInOTP: (NSUInteger)numberOfDigits
                           addCheckSum: (BOOL)useCheckSum
                              outError: (NSError **)error
                             expiresIn: (uint64_t *)validity;


/**
 * Class method to convert uint64_t data to Byte array.
 *
 * Note: The caller of the application has to free memory allocated to Byte
 *       array after its usage.
 *
 * @param  number  Number that has to be converted as Byte array
 * @return Byte array
 */
+ (Byte *)convertInt64ToByte: (uint64_t)number;

/**
 * Class method to convert uint64_t data to NSData object
 *
 * @param  number  Number that has to be converted as NSData object
 * @return NSData object containing bytes of passed uint64_t integer
 */
+ (NSData *)convertInt64ToNSData: (uint64_t)number;

/**
 * Class method to convert Byte array as hex formatted string.
 *
 * @param  byteData  Byte array that has to be converted
 * @return NSString object containing hex formatted string. Return value does
 *         contain "0x" prefix.
 */
+ (NSString *)convertByteAsHexFormattedString: (Byte *)byteData
                                       length: (NSUInteger)length;

/**
 * Class method to convert NSData object as hex formatted string.
 *
 * @param  data  NSData object that has to be converted
 * @return NSString object containing hex formatted string. Return value does
 *         contain "0x" prefix.
 */
+ (NSString *)convertDataAsHexFormattedString: (NSData *)data;

/**
 * Class method to convert NSString object as hex formatted string. NSString
 * is converted to Byte array using NSUTF8StringEncoding always.
 *
 * @param  string  NSString object that has to be converted
 * @return NSString object containing hex formatted string. Return value does
 *         contain "0x" prefix.
 */
+ (NSString *)convertStringAsHexFormattedString: (NSString *)string;

/**
 * Class method to convert byte to binary format
 *
 * @param  val   Byte value
 * @return NSString object containing binary representation of byte
 */
+ (NSString *)convertByteToBinaryString: (Byte)val;


@end
///////////////////////////////////////////////////////////////////////////////
// End
///////////////////////////////////////////////////////////////////////////////