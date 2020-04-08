/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

#import "OMCryptoService.h"
#import "OMObject.h"
#import "NSData+OMBase64.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"
#import "OMCredentialStore.h"
#import <CommonCrypto/CommonKeyDerivation.h>

#import <stdio.h>

#define ARC4RANDOM_MAX      0x100000000

// private methods
@interface OMCryptoService ()
// Get Public Key Ref from keychain store
+ (SecKeyRef) publicKeyRefWithTagPrefix:(NSString *)prefix
                               outError:(NSError **)error;

// Get Private Key Ref from keychain store
+ (SecKeyRef) privateKeyRefWithTagPrefix:(NSString *)prefix
                                outError:(NSError **)error;

// Get Public or Private Key Ref from keychain store
+ (SecKeyRef) keyRefWithTagPrefix:(NSString *)prefix
                           public:(BOOL)public
                         outError:(NSError **)error;

@end

@implementation OMCryptoService

#pragma mark -
#pragma mark Private
////////////////////////////////////////////////////////////////////////////////
// Get Public Key Ref from keychain store
////////////////////////////////////////////////////////////////////////////////
+ (SecKeyRef) publicKeyRefWithTagPrefix:(NSString *)prefix
                               outError:(NSError **)error
{
    // caller owns the returned reference and must free it when done with it.
    return [OMCryptoService keyRefWithTagPrefix:prefix
                                         public:YES
                                       outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Get Private Key Ref from keychain store
////////////////////////////////////////////////////////////////////////////////
+ (SecKeyRef) privateKeyRefWithTagPrefix:(NSString *)prefix
                                outError:(NSError **)error
{
    // caller owns the returned reference and must free it when done with it.
    return [OMCryptoService keyRefWithTagPrefix:prefix
                                         public:NO
                                       outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Get Public or Private Key Ref from keychain store
////////////////////////////////////////////////////////////////////////////////
+ (SecKeyRef) keyRefWithTagPrefix:(NSString *)prefix
                           public:(BOOL)public
                         outError:(NSError **)error
{
    OSStatus status = noErr;
    SecKeyRef keyReference = NULL;
    
    NSString *  publicTag = OM_KEYPAIR_TAG_PUBLIC;
    NSString * privateTag = OM_KEYPAIR_TAG_PRIVATE;
    NSString * tag;
    
    if (public)
    {
        tag = [prefix stringByAppendingString:publicTag];
    }
    else
    {
        tag = [prefix stringByAppendingString:privateTag];
    }
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    
    // Set the private key query dictionary.
    [queryKey setObject:(id)kSecClassKey
                 forKey:(id)kSecClass];
    [queryKey setObject:tag
                 forKey:(id)kSecAttrApplicationTag];
    [queryKey setObject:[NSNumber numberWithBool:YES]
                 forKey:(id)kSecReturnRef];
    
    // Get the key.
    status = SecItemCopyMatching((CFDictionaryRef)queryKey,
                                 (CFTypeRef *)&keyReference);
    
    if (status == errSecItemNotFound)
    {
        keyReference = NULL;
        
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_ITEM_NOT_FOUND];
    }
    else if (status != noErr)
    {
        keyReference = NULL;
        
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_SYSTEM_ERROR, status];
    }
    
    
    return keyReference;
}

#pragma mark -
#pragma mark Hashing
////////////////////////////////////////////////////////////////////////////////
// Hash MD5
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) MD5HashData:(NSData *)plainText
                outError:(NSError **)error
{
    return [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:OMAlgorithmMD5
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash MD5, Base64 encode, prefix salt, prefix algorithm name
////////////////////////////////////////////////////////////////////////////////
+ (NSString *)  MD5HashAndBase64EncodeData:(NSData *)plainText
                       withSaltOfBitLength:(NSUInteger)saltLength
                                   outSalt:(NSString **)outSalt
                                  outError:(NSError **)error
{
    NSString *salt = nil;
    OMCryptoAlgorithm algorithm = OMAlgorithmMD5;
    BOOL appendSalt = NO;
    
    if (saltLength > 0)
    {
        salt = [OMCryptoService generateSaltOfBitLength:saltLength
                                               outError:error];
        if (salt == nil)
            return nil;
        
        if (outSalt)
            *outSalt = salt;
        
        algorithm = OMAlgorithmSMD5;
        appendSalt = YES;
    }
    
    return [OMCryptoService hashData:plainText
                            withSalt:salt
                           algorithm:algorithm
                  appendSaltToOutput:appendSalt
                        base64Encode:YES
       prefixOutputWithAlgorithmName:YES
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA1
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) SHA1HashData:(NSData *)plainText
                 outError:(NSError **)error
{
    return [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:OMAlgorithmSHA1
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA1, Base64 encode, prefix salt, prefix algorithm name
////////////////////////////////////////////////////////////////////////////////
+ (NSString *)  SHA1HashAndBase64EncodeData:(NSData *)plainText
                        withSaltOfBitLength:(NSUInteger)saltLength
                                    outSalt:(NSString **)outSalt
                                   outError:(NSError **)error
{
    NSString *salt = nil;
    OMCryptoAlgorithm algorithm = OMAlgorithmSHA1;
    BOOL appendSalt = NO;
    
    if (saltLength > 0)
    {
        salt = [OMCryptoService generateSaltOfBitLength:saltLength
                                               outError:error];
        if (salt == nil)
            return nil;
        
        if (outSalt)
            *outSalt = salt;
        
        algorithm = OMAlgorithmSSHA1;
        appendSalt = YES;
    }
    
    return [OMCryptoService hashData:plainText
                            withSalt:salt
                           algorithm:algorithm
                  appendSaltToOutput:appendSalt
                        base64Encode:YES
       prefixOutputWithAlgorithmName:YES
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA224
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) SHA224HashData:(NSData *)plainText
                   outError:(NSError **)error
{
    return [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:OMAlgorithmSHA224
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA224, Base64 encode, prefix salt, prefix algorithm name
////////////////////////////////////////////////////////////////////////////////
+ (NSString *)  SHA224HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error
{
    NSString *salt = nil;
    OMCryptoAlgorithm algorithm = OMAlgorithmSHA224;
    BOOL appendSalt = NO;
    
    if (saltLength > 0)
    {
        salt = [OMCryptoService generateSaltOfBitLength:saltLength
                                               outError:error];
        if (salt == nil)
            return nil;
        
        if (outSalt)
            *outSalt = salt;
        
        algorithm = OMAlgorithmSSHA224;
        appendSalt = YES;
    }
    
    return [OMCryptoService hashData:plainText
                            withSalt:salt
                           algorithm:algorithm
                  appendSaltToOutput:appendSalt
                        base64Encode:YES
       prefixOutputWithAlgorithmName:YES
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA256
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) SHA256HashData:(NSData *)plainText
                   outError:(NSError **)error
{
    return [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:OMAlgorithmSHA256
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA256, Base64 encode, prefix salt, prefix algorithm name
////////////////////////////////////////////////////////////////////////////////
+ (NSString *)  SHA256HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error
{
    NSString *salt = nil;
    OMCryptoAlgorithm algorithm = OMAlgorithmSHA256;
    BOOL appendSalt = NO;
    
    if (saltLength > 0)
    {
        salt = [OMCryptoService generateSaltOfBitLength:saltLength
                                               outError:error];
        if (salt == nil)
            return nil;
        
        if (outSalt)
            *outSalt = salt;
        
        algorithm = OMAlgorithmSSHA256;
        appendSalt = YES;
    }
    
    return [OMCryptoService hashData:plainText
                            withSalt:salt
                           algorithm:algorithm
                  appendSaltToOutput:appendSalt
                        base64Encode:YES
       prefixOutputWithAlgorithmName:YES
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA384
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) SHA384HashData:(NSData *)plainText
                   outError:(NSError **)error
{
    return [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:OMAlgorithmSHA384
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA384, Base64 encode, prefix salt, prefix algorithm name
////////////////////////////////////////////////////////////////////////////////
+ (NSString *)  SHA384HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error
{
    NSString *salt = nil;
    OMCryptoAlgorithm algorithm = OMAlgorithmSHA384;
    BOOL appendSalt = NO;
    
    if (saltLength > 0)
    {
        salt = [OMCryptoService generateSaltOfBitLength:saltLength
                                               outError:error];
        if (salt == nil)
            return nil;
        
        if (outSalt)
            *outSalt = salt;
        
        algorithm = OMAlgorithmSSHA384;
        appendSalt = YES;
    }
    
    return [OMCryptoService hashData:plainText
                            withSalt:salt
                           algorithm:algorithm
                  appendSaltToOutput:appendSalt
                        base64Encode:YES
       prefixOutputWithAlgorithmName:YES
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA512
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) SHA512HashData:(NSData *)plainText
                   outError:(NSError **)error
{
    return [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:OMAlgorithmSHA512
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Hash SHA512, Base64 encode, prefix salt, prefix algorithm name
////////////////////////////////////////////////////////////////////////////////
+ (NSString *)  SHA512HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error
{
    NSString *salt = nil;
    OMCryptoAlgorithm algorithm = OMAlgorithmSHA512;
    BOOL appendSalt = NO;
    
    if (saltLength > 0)
    {
        salt = [OMCryptoService generateSaltOfBitLength:saltLength
                                               outError:error];
        if (salt == nil)
            return nil;
        
        if (outSalt)
            *outSalt = salt;
        
        algorithm = OMAlgorithmSSHA512;
        appendSalt = YES;
    }
    
    return [OMCryptoService hashData:plainText
                            withSalt:salt
                           algorithm:algorithm
                  appendSaltToOutput:appendSalt
                        base64Encode:YES
       prefixOutputWithAlgorithmName:YES
                            outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Generate salt for use in cryptographic hashing
////////////////////////////////////////////////////////////////////////////////
+ (NSString *) generateSaltOfBitLength:(NSUInteger) length
                              outError:(NSError **) error
{
    uint8_t    *randBytes;
    NSUInteger  byteLength = 0;
    NSUInteger  i;
    
    // error too short
    if (length < 4)           // upper limit not checked ?!
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_REQUESTED_LENGTH_TOO_SHORT];
        return nil;
    }
    
    // base16 encoding requires length to be multiple of 4
    if (length%4 != 0)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_REQUESTED_LENGTH_NOT_A_MULTIPLE_OF_4];
        return nil;
    }
    
    // calculate random bytes required in whole number
    byteLength = (length+7) / 8;
    
    randBytes = (uint8_t *)malloc(byteLength);
    if (randBytes == NULL)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_MEMORY_ALLOCATION_FAILURE];
        return nil;
    }
    memset(randBytes, 0x0, byteLength);
    
    // generate random bytes
    OSStatus status = SecRandomCopyBytes(kSecRandomDefault,
                                         (size_t)byteLength,
                                         randBytes);
    if (status != noErr)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_RANDOM_GENERATOR_SYSTEM_ERROR, errno];
        // use strerror_r with a buffer to get the error string
        if (randBytes)
            free(randBytes);
        return nil;
    }
    NSMutableString *saltHex = [NSMutableString string];
    for (i = 0; i < byteLength; i++)
    {
        [saltHex appendString:[NSString stringWithFormat:@"%02X",randBytes[i]]];
    }
    
    if (randBytes)
        free(randBytes);
    
    return saltHex;
}

////////////////////////////////////////////////////////////////////////////////
// Generate cryptographic hash with or without a salt
////////////////////////////////////////////////////////////////////////////////
+ (id)               hashData:(NSData *)plainText
                     withSalt:(NSString *)salt
                    algorithm:(OMCryptoAlgorithm)algorithm
           appendSaltToOutput:(BOOL)appendSalt
                 base64Encode:(BOOL)base64
prefixOutputWithAlgorithmName:(BOOL)prefixAlgorithm
                     outError:(NSError **)error
{
    
    uint8_t      hashLength = 0;
    uint8_t    * hashBytes = NULL;
    id           hash = nil;
    NSData     * plainTextWithSalt;
    NSString   * algorithmName;
    
    // assert
    if (plainText == nil || [plainText length] == 0)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return nil;
    }
    
    // salt is optional
    if (salt != nil && [salt length] > 0)
    {
        // Non salted algorithms cannot take a salt
        if (algorithm == OMAlgorithmMD5    ||
            algorithm == OMAlgorithmSHA1   ||
            algorithm == OMAlgorithmSHA224 ||
            algorithm == OMAlgorithmSHA256 ||
            algorithm == OMAlgorithmSHA384 ||
            algorithm == OMAlgorithmSHA512 )
        {
            if (error)
                *error = [OMObject
                          createErrorWithCode:
                          OMERR_SALT_NOT_SUPPORTED_FOR_CHOSEN_ALGORITHM];
            return nil;
        }
        
        // Upper limit check of salt is not done.
        // max length of salt assumed to be NSUInteger
        
        // add salt to plainText - postfix
        NSMutableData *mutablePlainText = [plainText  mutableCopy];
        [mutablePlainText appendData:[salt dataUsingEncoding:
                                      NSUTF8StringEncoding]];
        plainTextWithSalt = mutablePlainText;
    }
    else
    {
        // salt is mandatory for salted algorithms
        if (algorithm == OMAlgorithmSMD5    ||
            algorithm == OMAlgorithmSSHA1   ||
            algorithm == OMAlgorithmSSHA224 ||
            algorithm == OMAlgorithmSSHA256 ||
            algorithm == OMAlgorithmSSHA384 ||
            algorithm == OMAlgorithmSSHA512 )
        {
            if (error)
                *error = [OMObject
                          createErrorWithCode:
                          OMERR_SALT_REQUIRED_FOR_CHOSEN_ALGORITHM];
            return nil;
        }
        
        // output prefix with salt needs a non-nil salt
        if (base64 && appendSalt)
        {
            if (error)
                *error = [OMObject createErrorWithCode:
                          OMERR_CANNOT_PREFIX_SALT_IN_NON_SALTED_ALGORITHM];
            return nil;
        }
        plainTextWithSalt = plainText;
    }
    
    // 64 bit sanity. CC_* algorithms only take CC_LONG (uint32_t)
    // while [<str> length] returns a wider NSUInteger
    if ([plainTextWithSalt length] > UINT32_MAX)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_LENGTH_MUST_BE_LESS_THAN_OR_EQUAL_TO,
                      UINT32_MAX];
        return nil;
    }
    
    // resultant hash length is decided by the chosen algorithm
    switch (algorithm)
    {
        case OMAlgorithmMD5:
            hashLength = CC_MD5_DIGEST_LENGTH;
            algorithmName = OM_CRYPTO_MD5;
            break;
        case OMAlgorithmSHA1:
            hashLength = CC_SHA1_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SHA1;
            break;
        case OMAlgorithmSHA224:
            hashLength = CC_SHA224_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SHA224;
            break;
        case OMAlgorithmSHA256:
            hashLength = CC_SHA256_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SHA256;
            break;
        case OMAlgorithmSHA384:
            hashLength = CC_SHA384_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SHA384;
            break;
        case OMAlgorithmSHA512:
            hashLength = CC_SHA512_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SHA512;
            break;
            
            // salted algorithms
        case OMAlgorithmSMD5:
            hashLength = CC_MD5_DIGEST_LENGTH;
            algorithmName = OM_CRYPTO_SMD5;
            break;
        case OMAlgorithmSSHA1:
            hashLength = CC_SHA1_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SSHA1;
            break;
        case OMAlgorithmSSHA224:
            hashLength = CC_SHA224_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SSHA224;
            break;
        case OMAlgorithmSSHA256:
            hashLength = CC_SHA256_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SSHA256;
            break;
        case OMAlgorithmSSHA384:
            hashLength = CC_SHA384_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SSHA384;
            break;
        case OMAlgorithmSSHA512:
            hashLength = CC_SHA512_DIGEST_LENGTH;
            algorithmName = OM_PROP_CRYPTO_SSHA512;
            break;
        default:
            // unsupported algorithm
            if (error)
                *error = [OMObject
                          createErrorWithCode:
                          OMERR_UNKNOWN_OR_UNSUPPORTED_ALGORITHM];
            return nil;
    }
    
    // buffer to hold hash.
    hashBytes = malloc( hashLength * sizeof(uint8_t) );
    if (hashBytes == NULL)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_MEMORY_ALLOCATION_FAILURE];
        return nil;
    }
    memset((void *)hashBytes, 0x0, hashLength);
    
    // generate hash
    switch (algorithm)
    {
        case OMAlgorithmMD5:
        case OMAlgorithmSMD5:
            CC_MD5   ((void *)[plainTextWithSalt bytes],
                      (CC_LONG)[plainTextWithSalt length], hashBytes);
            break;
        case OMAlgorithmSHA1:
        case OMAlgorithmSSHA1:
            CC_SHA1  ((void *)[plainTextWithSalt bytes],
                      (CC_LONG)[plainTextWithSalt length], hashBytes);
            break;
        case OMAlgorithmSHA224:
        case OMAlgorithmSSHA224:
            CC_SHA224((void *)[plainTextWithSalt bytes],
                      (CC_LONG)[plainTextWithSalt length], hashBytes);
            break;
        case OMAlgorithmSHA256:
        case OMAlgorithmSSHA256:
            CC_SHA256((void *)[plainTextWithSalt bytes],
                      (CC_LONG)[plainTextWithSalt length], hashBytes);
            break;
        case OMAlgorithmSHA384:
        case OMAlgorithmSSHA384:
            CC_SHA384((void *)[plainTextWithSalt bytes],
                      (CC_LONG)[plainTextWithSalt length], hashBytes);
            break;
        case OMAlgorithmSHA512:
        case OMAlgorithmSSHA512:
            CC_SHA512((void *)[plainTextWithSalt bytes],
                      (CC_LONG)[plainTextWithSalt length], hashBytes);
            break;
    }
    
    // base64 encoding is optional
    if (base64)
    {
        // base64 encoding is available in NSData, so we make a NSData
        NSMutableData * hash64 = [[NSMutableData alloc]
                                  initWithBytes:(const void *)hashBytes
                                  length:(NSUInteger)hashLength];

        // append salt to output - only for base64 encoded output
        if (appendSalt && [salt length] > 0)
        {
            [hash64 appendData:[salt dataUsingEncoding:NSUTF8StringEncoding]];
        }
        
        // return NSString
        hash = [hash64 base64EncodedString];
        
        // prefix output with algorithm name - only for base64 encoded output
        if (prefixAlgorithm)
        {
            hash = [NSString stringWithFormat:@"{%@}%@", algorithmName, hash];
        }
    }
    else
    {
        // return NSData
        hash = [NSData dataWithBytes:(const void *)hashBytes
                              length:(NSUInteger)hashLength];
    }
    
    if (hashBytes)
        free(hashBytes);
    
    return hash;
}

#pragma mark -
#pragma mark Symmetric Key
////////////////////////////////////////////////////////////////////////////////
// Symmetric key encryption - AES128, PKCS7 padding, CBC mode
////////////////////////////////////////////////////////////////////////////////
+ (NSData *)            encryptData:(NSData *)plainText
                   withSymmetricKey:(NSData *)symmetricKey
                           outError:(NSError **)error
{
    return [OMCryptoService encryptData:plainText
                       withSymmetricKey:symmetricKey
                   initializationVector:nil
                              algorithm:OMAlgorithmAES128
                                padding:OMPaddingPKCS7
                                   mode:OMModeCBC
                     base64EncodeOutput:NO
          prefixOutputWithAlgorithmName:NO
                               outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Symmetric key encryption - Salt generation, AES128, PKCS7 padding, CBC mode
////////////////////////////////////////////////////////////////////////////////
+ (id)            encryptData:(NSData *)plainText
     withSymmetricKeyOfLength:(NSUInteger)keyLength
              outSymmetricKey:(NSData **)key
                     outError:(NSError **)error
{
    NSData * symmetricKey = nil;
    
    symmetricKey = [OMCryptoService generateSymmetricKeyOfLength:keyLength
                                                        outError:error];
    if (key == nil)
        return nil;
    
    *key = symmetricKey;
    
    return [OMCryptoService encryptData:plainText
                       withSymmetricKey:symmetricKey
                   initializationVector:nil
                              algorithm:OMAlgorithmAES128
                                padding:OMPaddingPKCS7
                                   mode:OMModeCBC
                     base64EncodeOutput:NO
          prefixOutputWithAlgorithmName:NO
                               outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Symmetric key encryption - AES128, PKCS7 padding, CBC mode
////////////////////////////////////////////////////////////////////////////////
+ (NSData *)            decryptData:(NSData *)cipherText
                   withSymmetricKey:(NSData *)symmetricKey
                           outError:(NSError **)error
{
    return [OMCryptoService decryptData:cipherText
                       withSymmetricKey:symmetricKey
                   initializationVector:nil
                              algorithm:OMAlgorithmAES128
                                padding:OMPaddingPKCS7
                                   mode:OMModeCBC
       isInputPrefixedWithAlgorithmName:NO
                   isInputBase64Encoded:NO
                               outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Generate key for use in symmetric encryption like AES, DES etc.
////////////////////////////////////////////////////////////////////////////////
+ (NSData *)generateSymmetricKeyOfLength:(NSUInteger)length
                                outError:(NSError **)error
{
    OSStatus  status          = noErr;
    uint8_t * symmetricKeyBuf = NULL;
    
    // sanity check
    if (length == 0)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_KEY_IS_NIL];
        return nil;
    }
    
    // space for key
    symmetricKeyBuf = malloc(length * sizeof(uint8_t));
    if (symmetricKeyBuf == NULL)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_MEMORY_ALLOCATION_FAILURE];
        return nil;
    }
    memset((void *)symmetricKeyBuf, 0x0, length);
    
    // generate key
    status = SecRandomCopyBytes(kSecRandomDefault, length, symmetricKeyBuf);
    if (status != noErr)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_RANDOM_GENERATOR_SYSTEM_ERROR, errno];
        
        if (symmetricKeyBuf)
            free(symmetricKeyBuf);
        
        return nil;
    }
    
    // encapsulate as NSData
    NSData *symmetricKey = [[NSData alloc]
                            initWithBytes:(const void *)symmetricKeyBuf
                            length:length];
    
    if (symmetricKeyBuf)
        free(symmetricKeyBuf);
    
    return symmetricKey;
}

////////////////////////////////////////////////////////////////////////////////
// Generate key for use in symmetric encryption like AES, DES etc.
////////////////////////////////////////////////////////////////////////////////
+(NSData *) generateSymmetricKeyWithPassPhrase:(NSString *)passPhrase 
                                      outError:(NSError **)error
{
//    NSDictionary *deviceClaims = [[OMIdentityContext sharedInstance]
//                                  deviceClaims:[NSArray arrayWithObjects:OM_DEVICE_UNIQUE_ID, OM_IMEI,nil]];
    NSString *vendorId = [[UIDevice currentDevice] identifierForVendor].UUIDString;

    NSString* data = [NSString stringWithFormat:@"%@%@",passPhrase,vendorId];
    return [OMCryptoService hashData:[data dataUsingEncoding:NSASCIIStringEncoding] withSalt:nil algorithm:OMAlgorithmSHA256 appendSaltToOutput:false base64Encode:false prefixOutputWithAlgorithmName:false outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Symmetric key encryption
////////////////////////////////////////////////////////////////////////////////
+ (id)            encryptData:(NSData *)plainText
             withSymmetricKey:(NSData *)symmetricKey
         initializationVector:(NSData *)iv
                    algorithm:(OMCryptoAlgorithm)algorithm
                      padding:(OMCryptoPadding)padding
                         mode:(OMCryptoMode)mode
           base64EncodeOutput:(BOOL)base64
prefixOutputWithAlgorithmName:(BOOL)prefix
                     outError:(NSError **)error
{
    NSUInteger      keyLength = 0;
    CCCryptorStatus status = kCCSuccess;
    CCCryptorRef    cryptorRef = NULL;
    id              cipherText = nil;
    uint8_t       * bufferPtr = NULL;
    size_t          bufferSize = 0;
    size_t          movedBytes = 0;
    size_t          remainingBytes = 0;
    size_t          totalBytesWritten = 0;
    size_t          plainTextLength = 0;
    uint8_t       * ptr;
    uint32_t        kCCOptions = 0;
    uint32_t        kCCAlgorithm = kCCAlgorithmAES128;
    uint32_t        kCCBlockSize = kCCBlockSizeAES128;
    NSString      * algorithmName;
    
    // input sanity
    if (plainText == nil || [plainText length] == 0)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return nil;
    }
    plainTextLength = [plainText length];
    
    if (symmetricKey == nil || [symmetricKey length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
        return nil;
    }
    keyLength = [symmetricKey length];
    
    // alogirthm and keylength matching
    NSUInteger errorCode = OMERR_SUCCESS;
    switch (algorithm)
    {
        case OMAlgorithmDES:
            if (keyLength != kCCKeySizeDES)
            {
                errorCode = OMERR_KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM;
                break;
            }
            algorithmName = OM_CRYPTO_DES;
            kCCAlgorithm = kCCAlgorithmDES;
            kCCBlockSize = kCCBlockSizeDES;
            break;
        case OMAlgorithm3DES:
            if (keyLength != kCCKeySize3DES)
            {
                errorCode = OMERR_KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM;
                break;
            }
            algorithmName = OM_CRYPTO_3DES;
            kCCAlgorithm = kCCAlgorithm3DES;
            kCCBlockSize = kCCBlockSize3DES;
            break;
        case OMAlgorithmAES128:
            if (keyLength != kCCKeySizeAES128 &&
                keyLength != kCCKeySizeAES192 &&
                keyLength != kCCKeySizeAES256   )
            {
                errorCode = OMERR_KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM;
                break;
            }
            algorithmName = OM_PROP_CRYPTO_AES;
            kCCAlgorithm = kCCAlgorithmAES128;
            kCCBlockSize = kCCBlockSizeAES128;
            break;
        default:
            errorCode = OMERR_UNKNOWN_OR_UNSUPPORTED_ALGORITHM;
    }
    
    if (errorCode != OMERR_SUCCESS)
    {
        if (error)
            *error = [OMObject createErrorWithCode:errorCode];
        return nil;
    }
    
    // iv
    if (iv != nil && [iv length] > 0)
    {
        if ([iv length] != kCCBlockSize)
        {
            if (error)
                *error = [OMObject
                          createErrorWithCode:
                          OMERR_IV_LENGTH_MUST_MATCH_ALGORITHM_BLOCK_SIZE];
            return nil;
        }
    }
    
    // padding
    
    if (padding == OMPaddingPKCS7)
    {
        kCCOptions |= kCCOptionPKCS7Padding;
    }
    else if (padding == OMPaddingNone)
    {
        if ((plainTextLength % kCCBlockSize) != 0)
        {
            if (error)
            {
                *error = [OMObject createErrorWithCode:OMERR_PADDING_REQUIRED];
            }
            return nil;
        }
    }
    else
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING];
        return nil;
    }
    
    // mode
    if (mode == OMModeECB)
    {
        kCCOptions |= kCCOptionECBMode;
    } // default is OMModeCBC
    
    // 1 of 4. Create and Initialize the crypto reference.
    status = CCCryptorCreate(kCCEncrypt,
                             kCCAlgorithm,
                             kCCOptions,
                             (const void *)[symmetricKey bytes],
                             keyLength,
                             (const void *)[iv bytes],
                             &cryptorRef
                             );
    
    if (status != kCCSuccess)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_ENCRYPTION_SYSTEM_ERROR, status];
        if (cryptorRef)
            CCCryptorRelease(cryptorRef);
        return nil;
    }
    
    // calculate required output buffer length
    // Note: when plainTextLength is not a multiple of block size and no padding
    // is asked, size calculation goes wrong. This is prevented early by
    // throwing an error mandating padding for odd sized plainText
    bufferSize = CCCryptorGetOutputLength(cryptorRef,
                                          plainTextLength, true);
    
    // Note: Theoretical max size required => (plainTextLength + kCCBlockSize)
    // NSLog(@"buffer ptr size %ld", bufferSize);
    
    // Allocate buffer.
    bufferPtr = malloc(bufferSize * sizeof(uint8_t));
    if (bufferPtr == NULL)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_MEMORY_ALLOCATION_FAILURE];
        if (cryptorRef)
            CCCryptorRelease(cryptorRef);
        return nil;
    }
    memset((void *)bufferPtr, 0x0, bufferSize);
    
    // Initialize some necessary book keeping.
    ptr = bufferPtr;
    
    // Set up initial size.
    remainingBytes = bufferSize;
    
    // 2 of 4. Perform encryption.
    status = CCCryptorUpdate(cryptorRef,
                             (const void *) [plainText bytes],
                             plainTextLength,
                             ptr,
                             remainingBytes,
                             &movedBytes
                             );
    
    if (status != kCCSuccess)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_ENCRYPTION_SYSTEM_ERROR, status];
        if (cryptorRef)
            CCCryptorRelease(cryptorRef);
        if (bufferPtr)
            free(bufferPtr);
        return nil;
    }
    
    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;
    
    // 3 of 4. Finalize everything to the output buffer.
    status = CCCryptorFinal(cryptorRef,
                            ptr,
                            remainingBytes,
                            &movedBytes
                            );
    
    totalBytesWritten += movedBytes;
    
    // 4 of 4. Cleanup
    if (cryptorRef)
    {
        (void) CCCryptorRelease(cryptorRef);
        cryptorRef = NULL;
    }
    
    if (status != kCCSuccess)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_ENCRYPTION_SYSTEM_ERROR, status];
        if (bufferPtr)
            free(bufferPtr);
        return nil;
    }
    
    // paranoid assert
    if (totalBytesWritten == 0)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_ENCRYPTION_SYSTEM_ERROR, 0];
        return nil;
    }
    
    // base64 encoding is optional
    if (base64)
    {
        // encapsulate as NSData as base64 encoding is available in NSData
        NSData * cipherData = [[NSData alloc]
                               initWithBytes:(const void *)bufferPtr
                               length:(NSUInteger)totalBytesWritten];
        NSString * cipherBase64 = [cipherData base64EncodedString];
        
        // algorithm name prefix in output
        if (prefix)
        {
            cipherBase64 = [NSString stringWithFormat:@"{%@}%@", algorithmName,
                            cipherBase64];
        }
        cipherText = cipherBase64;
    }
    else
    {
        // prepare output
        cipherText = [NSData dataWithBytes:(const void *)bufferPtr
                                    length:(NSUInteger)totalBytesWritten];
    }
    
    if (bufferPtr)
        free(bufferPtr);
    
    return cipherText;
}


////////////////////////////////////////////////////////////////////////////////
// Symmetric key decryption
////////////////////////////////////////////////////////////////////////////////
+ (NSData *)         decryptData:(id)cipherText
                withSymmetricKey:(NSData *)symmetricKey
            initializationVector:(NSData *)iv
                       algorithm:(OMCryptoAlgorithm)algorithm
                         padding:(OMCryptoPadding)padding
                            mode:(OMCryptoMode)mode
isInputPrefixedWithAlgorithmName:(BOOL)prefix
            isInputBase64Encoded:(BOOL)base64
                        outError:(NSError **)error
{
    NSUInteger      keyLength = 0;
    CCCryptorStatus status = kCCSuccess;
    CCCryptorRef    cryptorRef = NULL;
    id              plainText = nil;
    uint8_t       * bufferPtr = NULL;
    size_t          bufferSize = 0;
    size_t          movedBytes = 0;
    size_t          remainingBytes = 0;
    size_t          totalBytesWritten = 0;
    size_t          cipherTextLength = 0;
    uint8_t       * ptr;
    uint32_t        kCCOptions = 0;
    uint32_t        kCCAlgorithm = kCCAlgorithmAES128;
    uint32_t        kCCBlockSize = kCCBlockSizeAES128;
    NSString      * algorithmName;
    NSString      * cipherTextString;
    NSData        * cipherData;
    
    // input sanity
    if (cipherText == nil || [cipherText length] == 0)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return nil;
    }
    
    if (symmetricKey == nil || [symmetricKey length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
        return nil;
    }
    keyLength = [symmetricKey length];
    
    // alogirthm and keylength matching
    NSUInteger errorCode = OMERR_SUCCESS;
    switch (algorithm)
    {
        case OMAlgorithmDES:
            if (keyLength != kCCKeySizeDES)
            {
                errorCode = OMERR_KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM;
                break;
            }
            algorithmName = OM_CRYPTO_DES;
            kCCAlgorithm = kCCAlgorithmDES;
            kCCBlockSize = kCCBlockSizeDES;
            break;
        case OMAlgorithm3DES:
            if (keyLength != kCCKeySize3DES)
            {
                errorCode = OMERR_KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM;
                break;
            }
            algorithmName = OM_CRYPTO_3DES;
            kCCAlgorithm = kCCAlgorithm3DES;
            kCCBlockSize = kCCBlockSize3DES;
            break;
        case OMAlgorithmAES128:
            if (keyLength != kCCKeySizeAES128 &&
                keyLength != kCCKeySizeAES192 &&
                keyLength != kCCKeySizeAES256   )
            {
                errorCode = OMERR_KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM;
                break;
            }
            algorithmName = OM_PROP_CRYPTO_AES;
            kCCAlgorithm = kCCAlgorithmAES128;
            kCCBlockSize = kCCBlockSizeAES128;
            break;
        default:
            errorCode = OMERR_UNKNOWN_OR_UNSUPPORTED_ALGORITHM;
    }
    
    if (errorCode != OMERR_SUCCESS)
    {
        if (error)
            *error = [OMObject createErrorWithCode:errorCode];
        return nil;
    }
    algorithmName = [NSString stringWithFormat:@"{%@}", algorithmName];
    
    // base64 encoding is optional
    if (base64)
    {
        if (![cipherText isKindOfClass:[NSString class]])
        {
            if (error)
                *error = [OMObject createErrorWithCode:
                          OMERR_INPUT_MUST_BE_NSSTRING_WHEN_BASE64_IS_ENABLED];
            return nil;
        }
        
        cipherTextString = cipherText;
        
        // strip algorithm name prefix
        if (prefix)
        {
            if ([cipherTextString rangeOfString:algorithmName].location != 0)
            {
                if (error)
                    *error = [OMObject createErrorWithCode:
                              OMERR_INPUT_NOT_PREFIXED_WITH_ALGORITHM_NAME];
                return nil;
            }
            
            cipherTextString = [cipherTextString
                                substringFromIndex:[algorithmName length]];
            
            if (cipherTextString == nil || [cipherTextString length] == 0)
            {
                if (error)
                    *error = [OMObject
                              createErrorWithCode:
                              OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
                return nil;
            }
        }
        
        cipherData = [NSData dataFromBase64String:cipherTextString];
        cipherTextLength = [cipherData length];
    }
    else if ([cipherText isKindOfClass:[NSData class]])
    {
        cipherData = cipherText;
        cipherTextLength = [cipherText length];
    }
    else
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_UNKNOWN_INPUT_TYPE];
        return nil;
    }
    
    // iv
    if (iv != nil && [iv length] > 0)
    {
        if ([iv length] != kCCBlockSize)
        {
            if (error)
                *error = [OMObject
                          createErrorWithCode:
                          OMERR_IV_LENGTH_MUST_MATCH_ALGORITHM_BLOCK_SIZE];
            return nil;
        }
    }
    
    // padding
    if (padding == OMPaddingPKCS7)
    {
        kCCOptions |= kCCOptionPKCS7Padding;
    }
    else if (padding != OMPaddingNone)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING];
        return nil;
    }
    
    // mode
    if (mode == OMModeECB)
    {
        kCCOptions |= kCCOptionECBMode;
    } // default is OMModeCBC
    
    // 1 of 4. Create and Initialize the crypto reference.
    status = CCCryptorCreate(kCCDecrypt,
                             kCCAlgorithm,
                             kCCOptions,
                             (const void *)[symmetricKey bytes],
                             keyLength,
                             (const void *)[iv bytes],
                             &cryptorRef
                             );
    
    if (status != kCCSuccess)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_DECRYPTION_SYSTEM_ERROR, status];
        return nil;
    }
    
    // calculate required output buffer length
    // Note: when plainTextLength is not a multiple of block size and no padding
    // is asked, size calculation goes wrong. This is prevented early by
    // throwing an error mandating padding for odd sized plainText
    bufferSize = CCCryptorGetOutputLength(cryptorRef,
                                          cipherTextLength, true);
    
    // Note: Theoretical max size required => (plainTextLength + kCCBlockSize)
    // NSLog(@"buffer ptr size %ld", bufferSize);
    
    // Allocate buffer.
    bufferPtr = malloc(bufferSize * sizeof(uint8_t));
    if (bufferPtr == NULL)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_MEMORY_ALLOCATION_FAILURE];
        return nil;
    }
    memset((void *)bufferPtr, 0x0, bufferSize);
    
    // Initialize some necessary book keeping.
    ptr = bufferPtr;
    
    // Set up initial size.
    remainingBytes = bufferSize;

    // Single API call versus multiple calls
    // Multiple calls is more flexible and used for production
#if 1
    // 2 of 4. Perform decryption.
    status = CCCryptorUpdate(cryptorRef,
                             (const void *) [cipherData bytes],
                             cipherTextLength,
                             ptr,
                             remainingBytes,
                             &movedBytes
                             );
    
    if (status != kCCSuccess)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_ENCRYPTION_SYSTEM_ERROR, status];
        if (bufferPtr)
            free(bufferPtr);
        return nil;
    }
    
    // Handle book keeping.
    ptr += movedBytes;
    remainingBytes -= movedBytes;
    totalBytesWritten += movedBytes;
    
    // 3 of 4. Finalize everything to the output buffer.
    status = CCCryptorFinal(cryptorRef,
                            ptr,
                            remainingBytes,
                            &movedBytes
                            );
    
    totalBytesWritten += movedBytes;
#else
    // Single method invocation for debugging
    // helps with differences in iOS versions
    CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptions, [symmetricKey bytes],
            keyLength, [iv bytes], [cipherData bytes], cipherTextLength, ptr,
            remainingBytes, &movedBytes); 
#endif
    
    // 4 of 4. Cleanup
    if (cryptorRef)
    {
        (void) CCCryptorRelease(cryptorRef);
        cryptorRef = NULL;
    }
    
    if (status != kCCSuccess)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_ENCRYPTION_SYSTEM_ERROR, status];
        if (bufferPtr)
            free(bufferPtr);
        return nil;
    }
    
    // prepare output
    plainText = [NSData dataWithBytes:(const void *)bufferPtr
                               length:(NSUInteger)totalBytesWritten];
    
    if (bufferPtr)
        free(bufferPtr);
    
    return plainText;
}

#pragma mark -
#pragma mark Key Pair

////////////////////////////////////////////////////////////////////////////////
// Generate Assymmetric Key Pair and store in keychain
////////////////////////////////////////////////////////////////////////////////
+ (BOOL) generateAndStoreKeyPairOfBitLength:(NSUInteger)length
                          keychainTagPrefix:(NSString *)tagPrefix
                                 protection:(NSString *)protection
                                   outError:(NSError **)error
{
    return [OMCryptoService generateAndStoreKeyPairOfBitLength:length
                                                       keyType:OMKeyTypeRSA
                                             keychainTagPrefix:tagPrefix
                                                    protection:protection
                                                      outError:error];
}

////////////////////////////////////////////////////////////////////////////////
// Generate Assymmetric Key Pair of key type and store in keychain
////////////////////////////////////////////////////////////////////////////////
+ (BOOL) generateAndStoreKeyPairOfBitLength:(NSUInteger)length
                                    keyType:(OMCryptoKeyType)keyType
                          keychainTagPrefix:(NSString *)tagPrefix
                                 protection:(NSString *)protection
                                   outError:(NSError **)error
{
    OSStatus status = noErr;
    SecKeyRef publicKeyRef = NULL;
    SecKeyRef privateKeyRef = NULL;
    
    NSString * privateTag = OM_KEYPAIR_TAG_PRIVATE;
    NSString *  publicTag = OM_KEYPAIR_TAG_PUBLIC;
    
    NSError *lookupError = nil;
    SecKeyRef lookupKey = NULL;
    
    id underlyingKeyType;
    
    // Note: iPhone 5.0, 6.0 works with RSA key size upto 4096 (not above).
    //       An upper limit check is not needed, as generation will fail anyway
    //       in the underlying SecKeyGeneratePair call.
    
    // A tag is required to store keypair in key chain
    if (tagPrefix == nil || [tagPrefix length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN];
        return NO;
    }
    
    // Check keychain if we already have the keys
    // public key
    lookupKey = [OMCryptoService publicKeyRefWithTagPrefix:tagPrefix
                                                  outError:&lookupError];
    if (lookupKey != NULL)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_ITEM_ALREADY_FOUND];
        return NO;
    }
    else if (lookupKey == NULL)
    {
        if (lookupError != nil &&
            [lookupError code] != OMERR_KEYCHAIN_ITEM_NOT_FOUND)
        {
            if (error)
                *error = lookupError;
            return NO;
        }
    }
    if (lookupKey)
        CFRelease(lookupKey);
    
    // private key
    lookupKey = [OMCryptoService privateKeyRefWithTagPrefix:tagPrefix
                                                   outError:&lookupError];
    if (lookupKey != NULL)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_ITEM_ALREADY_FOUND];
        return NO;
    }
    else if (lookupKey == NULL)
    {
        if (lookupError != nil &&
            [lookupError code] != OMERR_KEYCHAIN_ITEM_NOT_FOUND)
        {
            if (error)
                *error = lookupError;
            return NO;
        }
    }
    if (lookupKey)
        CFRelease(lookupKey);
    
    // setup key type
    // IMPORTANT: For Elliptic Circle key type, iOS 6.0 does not implement
    //            signing or encryption. Only key generation is supported.
    switch (keyType)
    {
        case OMKeyTypeRSA:
            underlyingKeyType = kSecAttrKeyTypeRSA;
            break;

// The symbol kSecAttrKeyTypeEC is claimed to be available in iOS 4.0, but
// in reality this symbol causes runtime failures on iOS 4.3 device. Also
// even on iOS 6.0 only key generation is available. Can be enabled when
// this keytype can work with sign/verify, wrap/unwrap.
#if 0
        case OMKeyTypeEC:
            underlyingKeyType = kSecAttrKeyTypeEC;
            break;
#endif
        default:
            if (error)
                *error = [OMObject createErrorWithCode:
                          OMERR_UNKNOWN_OR_UNSUPPORTED_KEY_TYPE];
            return NO;
    }
    
    // setup tags
    privateTag = [tagPrefix stringByAppendingString:privateTag];
    publicTag  = [tagPrefix stringByAppendingString:publicTag];
    
    // protection
    CFTypeRef accessible = (__bridge CFTypeRef) protection;//SHIV:(__bridge CFTypeRef)([OMCredentialStore protectionInternalRepresentation:protection]);

    if (nil == accessible)
    {
        if (error)
            *error = [OMObject createErrorWithCode:OMERR_INVALID_KEYCHAIN_DATA_PROTECTION_LEVEL];
        return NO;
    }

    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // set top level dictionary for the keypair.
    [keyPairAttr setObject:(id)underlyingKeyType
                    forKey:(id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:length]
                    forKey:(id)kSecAttrKeySizeInBits];
    [keyPairAttr setObject:(__bridge id _Nonnull)accessible
                    forKey:(id)kSecAttrAccessible];
    
    // set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES]
                       forKey:(id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag
                       forKey:(id)kSecAttrApplicationTag];
    [privateKeyAttr setObject:(__bridge id _Nonnull)(accessible)
                       forKey:(id)kSecAttrAccessible];
    
    // set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES]
                      forKey:(id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag
                      forKey:(id)kSecAttrApplicationTag];
    [publicKeyAttr  setObject:(__bridge id _Nonnull)(accessible)
                       forKey:(id)kSecAttrAccessible];
    
    // set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(id)kSecPublicKeyAttrs];
    
    // generate
    status = SecKeyGeneratePair((CFDictionaryRef)keyPairAttr,
                                &publicKeyRef, &privateKeyRef);
    
    
    if (status == noErr && publicKeyRef != NULL && privateKeyRef != NULL)
    {
        return TRUE;
    }
    else
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYPAIR_GENERATION_SYSTEM_ERROR, status];
        return NO;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Get bits of a Key Pair's public key
////////////////////////////////////////////////////////////////////////////////
+ (NSData *)   publicKeyFromKeychainWithTagPrefix:(NSString *)tagPrefix
                                         outError:(NSError **)error
{
    OSStatus status = noErr;

    NSData * publicKeyData = NULL;
    CFTypeRef inTypeRef = (__bridge CFTypeRef)publicKeyData;

    NSString *  publicTag = OM_KEYPAIR_TAG_PUBLIC;
    
    if (tagPrefix == nil || [tagPrefix length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN];
        return nil;
    }
    
    publicTag  = [tagPrefix stringByAppendingString:publicTag];
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    // set the public key query dictionary.
    [queryPublicKey setObject:(id)kSecClassKey
                       forKey:(id)kSecClass];
    [queryPublicKey setObject:publicTag
                       forKey:(id)kSecAttrApplicationTag];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES]
                       forKey:(id)kSecReturnData];
    
    // get key
    status = SecItemCopyMatching((CFDictionaryRef)queryPublicKey,
                                 (CFTypeRef *)&inTypeRef);
    
    if (status == errSecItemNotFound)
    {
        inTypeRef = nil;
        
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_ITEM_NOT_FOUND];
    }
    else if (status != noErr)
    {
        inTypeRef = nil;
        
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_SYSTEM_ERROR, status];
    }
    
    
    return (__bridge NSData *)inTypeRef;
}

////////////////////////////////////////////////////////////////////////////////
// Get bits of a Key Pair's private key
////////////////////////////////////////////////////////////////////////////////
+ (NSData *)privateKeyFromKeychainWithTagPrefix:(NSString *)tagPrefix
                                         outError:(NSError **)error
{
    OSStatus status = noErr;

    NSData * privateKeyData = NULL;
    CFTypeRef inTypeRef = (__bridge CFTypeRef)privateKeyData;

    NSString *  publicTag = OM_KEYPAIR_TAG_PRIVATE;
    
    if (tagPrefix == nil || [tagPrefix length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN];
        return nil;
    }
    
    publicTag  = [tagPrefix stringByAppendingString:publicTag];
    
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // set the private key query dictionary.
    [queryPrivateKey setObject:(id)kSecClassKey
                       forKey:(id)kSecClass];
    [queryPrivateKey setObject:publicTag
                       forKey:(id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES]
                       forKey:(id)kSecReturnData];
    
    // get key
    status = SecItemCopyMatching((CFDictionaryRef)queryPrivateKey,
                                 (CFTypeRef *)&inTypeRef);
    
    if (status == errSecItemNotFound)
    {
        inTypeRef = nil;
        
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_ITEM_NOT_FOUND];
    }
    else if (status != noErr)
    {
        inTypeRef = nil;
        
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_SYSTEM_ERROR, status];
    }
    
    
    return (__bridge NSData *)inTypeRef;
}

////////////////////////////////////////////////////////////////////////////////
// Delete key pair from keychain
////////////////////////////////////////////////////////////////////////////////
+ (BOOL) deleteKeyPairFromKeychainWithTagPrefix:(NSString *)tagPrefix
                                       outError:(NSError **)error
{
    NSString * privateTag = OM_KEYPAIR_TAG_PRIVATE;
    NSString *  publicTag = OM_KEYPAIR_TAG_PUBLIC;
    OSStatus status = noErr;
    BOOL result = NO;
    
    if (tagPrefix == nil || [tagPrefix length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN];
        return NO;
    }
    
    // setup tags
    privateTag = [tagPrefix stringByAppendingString:privateTag];
    publicTag  = [tagPrefix stringByAppendingString:publicTag];
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPublicKey setObject:publicTag forKey:(id)kSecAttrApplicationTag];
    
    // Set the private key query dictionary.
    [queryPrivateKey setObject:(id)kSecClassKey forKey:(id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(id)kSecAttrApplicationTag];
    
    // Delete the private key.
    status = SecItemDelete((CFDictionaryRef)queryPrivateKey);
    
    if (status == errSecItemNotFound)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_ITEM_NOT_FOUND];
        goto last;
    }
    else if (status != noErr)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_SYSTEM_ERROR, status];
        goto last;
    }
    
    // Delete the public key.
    status = SecItemDelete((CFDictionaryRef)queryPublicKey);
    
    if (status == errSecItemNotFound)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_ITEM_NOT_FOUND];
        goto last;
    }
    else if (status != noErr)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_KEYCHAIN_SYSTEM_ERROR, status];
        goto last;
    }
    result = YES;
    
last:
    
    return result;
}

////////////////////////////////////////////////////////////////////////////////
// Sign data with Key Pair's private key
////////////////////////////////////////////////////////////////////////////////
+ (NSData *)     signData:(NSData *)plainText
  withPrivateKeyTagPrefix:(NSString *)prefix
  paddingAndHashingScheme:(OMCryptoPadding)padding
                 outError:(NSError **)error
{
    OSStatus status = noErr;
    NSData * signedHash = nil;
    SecPadding underlyingPadding;
    OMCryptoAlgorithm hashAlgorithm = OMAlgorithmSHA1;
    size_t hashLength = 0;
    NSData *hash = nil;
    
    uint8_t * signedHashBytes = NULL;
    size_t signedHashBytesSize = 0;
    
    SecKeyRef privateKey = NULL;
    
    if (plainText == nil || [plainText length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return nil;
    }
    
    if (prefix == nil || [prefix length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN];
        return nil;
    }
    
    // setup padding, hash length, hash algorithm
    switch (padding)
    {
        case OMPaddingNone:
            underlyingPadding = kSecPaddingNone;
            hashAlgorithm = OMAlgorithmSHA1;
            hashLength = CC_SHA1_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1:
            underlyingPadding = kSecPaddingPKCS1;
            hashAlgorithm = OMAlgorithmSHA1;
            hashLength = CC_SHA1_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1SHA1:
            underlyingPadding = kSecPaddingPKCS1SHA1;
            hashAlgorithm = OMAlgorithmSHA1;
            hashLength = CC_SHA1_DIGEST_LENGTH;
            break;
            // Note: SHA2 symbols are available only on iOS 6.0 SDK
            // On older devices this will bypass to the default block below
            // leading to OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING. Support for
            // 384, 512 is not available even on iOS 6.0 though the
            // symbol exists.
        case OMPaddingPKCS1SHA224:
            underlyingPadding = kSecPaddingPKCS1SHA224;
            hashAlgorithm = OMAlgorithmSHA224;
            hashLength = CC_SHA224_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1SHA256:
            underlyingPadding = kSecPaddingPKCS1SHA256;
            hashAlgorithm = OMAlgorithmSHA256;
            hashLength = CC_SHA256_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1SHA384:
            underlyingPadding = kSecPaddingPKCS1SHA384;
            hashAlgorithm = OMAlgorithmSHA384;
            hashLength = CC_SHA384_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1SHA512:
            underlyingPadding = kSecPaddingPKCS1SHA512;
            hashAlgorithm = OMAlgorithmSHA512;
            hashLength = CC_SHA512_DIGEST_LENGTH;
            break;
        default:
            if (error)
                *error = [OMObject createErrorWithCode:
                          OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING];
            return nil;
    }
    
    privateKey = [OMCryptoService privateKeyRefWithTagPrefix:prefix
                                                    outError:error];
    if (privateKey == NULL)
        return nil;
    
    signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    
    // allocate buffer to hold signature
    signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
    
    if (!signedHashBytes)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_MEMORY_ALLOCATION_FAILURE];
        return nil;
    }
    memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
    
    // hash with chosen algorithm
    hash = [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:hashAlgorithm
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
    if (hash == nil)
    {
        if (privateKey)
            CFRelease(privateKey);
        if (signedHashBytes)
            free(signedHashBytes);
        return nil;
    }
    
    // sign the hash
    status = SecKeyRawSign(privateKey,
                           underlyingPadding,
                           (const uint8_t *)[hash bytes],
                           hashLength,
                           (uint8_t *)signedHashBytes,
                           &signedHashBytesSize
                           );
    
    if (status != noErr)
    {
        if (error)
        {
            if (status == errSecParam)
                *error = [OMObject createErrorWithCode:
                          OMERR_INVALID_INPUT];
            else
                *error = [OMObject createErrorWithCode:
                          OMERR_SIGNING_SYSTEM_ERROR, status];
        }
        if (privateKey)
            CFRelease(privateKey);
        if (signedHashBytes)
            free(signedHashBytes);
        return nil;
    }
    
    // build up signed blob.
    signedHash = [NSData dataWithBytes:(const void *)signedHashBytes
                                length:(NSUInteger)signedHashBytesSize];
    
    if (privateKey)
        CFRelease(privateKey);
    
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}

////////////////////////////////////////////////////////////////////////////////
// Verify data with Key Pair's public key
////////////////////////////////////////////////////////////////////////////////
+ (BOOL)       verifyData:(NSData *)plainText
            withSignature:(NSData *)signature
       publicKeyTagPrefix:(NSString *)prefix
  paddingAndHashingScheme:(OMCryptoPadding)padding
                 outError:(NSError **)error
{
    size_t signedHashBytesSize = 0;
    OSStatus status = noErr;
    SecKeyRef publicKey = NULL;
    SecPadding underlyingPadding;
    OMCryptoAlgorithm hashAlgorithm = OMAlgorithmSHA1;
    size_t hashLength = 0;
    NSData *hash = nil;
    
    // plain text is mandatory
    if (plainText == nil || [plainText length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return NO;
    }
    
    // signature is mandatory
    if (signature == nil || [signature length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_SIGN_CANNOT_BE_EMPTY];
        return NO;
    }

    // setup padding, hash length, hash algorithm
    switch (padding)
    {
        case OMPaddingNone:
            underlyingPadding = kSecPaddingNone;
            hashAlgorithm = OMAlgorithmSHA1;
            hashLength = CC_SHA1_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1:
            underlyingPadding = kSecPaddingPKCS1;
            hashAlgorithm = OMAlgorithmSHA1;
            hashLength = CC_SHA1_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1SHA1:
            underlyingPadding = kSecPaddingPKCS1SHA1;
            hashAlgorithm = OMAlgorithmSHA1;
            hashLength = CC_SHA1_DIGEST_LENGTH;
            break;
            // Note: SHA2 symbols are available only on iOS 6.0 SDK
            // On older devices this will bypass to the default block below
            // leading to OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING. Support for
            // 384, 512 is not available even on iOS 6.0 though the
            // symbol exists.
        case OMPaddingPKCS1SHA224:
            underlyingPadding = kSecPaddingPKCS1SHA1;
            hashAlgorithm = OMAlgorithmSHA224;
            hashLength = CC_SHA224_DIGEST_LENGTH;
            break;
        case OMPaddingPKCS1SHA256:
            underlyingPadding = kSecPaddingPKCS1SHA1;
            hashAlgorithm = OMAlgorithmSHA256;
            hashLength = CC_SHA256_DIGEST_LENGTH;
            break;
        default:
            if (error)
                *error = [OMObject createErrorWithCode:
                          OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING];
            return NO;
    }
    
    // query keychain for key ref
    publicKey = [OMCryptoService publicKeyRefWithTagPrefix:prefix
                                                  outError:error];
    if (publicKey == NULL)
        return NO;
    
    // Get the size of the assymetric block.
    signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    
    // hash with chosen algorithm
    hash = [OMCryptoService hashData:plainText
                            withSalt:nil
                           algorithm:hashAlgorithm
                  appendSaltToOutput:NO
                        base64Encode:NO
       prefixOutputWithAlgorithmName:NO
                            outError:error];
    if (hash == nil)
    {
        if (publicKey)
            CFRelease(publicKey);
        return NO;
    }
    
    status = SecKeyRawVerify(publicKey,
                             underlyingPadding,
                             (const uint8_t *)[hash bytes],
                             hashLength,
                             (const uint8_t *)[signature bytes],
                             signedHashBytesSize
                             );
    
    if (status != noErr)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_VERIFICATION_SYSTEM_ERROR, status];
        if (publicKey)
            CFRelease(publicKey);
        
        return NO;
    }
    
    if (publicKey)
        CFRelease(publicKey);
    
    return YES;
}

////////////////////////////////////////////////////////////////////////////////
// Encrypt data with Key Pair's public key
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) wrapKeyData:(NSData *)key
  withPublicKeyTagPrefix:(NSString *)prefix
                 padding:(OMCryptoPadding)padding
                outError:(NSError **)error
{
    OSStatus status = noErr;
    SecPadding underlyingPadding;
    SecKeyRef publicKey = NULL;
    
    uint8_t * cipherText = NULL;
    size_t cipherTextLength = 0;
    NSData * cipherData = nil;
    
    NSUInteger maxSupportedLength = 0;
    
    if (key == nil || [key length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return nil;
    }
    
    if (prefix == nil || [prefix length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN];
        return nil;
    }
    
    // query keychain for key ref
    publicKey = [OMCryptoService publicKeyRefWithTagPrefix:prefix
                                                  outError:error];
    if (publicKey == NULL)
        return nil;
    
    cipherTextLength = SecKeyGetBlockSize(publicKey);
    
    // setup padding
    switch (padding)
    {
            // Note:
            //
            // < For a n-bit RSA key, direct encryption (with PKCS#1 "old-style"
            // < padding) works for arbitrary binary messages up to
            // < floor(n/8)-11 bytes. In other words, for a 1024-bit RSA key
            // < (128 bytes), up to 117 bytes. With OAEP (the PKCS#1 "new-style"
            // < padding), this is a bit less: OAEP use a hash function with
            // < output length h bits; this implies a size limit of
            // < floor(n/8)-2*ceil(h/8)-2: still for a 1024-bit RSA key, with
            // < SHA-256 as hash function (h = 256), this means binary messages
            // < up to 60 bytes.
            //
        case OMPaddingNone:
            underlyingPadding = kSecPaddingNone;
            maxSupportedLength = cipherTextLength;
            break;
        case OMPaddingPKCS1:
            underlyingPadding = kSecPaddingPKCS1;
            // Note:
            // From SecKey.h
            // > When PKCS1 padding is performed, the maximum length of data
            // > that can be encrypted is the value returned by
            // >  SecKeyGetBlockSize() - 11.
            //
            // iOS implementation supports one byte lesser
            maxSupportedLength = cipherTextLength - 11 - 1;
            break;
        case OMPaddingOAEP:
            underlyingPadding = kSecPaddingOAEP;
            // Note:
            // < From "NIST: Recommendation for Pair-Wise Key Establishment
            // <       Schemes Using Integer Factorization Cryptography:"
            // <       (Aug 2009)
            // <
            // < RSA-OAEP can process up to nLen – 2hLen – 2 bytes of keying
            // < material, where nLen is the length of the recipient’s RSA
            // < modulus, and hLen is the length (in bytes) of the values output
            // < by the underlying hash function.
            
            // SHA1 output 160 bits
            // 2*(160/8) = 40
            
            // iOS implementation supports one byte lesser
            maxSupportedLength = cipherTextLength - 40 - 2 - 1;
            break;
        default:
            if (error)
                *error = [OMObject createErrorWithCode:
                          OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING];
            if (publicKey)
                CFRelease(publicKey);
            return nil;
    }
    
    if ([key length] > maxSupportedLength)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_LENGTH_MUST_BE_LESS_THAN_OR_EQUAL_TO,
                      maxSupportedLength];
        if (publicKey)
            CFRelease(publicKey);
        return nil;
    }
    
    // allocate buffer to hold signature
    cipherText = malloc( cipherTextLength * sizeof(uint8_t) );
    if (!cipherText)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_MEMORY_ALLOCATION_FAILURE];
        if (publicKey)
            CFRelease(publicKey);
        return nil;
    }
    memset((void *)cipherText, 0x0, cipherTextLength);
    
    // encrypt
    status = SecKeyEncrypt(publicKey,
                           underlyingPadding,
                           [key bytes],
                           [key length],
                           (uint8_t *)cipherText,
                           &cipherTextLength);
    
    if (status != noErr)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_ENCRYPTION_SYSTEM_ERROR, status];
        if (publicKey)
            CFRelease(publicKey);
        if (cipherText)
            free(cipherText);
        return nil;
    }
    
    // build up signed blob.
    cipherData = [NSData dataWithBytes:(const void *)cipherText
                                length:(NSUInteger)cipherTextLength];
    
    if (publicKey)
        CFRelease(publicKey);
    
    if (cipherText)
        free(cipherText);
    
    return cipherData;
}

////////////////////////////////////////////////////////////////////////////////
// Decrypt data with Key Pair's private key
////////////////////////////////////////////////////////////////////////////////
+ (NSData *) unwrapKeyData:(NSData *)key
   withPrivateKeyTagPrefix:(NSString *)prefix
                   padding:(OMCryptoPadding)padding
                  outError:(NSError **)error
{
    OSStatus status = noErr;
    SecKeyRef privateKey = NULL;
    SecPadding underlyingPadding;
    
    uint8_t *plainText = NULL;
    size_t plainTextLength = 0;
    NSData *plainTextData = nil;
    
    // plain text is mandatory
    if (key == nil || [key length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return nil;
    }
    
    // privateKey prefix is mandatory
    if (prefix == nil || [prefix length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_TAG_REQUIRED_TO_IDENTIFY_KEY_IN_KEYCHAIN];
        return nil;
    }
    
    // setup padding
    switch (padding)
    {
        case OMPaddingNone:
            underlyingPadding = kSecPaddingNone;
            break;
        case OMPaddingPKCS1:
            underlyingPadding = kSecPaddingPKCS1;
            break;
        case OMPaddingOAEP:
            underlyingPadding = kSecPaddingOAEP;
            break;
        default:
            if (error)
                *error = [OMObject createErrorWithCode:
                          OMERR_UNKNOWN_OR_UNSUPPORTED_PADDING];
            return nil;
    }
    
    // query keychain to get key ref
    privateKey = [OMCryptoService privateKeyRefWithTagPrefix:prefix
                                                    outError:error];
    if (privateKey == NULL)
        return nil;
    
    // Get the size of the assymetric block.
    plainTextLength = SecKeyGetBlockSize(privateKey);
    
    // length check
    if ([key length] > plainTextLength)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_LENGTH_MUST_BE_LESS_THAN_OR_EQUAL_TO,
                      plainTextLength];
        if (privateKey)
            CFRelease(privateKey);
        return nil;
    }
    
    // allocate space for output
    plainText = malloc( plainTextLength * sizeof(uint8_t) );
    if (!plainText)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_MEMORY_ALLOCATION_FAILURE];
        if (privateKey)
            CFRelease(privateKey);
        return nil;
    }
    memset((void *)plainText, 0x0, plainTextLength);
    
    // decrypt
    status = SecKeyDecrypt(privateKey,
                           underlyingPadding,
                           (const uint8_t *)[key bytes],
                           [key length],
                           (uint8_t *)plainText,
                           &plainTextLength);
    
    if (status != noErr)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_DECRYPTION_SYSTEM_ERROR, status];
        if (privateKey)
            CFRelease(privateKey);
        if (plainText)
            free(plainText);
        
        return nil;
    }
    
    // build up signed blob.
    plainTextData = [NSData dataWithBytes:(const void *)plainText
                                   length:(NSUInteger)plainTextLength];
    
    if (privateKey)
        CFRelease(privateKey);
    
    if (plainText)
        free(plainText);
    
    return plainTextData;
}

+ (long)secureRandomNumberOfDigits:(int)digits
{
    UInt32 state;
    if(digits > 10)
        return -1;
    UInt32 minVal = pow(10,(double)digits-1);
    UInt32 maxVal = pow(10,(double)digits);
    UInt32 randomResult = 0;
    int result = SecRandomCopyBytes(kSecRandomDefault, 4,
                                    (uint8_t*)&randomResult);
    if(result == 0)
    {
        UInt32 range = maxVal - minVal;
        state = (randomResult % range) + minVal;
    }
    else
    {
        randomResult = arc4random();
        UInt32 range = maxVal - minVal;
        state = (randomResult % range) + minVal;
    }
    return (long)state;
}

+(NSData *)generatePBKDF2EncryptionKeywithPassphrase:(NSString *)passphrase
                                                salt:(NSString *)salt
                                       hashAlgorithm:(OMCryptoAlgorithm)algorithm
                                           iteration:(NSUInteger)iterations
                                             keySize:(NSUInteger)keySize
                                            outError:(NSError **)error
{
    CCPseudoRandomAlgorithm prf;
    uint8_t *keyBuf = NULL;
    // passphrase is mandatory
    if (passphrase == nil || [passphrase length] == 0)
    {
        if (error)
            *error = [OMObject createErrorWithCode:
                      OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        return nil;
    }
    if(salt == nil || [salt length] == 0)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_SALT_REQUIRED_FOR_CHOSEN_ALGORITHM];
        return nil;
    }
    switch (algorithm)
    {
        case OMAlgorithmSSHA1:
            prf = kCCPRFHmacAlgSHA1;
            break;
        case OMAlgorithmSSHA224:
            prf = kCCPRFHmacAlgSHA224;
            break;
        case OMAlgorithmSSHA256:
            prf = kCCPRFHmacAlgSHA256;
            break;
        case OMAlgorithmSSHA384:
            prf = kCCPRFHmacAlgSHA384;
            break;
        case OMAlgorithmSSHA512:
            prf = kCCPRFHmacAlgSHA512;
            break;
        default:
            if (error)
                *error = [OMObject
                          createErrorWithCode:
                          OMERR_UNKNOWN_OR_UNSUPPORTED_ALGORITHM];
            return nil;
    }
    keyBuf = malloc(keySize * sizeof(uint8_t));
    if (keyBuf == NULL)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:OMERR_MEMORY_ALLOCATION_FAILURE];
        return nil;
    }
    memset((void *)keyBuf, 0x0, keySize);
    NSData *passphraseData = [passphrase dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];

    int status = CCKeyDerivationPBKDF(kCCPBKDF2,
                                      passphraseData.bytes,
                                      passphraseData.length,
                                      saltData.bytes,
                                      saltData.length,
                                      prf,
                                      (uint)iterations,
                                      keyBuf,
                                      keySize);
    if (status != kCCSuccess)
    {
        if (error)
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_PBKDF2_KEY_GENERATION_ERROR, errno];
        
        if (keyBuf)
            free(keyBuf);
        
        return nil;
    }
    
    // encapsulate as NSData
    NSData *symmetricKey = [[NSData alloc]
                            initWithBytes:(const void *)keyBuf
                            length:keySize];
    
    if (keyBuf)
        free(keyBuf);

    
    return symmetricKey;
}

+ (NSData *)randomDataOfLength:(size_t)length
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault,
                                    length,
                                    data.mutableBytes);
    if(result != 0)
        return nil;
    
    return data;
}

@end
