/* Copyright (c) 2011, 2015, Oracle and/or its affiliates. 
All rights reserved.*/

/*
 NAME
 OMCryptoService.h - Oracle Mobile Cryptography Service
 
 DESCRIPTION
 This class provides Crypto Service to OAM Mobile and Social SDK
 
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
 vismishr    04/22/15 - Added PBKDF2 API
 vismishr    09/13/13 - Added method to generate random number with given no. of
                        digits
 ashkusin    06/13/13 - Added method to generate symmetric key based on user 
                        specified pass phrase 
 msadasiv    02/21/13 - XbranchMerge msadasiv_keypair_keytype_revert from
                        st_ngam_11.1.2.1.0
 msadasiv    11/20/12 - Bug 14836655 - set ksecattraccessible to a secure 
                                       by default value
 msadasiv    10/17/12 - Rename hashing and asymmetric key encryption methods 
 msadasiv    09/24/12 - Implementation
 sativenk    06/24/12 - Creation
 */

/*!
 @enum       OMCryptoAlgorithm
 @discussion Hashing and symmetric key encryption algorithms supported
 by OMCryptoService.
 @constant   OMAlgorithmMD5       Hashing MD5, without salt
 @constant   OMAlgorithmSHA1      Hashing SHA-1, without salt
 @constant   OMAlgorithmSHA224    Hashing SHA-224, without salt
 @constant   OMAlgorithmSHA256    Hashing SHA-256, without salt
 @constant   OMAlgorithmSHA384    Hashing SHA-384, without salt
 @constant   OMAlgorithmSHA512    Hashing SHA-512, without salt
 @constant   OMAlgorithmSMD5      Hashing MD5, with salt
 @constant   OMAlgorithmSSHA1     Hashing SHA-1, with salt
 @constant   OMAlgorithmSSHA224   Hashing SHA-224, with salt
 @constant   OMAlgorithmSSHA256   Hashing SHA-256, with salt
 @constant   OMAlgorithmSSHA384   Hashing SHA-384, with salt
 @constant   OMAlgorithmSSHA512   Hashing SHA-512, with salt
 @constant   OMAlgorithmAES128    Symmetric key encryption with Advanced
                                  Encryption Standard 128 bit block. Supported
                                  key sizes 16, 24, 32.
 @constant   OMAlgorithmDES       Data Encryption Standard. Block size 8. 
                                  Key size 8.
 @constant   OMAlgorithm3DES      Triple DES. Block size 8. Key size 24. 
*/
enum
{
    // Hashing
    OMAlgorithmMD5,
    OMAlgorithmSHA1,
    OMAlgorithmSHA224,
    OMAlgorithmSHA256,
    OMAlgorithmSHA384,
    OMAlgorithmSHA512,
    
    // Salted Hashing
    OMAlgorithmSMD5,
    OMAlgorithmSSHA1,
    OMAlgorithmSSHA224,
    OMAlgorithmSSHA256,
    OMAlgorithmSSHA384,
    OMAlgorithmSSHA512,
    
    // Symmetric key encryption
    OMAlgorithmAES128,
    OMAlgorithmDES,
    OMAlgorithm3DES,
};
typedef NSUInteger OMCryptoAlgorithm;

/*!
 @enum       OMCryptoPadding
 @discussion Padding for use in various symmetric and keypair crypto
 algorithms.
 
 @warning    When an operation is tried with an unsupported padding scheme,
 error code 33 - Unknown or unsupported padding is returned.
 
 @constant   OMPaddingNone         Perform no padding. Can be used with 
                                   symmetric key algorithms when input is a 
                                   multiple of the algorithm's block size. For
                                   keypair algorithms this padding scheme
                                   specifies that data be processed as-is.
                                   Can be used with all symmetric key and
                                   keypair algorithms. This is the default value
                                   when no other padding is chosen.
 @constant   OMPaddingPKCS7        PKCS7 padding scheme. Used only with 
                                   symmetric key encryption/decryption 
                                   algorithms.
 @constant   OMPaddingPKCS1        PKCS1 padding scheme for use in keypair
                                   algorithms.
 @constant   OMPaddingOAEP         OAEP padding scheme for use in keypair wrap/
                                   unwrap algorithms.
 @constant   OMPaddingPKCS1SHA1    PKCS1 padding and SHA1 hashing scheme for use
                                   in keypair sign/verify operations.
 @constant   OMPaddingPKCS1SHA224  PKCS1 padding and SHA224 hashing scheme for
                                   use in keypair sign/verify operations.
                                   Available from iOS 6.0. On earlier iOS
                                   versions throws error code 23 - Input value 
                                   invalid.
 @constant   OMPaddingPKCS1SHA256  PKCS1 padding and SHA256 hashing scheme for
                                   use in keypair sign/verify operations.
                                   Available from iOS 6.0. On earlier iOS
                                   versions throws error code 23 - Input value
                                   invalid.
*/
enum
{
    OMPaddingNone,
    OMPaddingPKCS7,
    OMPaddingPKCS1,
    OMPaddingOAEP,
    OMPaddingPKCS1SHA1,
    OMPaddingPKCS1SHA224,
    OMPaddingPKCS1SHA256,
};
typedef uint32_t OMCryptoPadding;

/*!
 @enum       OMCryptoMode
 @discussion Modes of operation for symmetric key algorithms. Modes are
 used with block ciphers like AES, DES and 3DES.
 
 @constant   OMModeCBC             Cipher-block Chaining mode. This is the
                                   default mode chosen when OMCryptoMode is not
                                   specified.
 @constant   OMModeECB             Eletronic codebook mode.
*/
enum
{
    OMModeCBC,
    OMModeECB,
};
typedef uint32_t OMCryptoMode;

/*!
 @enum       OMCryptoKeyType
 @discussion Key types for use in keypair algorithms (asymmetric key). 
 Additional key types will be added based on availability of support from
 underlying platform.
 
 @constant   OMKeyTypeRSA           RSA
*/
enum
{
    OMKeyTypeRSA,
};
typedef uint32_t OMCryptoKeyType;

/** OMCryptoService provides common crypto features like hashing,
 symmetric key cipher and keypair operations.
 */
@interface OMCryptoService : NSObject
{
    
}

/** @name Hashing */
#pragma mark -
#pragma mark Hashing
/**
 * Generate cryptographic hash using MD5 algorithm.
 *
 * @param  plainText  Data to be hashed.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. Returns nil if an
 *                    error is encountered.
 */
+ (NSData *) MD5HashData:(NSData *)plainText
                outError:(NSError **)error;

/**
 * Generate cryptographic hash using MD5 algorithm with an optional salt.
 * This is a variation of MD5HashData that returns base64 encoded output.
 * The algorithm name and salt if any are also prefixed to the output.
 *
 * @param  plainText  Data to be hashed.
 * @param  saltLength Generate salt of given bit length and add to data
 *                    before hashing. Must be a multiple of 4. Can be set to 0
 *                    to perform hashing without a salt.
 * @param  outSalt    Returns the salt, if generated.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. The output data is
 *                    Base64 encoded. If a salt is generated, the output is
 *                    prefixed with salt. The algorithm name is also prefixed
 *                    to the output as {MD5} or {SaltedMD5}. Returns nil if an
 *                    error is encountered.
 */
+ (NSString *)  MD5HashAndBase64EncodeData:(NSData *)plainText
                       withSaltOfBitLength:(NSUInteger)saltLength
                                   outSalt:(NSString **)outSalt
                                  outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA1 algorithm.
 *
 * @param  plainText  Data to be hashed.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. Returns nil if an
 *                    error is encountered.
 */
+ (NSData *) SHA1HashData:(NSData *)plainText
                 outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA1 algorithm with an optional salt.
 * This is a variation of SHA1HashData that returns base64 encoded output.
 * The algorithm name and salt if any are also prefixed to the output.
 *
 * @param  plainText  Data to be hashed.
 * @param  saltLength Generate salt of given bit length and add to data
 *                    before hashing. Must be a multiple of 4. Can be set to 0
 *                    to perform hashing without a salt.
 * @param  outSalt    Returns the salt, if generated.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. The output data is
 *                    Base64 encoded. If a salt is generated, the output is
 *                    prefixed with salt. The algorithm name is also prefixed
 *                    to the output as {SHA-1} or {SaltedSHA-1}. Returns nil if
 *                    an error is encountered.
 */
+ (NSString *)  SHA1HashAndBase64EncodeData:(NSData *)plainText
                        withSaltOfBitLength:(NSUInteger)saltLength
                                    outSalt:(NSString **)outSalt
                                   outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA224 algorithm.
 *
 * @param  plainText  Data to be hashed.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. Returns nil if an
 *                    error is encountered.
 */
+ (NSData *) SHA224HashData:(NSData *)plainText
                   outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA224 algorithm with an optional salt.
 * This is a variation of SHA224HashData that returns base64 encoded output.
 * The algorithm name and salt if any are also prefixed to the output.
 *
 * @param  plainText  Data to be hashed.
 * @param  saltLength Generate salt of given bit length and add to data
 *                    before hashing. Must be a multiple of 4. Can be set to 0
 *                    to perform hashing without a salt.
 * @param  outSalt    Returns the salt, if generated.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. The output data is
 *                    Base64 encoded. If a salt is generated, the output is
 *                    prefixed with salt. The algorithm name is also prefixed
 *                    to the output as {SHA-224} or {SaltedSHA-224}. Returns nil
 *                    if an error is encountered.
 */
+ (NSString *)  SHA224HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA256 algorithm.
 *
 * @param  plainText  Data to be hashed.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. Returns nil if an
 *                    error is encountered.
 */
+ (NSData *) SHA256HashData:(NSData *)plainText
                   outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA256 algorithm with an optional salt.
 * This is a variation of SHA256HashData that returns base64 encoded output.
 * The algorithm name and salt if any are also prefixed to the output.
 *
 * @param  plainText  Data to be hashed.
 * @param  saltLength Generate salt of given bit length and add to data
 *                    before hashing. Must be a multiple of 4. Can be set to 0
 *                    to perform hashing without a salt.
 * @param  outSalt    Returns the salt, if generated.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. The output data is
 *                    Base64 encoded. If a salt is generated, the output is
 *                    prefixed with salt. The algorithm name is also prefixed
 *                    to the output as {SHA-256} or {SaltedSHA-256}. Returns nil
 *                    if an error is encountered.
 */
+ (NSString *)  SHA256HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA384 algorithm.
 *
 * @param  plainText  Data to be hashed.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. Returns nil if an
 *                    error is encountered.
 */
+ (NSData *) SHA384HashData:(NSData *)plainText
                   outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA384 algorithm with an optional salt.
 * This is a variation of SHA384HashData that returns base64 encoded output.
 * The algorithm name and salt if any are also prefixed to the output.
 *
 * @param  plainText  Data to be hashed.
 * @param  saltLength Generate salt of given bit length and add to data
 *                    before hashing. Must be a multiple of 4. Can be set to 0
 *                    to perform hashing without a salt.
 * @param  outSalt    Returns the salt, if generated.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. The output data is
 *                    Base64 encoded. If a salt is generated, the output is
 *                    prefixed with salt. The algorithm name is also prefixed
 *                    to the output as {SHA-384} or {SaltedSHA-384}. Returns nil
 *                    if an error is encountered.
 */
+ (NSString *)  SHA384HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA512 algorithm.
 *
 * @param  plainText  Data to be hashed.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. Returns nil if an
 *                    error is encountered.
 */
+ (NSData *) SHA512HashData:(NSData *)plainText
                   outError:(NSError **)error;

/**
 * Generate cryptographic hash using SHA512 algorithm with an optional salt.
 * This is a variation of SHA512HashData that returns base64 encoded output.
 * The algorithm name and salt if any are also prefixed to the output.
 *
 * @param  plainText  Data to be hashed.
 * @param  saltLength Generate salt of given bit length and add to data
 *                    before hashing. Must be a multiple of 4. Can be set to 0
 *                    to perform hashing without a salt.
 * @param  outSalt    Returns the salt, if generated.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash value when successful. The output data is
 *                    Base64 encoded. If a salt is generated, the output is
 *                    prefixed with salt. The algorithm name is also prefixed
 *                    to the output as {SHA-512} or {SaltedSHA-512}. Returns nil
 *                    if an error is encountered.
 */
+ (NSString *)  SHA512HashAndBase64EncodeData:(NSData *)plainText
                          withSaltOfBitLength:(NSUInteger)saltLength
                                      outSalt:(NSString **)outSalt
                                     outError:(NSError **)error;

/**
 * Generate salt for use in cryptographic hash generation.
 *
 * @param  length     Length of salt in bits. Must be a multiple of 4.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            The generated salt as Hex (or Base16) encoded string.
 *                    Returns nil if an error is encountered.
 */
+ (NSString *) generateSaltOfBitLength:(NSUInteger)length
                              outError:(NSError **)error;

/**
 * Generate cryptographic hash of input with or without salt.
 *
 * @param  plainText  Data to be hashed.
 * @param  salt       Salt for the hash. If a non-salted algorithm is chosen
 *                    salt must be nil. If a salted algorithm is chosen salt
 *                    must be provided.
 * @param  algorithm  The hashing algorithm to use for hashing. Refer
 *                    OMCryptoAlgorithm for values.
 * @param  appendSalt Prefix the given salt to output. Only effective
 *                    when base64EncodeOutput is YES. Ignored if
 *                    base64EncodeOutput is NO.
 * @param  base64     If Yes, output is Base64 encoded.
 * @param  prefixAlgorithm Prefix algorithm name to output. Only
 *                    effective when base64EncodeOutput is YES. Ignored if
 *                    base64EncodeOutput is NO. Taking SHA1 as example the
 *                    algorithm name prefix is done with the format: {SHA-1}.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns hash as NSData object if base64EncodeOutput is NO
 *                    Returns hash a NSString object if base64EncodeOutput is 
 *                    YES. Returns nil if an error is encountered.
 */
+ (id)                hashData:(NSData *)plainText
                      withSalt:(NSString *)salt
                     algorithm:(OMCryptoAlgorithm)algorithm
            appendSaltToOutput:(BOOL)appendSalt
                  base64Encode:(BOOL)base64
 prefixOutputWithAlgorithmName:(BOOL)prefixAlgorithm
                      outError:(NSError **)error;

/** @name Symmetric key */
#pragma mark -
#pragma mark Symmetric key
/**
 * Encrypt data with symmetric key using AES algorithm and PKCS7 padding
 * in CBC mode.
 *
 * @param  plainText  The data to be encrypted.
 * @param  symmetricKey Symmetric key for encryption. Length must
 *                    match the key length required by the algorithm.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns encrypted data if encryption is successful.
 *                    Returns nil if an error is encountered.
 */
+ (NSData *)          encryptData:(NSData *)plainText
                 withSymmetricKey:(NSData *)symmetricKey
                         outError:(NSError **)error;

/**
 * Encrypt data with symmetric key using AES128 algorithm and PKCS7 padding
 * in CBC mode. A symmetric key of requested length can be generated and used 
 * for encryption.
 *
 * @param  plainText  The data to be encrypted.
 * @param  keyLength  Generate symmetric key of given length.
 *                    Length must not be 0.
 * @param  key        On return contains the generated symmetric key.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns encrypted data if encryption is successful.
 *                    Returns nil if an error is encountered.
 */
+ (NSData *)          encryptData:(NSData *)plainText
         withSymmetricKeyOfLength:(NSUInteger)keyLength
                  outSymmetricKey:(NSData **)key
                         outError:(NSError **)error;

/**
 * Decrypt data with symmetric key using AES128 algorithm and PKCS7 padding
 * in CBC mode.
 *
 * @param  cipherText The data to be decrypted.
 * @param  symmetricKey Symmetric key to use for decryption.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns decrypted data if decryption is successful.
 *                    Returns nil if an error is encountered.
 */
+ (NSData *)          decryptData:(NSData *)cipherText
                 withSymmetricKey:(NSData *)symmetricKey
                         outError:(NSError **)error;

/**
 * Generate a key for use in symmetric encryption and decryption operations.
 *
 * @param  length     Length of key in bytes to be generated. Any length can be
 *                    generated though when used, it must match the requirements
 *                     of the algorithm.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            The resultant hash or nil if an error is encountered.
 */
+ (NSData *) generateSymmetricKeyOfLength:(NSUInteger)length
                                 outError:(NSError **)error;
/**
 * Generate a key for use in symmetric encryption and decryption operations.
 *
 * @param  passPhrase A string that is used in deriving symmetric key
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            The resultant hash or nil if an error is encountered.
 */
+ (NSData *) generateSymmetricKeyWithPassPhrase:(NSString *) passPhrase
                                       outError:(NSError **) error;

/**
 * Encrypt data with symmetric key.
 *
 * @param  plainText  The data to be encrypted.
 * @param  symmetricKey Symmetric key for encryption. Length must be
 *                    match the key length required by the algorithm.
 * @param  iv         Optional, initialization vector for encryption.
 *                    The length must be the same as the block size of the
 *                    selected algorithm. Ignored if OMModeECB is used. In the
 *                    default mode OMModeCBC if no initializationVector is
 *                    provided a value of all 0's is used.
 * @param  algorithm  The symmetric encryption algorithm to use for encryption.
 *                    Refer OMCryptoAlgorithm. The supported algorithms are 
 *                    AES128, DES and 3DES.
 * @param  padding    Padding to be used when plainText is not a multiple of
 *                    algorithm's block size. Refer OMCryptoPadding for values.
 *                    OMPaddingPKCS7 is the only padding type supported.
 * @param  mode       Encryption mode. The default is  OMOModeCBC.
 * @param  base64     If YES, output data is Base64 encoded.
 * @param  prefix     Prefix algorithm name to output. Only
 *                    effective when base64EncodeOutput is YES. Ignored if
 *                    base64EncodeOutput is NO. Taking AES128 algorithm as an
 *                    example the prefix format is {AES}.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns encrypted data as NSData object if 
 *                    base64EncodeOutput is NO. Returns NSString object if 
 *                    base64EncodeOutput is YES. Returns nil if an error is
 *                    encountered.
 */
+ (id)                encryptData:(NSData *)plainText
                 withSymmetricKey:(NSData *)symmetricKey
             initializationVector:(NSData *)iv
                        algorithm:(OMCryptoAlgorithm)algorithm
                          padding:(OMCryptoPadding)padding
                             mode:(OMCryptoMode)mode
               base64EncodeOutput:(BOOL)base64
    prefixOutputWithAlgorithmName:(BOOL)prefix
                         outError:(NSError **)error;

/**
 * Decrypt data with symmetric key.
 *
 * @param  cipherText The data to be decrypted.
 * @param  symmetricKey Symmetric key required for decryption. Length must
 *                    match the key length required by the algorithm.
 * @param  iv         Initialization vector for decryption. The length
 *                    must be the same as the block size of the selected
 *                    algorithm. Ignored if OMModeECB is used. In the default
 *                    mode OMModeCBC if no initializationVector is provided a
 *                    value of all 0's is used.
 * @param  algorithm  The symmetric encryption algorithm to use for decryption.
 * @param  padding    Padding. Use the same value used for encryption.
 * @param  mode       Mode used for encryption. OMModeCBC is the default.
 * @param  prefix     If YES, algorithm name prefix is
 *                    removed before decryption. Taking AES128 algorithm as an
 *                    example the expected prefix format is {AES}.
 * @param  base64     If YES, input data is Base64 decoded before
 *                    decryption.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns decrypted data when successful.
 *                    Returns nil if an error is encountered.
 */
+ (NSData *)          decryptData:(id)cipherText
                 withSymmetricKey:(NSData *)symmetricKey
             initializationVector:(NSData *)iv
                        algorithm:(OMCryptoAlgorithm)algorithm
                          padding:(OMCryptoPadding)padding
                             mode:(OMCryptoMode)mode
 isInputPrefixedWithAlgorithmName:(BOOL)prefix
             isInputBase64Encoded:(BOOL)base64
                         outError:(NSError **)error;

/** @name Keypair */
#pragma mark -
#pragma mark Key pair
/**
 * Generate key pair and store it in keychain.
 *
 * @param  length     The length of the key in bits.
 * @param  tagPrefix  When storing the generated key pair, sets the
 *                    ApplicationTag attribute value to identify the key pair.
 *                    The value is the combination of the given prefix and
 *                    ".private" or ".public" respectively to refer to the
 *                    private or public key. The private key is stored with tag
 *                    <keychainTagPrefix>.private and the public
 *                    key is stored with tag <keychainTagPrefix>.public. For
 *                    example, when the keychainTagPrefix is
 *                    "com.yourcompany.appauth", the private key will be stored
 *                    with tag  "com.yourcompany.appauth.private".
 * @param  protection Protect the keychain item at this level. Takes the same
 *                    values accepted by OM_PROP_KEYCHAIN_DATA_PROTECTION.
 *                    If nil, the default value chosen is
 *                    OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY
 * @param  error      Pointer to pointer to NSError object to which error will
 *                    be copied, if an error is encountered. This parameter is
 *                    mandatory to unambiguously know if verification failed or
 *                    if an error was encountered.
 * @return            Returns YES if key pair is successfully generated and
 *                    stored. Returns NO if key pair generation fails or if
 *                    an error is encountered.
 */
+ (BOOL) generateAndStoreKeyPairOfBitLength:(NSUInteger)length
                          keychainTagPrefix:(NSString *)tagPrefix
                                 protection:(NSString *)protection
                                   outError:(NSError **)error;

/**
 * Generate key pair and store it in keychain.
 *
 * @param  length     The length of the key in bits.
 * @param  keyType    Key pair type. Refer OMCryptoKeyType
 * @param  tagPrefix  When storing the generated key pair, sets the
 *                    ApplicationTag attribute value to identify the key pair.
 *                    The value is the combination of the given prefix and
 *                    ".private" or ".public" respectively to refer to the
 *                    private or public key. The private key is stored with tag
 *                    <keychainTagPrefix>.private and the public
 *                    key is stored with tag <keychainTagPrefix>.public. For
 *                    example, when the keychainTagPrefix is
 *                    "com.yourcompany.appauth", the private key will be stored
 *                    with tag  "com.yourcompany.appauth.private".
 * @param  protection Protect the keychain item at this level. Takes the same
 *                    values accepted by OM_PROP_KEYCHAIN_DATA_PROTECTION.
 *                    If nil, the default value chosen is
 *                    OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY
 * @param  error      Pointer to pointer to NSError object to which error will
 *                    be copied, if an error is encountered. This parameter is
 *                    mandatory to unambiguously know if verification failed or
 *                    if an error was encountered.
 * @return            Returns YES if key pair is successfully generated and
 *                    stored. Returns NO if key pair generation fails or if
 *                    an error is encountered.
 */
+ (BOOL) generateAndStoreKeyPairOfBitLength:(NSUInteger)length
                                    keyType:(OMCryptoKeyType)keyType
                          keychainTagPrefix:(NSString *)tagPrefix
                                 protection:(NSString *)protection
                                   outError:(NSError **)error;

/**
 * Retrieve public key bits from keychain.
 *
 * @param  tagPrefix  Retrieve the stored public key in keychain based on the
 *                    value of ApplicationTag attribute. The value of the
 *                    attribute is the combination of the given prefix and
 *                    the string ".public". For example, when the TagPrefix is
 *                    "com.yourcompany.appauth", the public key with the tag
 *                    "com.yourcompany.appauth.public" is picked.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns public key data on success or nil on failure.
 */
+ (NSData *) publicKeyFromKeychainWithTagPrefix:(NSString *)tagPrefix
                                       outError:(NSError **)error;

/**
 * Delete key pair from keychain.
 *
 * @param  tagPrefix  Delete a stored key pair in keychain based on the value of
 *                    ApplicationTag attribute. The value of the attribute is
 *                    the combination of TagPrefix and string ".public" or
 *                    ".private". For example, when the TagPrefix is
 *                    "com.yourcompany.appauth", the public key with tag
 *                    "com.yourcompany.appauth.public" and the private
 *                    key with tag "com.yourcompany.appauth.private" is deleted.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.  This parameter is
 *                    mandatory to unambiguously know if verification failed or
 *                    if an error was encountered.
 * @return            Returns YES on success. Returns NO if key item is not
 *                    found or if an error was encountered.
 */
+ (BOOL) deleteKeyPairFromKeychainWithTagPrefix:(NSString *)tagPrefix
                                       outError:(NSError **)error;

/**
 * Sign data using stored private key.
 *
 * @param  plainText  The data to be signed.
 * @param  prefix     Sign with the stored private key in keychain
 *                    identified with the value of ApplicationTag attribute. The
 *                    value of the attribute is the combination of the given
 *                    prefix and the string ".public". For example, when the
 *                    TagPrefix is "com.yourcompany.appauth", the public key
 *                    with the tag "com.yourcompany.appauth.public" is picked.
 * @param  padding    Padding and hashing algorithm to use for
 *                    signing. Refer OMCryptoPadding for values.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns signature data on success or nil on failure.
 */
+ (NSData *)          signData:(NSData *)plainText
       withPrivateKeyTagPrefix:(NSString *)prefix
       paddingAndHashingScheme:(OMCryptoPadding)padding
                      outError:(NSError **)error;

/**
 * Verify signature using stored public key.
 *
 * @param  plainText  The data to be verified.
 * @param  signature  Signature bytes to verify the data with.
 * @param  prefix     Verify with the stored public key in keychain
 *                    identified with the value of ApplicationTag attribute. The 
 *                    value of the attribute is the combination of the given
 *                    prefix and  the string ".public". For example, when the
 *                    TagPrefix is "com.yourcompany.appauth", the public key
 *                    with the tag "com.yourcompany.appauth.public" is picked.
 * @param  padding    Padding and hashing algorithm used when
 *                    signing. Refer OMCryptoPadding for values.
 * @param  error      Pointer to pointer to NSError object to which error to be
 *                    copied, if there is an error. This parameter is mandatory
 *                    to unambiguously know if verification failed or an
 *                    error was encountered.
 * @return            Returns YES, if data is successfully verified.
 *                    Returns NO, if verification failed or an error was
 *                    encountered.
 */
+ (BOOL)              verifyData:(NSData *)plainText
                   withSignature:(NSData *)signature
              publicKeyTagPrefix:(NSString *)prefix
         paddingAndHashingScheme:(OMCryptoPadding)padding
                        outError:(NSError **)error;

/**
 * Wrap a key (typically symmetric key) with a stored public key.
 *
 * @param  key        The key to be wrapped. The maximum length is
 *                    dependent on the key size and the padding used.
 * @param  prefix     Encrypt with the stored public key in keychain
 *                    identified by the value of ApplicationTag attribute. The
 *                    value of the attribute is a combination of the given
 *                    prefix and the string ".public". For example, when the
 *                    TagPrefix is "com.yourcompany.appauth", the public key
 *                    with tag "com.yourcompany.appauth.public" is picked.
 * @param  padding    Padding to use for encryption. Refer OMCryptoPadding for
 *                    values.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns wrapped symmetric key on success 
 *                    or nil on failure.
 */
+ (NSData *)     wrapKeyData:(NSData *)key
      withPublicKeyTagPrefix:(NSString *)prefix
                     padding:(OMCryptoPadding)padding
                    outError:(NSError **)error;

/**
 * Unwrap a wrapped key (typically symmetric key) with a stored private key.
 *
 * @param  key        The wrapped key to unwrap.
 * @param  prefix     Identify the stored key in keychain based on
 *                    the value of ApplicationTag attribute. The value of the
 *                    attribute is the combination of the given prefix and the
 *                    string ".private". For example, when the TagPrefix is
 *                    "com.yourcompany.appauth", the private key is searched for
 *                    with tag  "com.yourcompany.appauth.private".
 * @param  padding    Padding used during encryption.
 *                    Refer OMCryptoPadding for values.
 * @param  error      If not nil, on return this points to an error object when
 *                    an error is encountered.
 * @return            Returns unwrapped symmetric key on success 
 *                    or nil on failure.
 */
+ (NSData *)   unwrapKeyData:(NSData *)key
     withPrivateKeyTagPrefix:(NSString *)prefix
                     padding:(OMCryptoPadding)padding
                    outError:(NSError **)error;

/**
 * Generates a secure random number with given number of digits.
 *
 * @param   digits    Number of digits in the generated random number. Maximum
 *                    number of digit can be 10
 * @return            Returns a random number with given number of digits and -1
                      if number of digits passed is greater than 10
 *
 */
+ (long)secureRandomNumberOfDigits:(int)digits;

/**
 * Generates a symmetric encryption key of specified size using PBKDF2.
 *
 * @param passphrase String containing passphrase input to PBKDF2
 * @param salt String containing salt to be used to generate key
 * @param hashAlgorithm OMCryptoAlgorithm specifying the hashing algorithm to be
 *                      used with PBKDF2.
 * @param iteration Number of iterations of PBKDF2 to genarate the key
 * @param keySize The size of the key to be generated
 * @param outError Refrence to a NSError object that will contain any error
 *                 while generating the key
 * @return         NSData containing the symmetric encryption key
 */

+(NSData *)generatePBKDF2EncryptionKeywithPassphrase:(NSString *)passphrase
                                                salt:(NSString *)salt
                                       hashAlgorithm:(OMCryptoAlgorithm)algorithm
                                           iteration:(NSUInteger)iterations
                                             keySize:(NSUInteger)keySize
                                            outError:(NSError **)error;
/**
 * Genarates random NSData of specified length.
 * 
 * @param length Length in bytes that specified the number of random bytes to be
 *               generated.
 * @return       NSData containing random bytes of specified length.
 */
+ (NSData *)randomDataOfLength:(size_t)length;

@end
