/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMSecureCrypto.h"
#import "OMObject.h"
#import "OMDataSerializationHelper.h"
#import "OMErrorCodes.h"
#import "OMKeyStore.h"
#import "OMCryptoService.h"
#import "NSData+OMBase64.h"
#import "IDMMobileSDKv2Library.h"

@interface OMSecureCrypto ()

@property (nonatomic, weak) OMKeyStore *keyStore;

@end


@implementation OMSecureCrypto

- (id)initWithKeyStore:(OMKeyStore*)keyStore error:(NSError**)error;
{
    self = [super init];
    
    if (self)
    {
        
        if (keyStore)
        {
            _keyStore = keyStore;
        }
        else
        {
            if (error)
                *error = [OMObject
                          createErrorWithCode:OMERR_KEYCHAIN_CANNOT_BE_NIL];
            self = nil;
        }
        
        
    }
    
    return self;
}

- (NSData*)encryptData:(NSData*)data withKey:(NSString*)encryptKey
                 error:(NSError**)error
{
    
    NSData *encKey = nil;
    
    if (encryptKey == nil)
    {
        encKey = [self.keyStore defaultKey];
        
    }
    else
    {
        encKey = [self.keyStore getKey:encryptKey];
        
    }
    
    NSData *archivedData = [OMDataSerializationHelper serializeData:data];

    NSData *encryptedData = [OMCryptoService encryptData:archivedData
                                        withSymmetricKey:encKey
                                                outError:error];
    

    return encryptedData;
}

- (id)decryptData:(NSData*)data withKey:(NSString*)encryptKey
                 error:(NSError**)error
{
    NSData *encKey = nil;
    
    if (encryptKey == nil)
    {
        encKey = [self.keyStore defaultKey];
        
    }
    else
    {
        encKey = [self.keyStore getKey:encryptKey];
        
    }
    

    NSData *decryptedData = [OMCryptoService decryptData:data
                                        withSymmetricKey:encKey
                                                outError:error];
    id dec = [OMDataSerializationHelper deserializeData:decryptedData];
    
    return dec;
}

- (NSString*)encryptString:(NSString*)plainText withKey:(NSString*)encryptKey
                     error:(NSError**)error;
{
    NSData *encKey = nil;
    
    if (encryptKey == nil)
    {
        encKey = [self.keyStore defaultKey];
        
    }
    else
    {
        encKey = [self.keyStore getKey:encryptKey];
        
    }

    NSData *archivedData = [OMDataSerializationHelper serializeData:plainText];

    NSString *encryptedData = [OMCryptoService encryptData:archivedData
                                        withSymmetricKey:encKey
                                    initializationVector:nil
                                               algorithm:OMAlgorithmAES128
                                                 padding:OMPaddingPKCS7
                                                    mode:OMModeCBC
                                      base64EncodeOutput:YES
                           prefixOutputWithAlgorithmName:NO
                                                outError:error];
    
    return encryptedData;
    
}

- (NSString*)decryptString:(NSString*)plainText withKey:(NSString*)encryptKey
                     error:(NSError**)error;
{
    NSData *encKey = nil;
    
    if (encryptKey == nil)
    {
        encKey = [self.keyStore defaultKey];
        
    }
    else
    {
        encKey = [self.keyStore getKey:encryptKey];
        
    }

        NSData *decryptedData  = [OMCryptoService decryptData:plainText
                    withSymmetricKey:encKey
                initializationVector:nil
                           algorithm:(OMAlgorithmAES128)
                             padding:OMPaddingPKCS7 mode:OMModeCBC
    isInputPrefixedWithAlgorithmName:NO
                isInputBase64Encoded:YES
                        outError:error];
    
    if (!decryptedData)
    {
        return nil;
    }
    NSString *decryptedString = [OMDataSerializationHelper deserializeData:decryptedData];

    return decryptedString;
    
}

@end
