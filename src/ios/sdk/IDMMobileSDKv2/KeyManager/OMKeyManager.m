/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMKeyManager.h"
#import "OMKeyStore.h"
#import "OMObject.h"
#import "OMErrorCodes.h"
#import "OMUtilities.h"
#import "OMCryptoService.h"
#import "OMDefinitions.h"


@interface OMKeyManager ()

@property (nonatomic, strong) NSMutableDictionary *keyStoreMap;

@end

@implementation OMKeyManager

+ (OMKeyManager *)sharedManager
{
    static OMKeyManager *kSharedManger = nil;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        kSharedManger = [[self alloc] init];
        
    });
    
    return kSharedManger;
}


-(id)init
{
    if (self = [super init])
    {
        _keyStoreMap = [NSMutableDictionary dictionary];
    }
    
    return self;
}

- (OMKeyStore *)keyStore:(NSString *)keyStoreId kek:(NSData*)kek error:(NSError**)error;
{
    OMKeyStore *keyStore = nil;
    NSInteger errorCode = 0;

    if (!keyStoreId || !kek)
    {
        errorCode = OMERR_KEY_IS_NIL;
    }
    
    if (self.keyStoreMap[keyStoreId] && [self.keyStoreMap[keyStoreId] isValidKek:kek])
    {
        keyStore = self.keyStoreMap[keyStoreId];
    }
    else if ([self isKeyStoreCreated:keyStoreId kek:kek])
    {
        keyStore = [[OMKeyStore alloc] initWithKeyStoreId:keyStoreId kek:kek];
        [keyStore loadKeys];
        self.keyStoreMap[keyStoreId] = keyStore;
    }
    else if(errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }

    return keyStore;
}

- (OMKeyStore*)createKeyStore:(NSString *)keyStoreId kek:(NSData*)kek
                    overWrite:(BOOL)overWrite error:(NSError**)error
{
    OMKeyStore *keyStore = nil;
    NSInteger errorCode = 0;
    
    if (!keyStoreId || !kek)
    {
        errorCode = OMERR_KEY_IS_NIL;
    }

    if (!errorCode)
    {
        BOOL isKeyStoreCreated = [self isKeyStoreCreated:keyStoreId kek:kek];
        
        if (isKeyStoreCreated && !overWrite)
        {
            errorCode = OM_KEYSTORE_EXIST;

        }else
        {
            keyStore = [[OMKeyStore alloc] initWithKeyStoreId:keyStoreId kek:kek];
            [keyStore createKey:OM_DEFAULT_KEY overwrite:false error:error];
            self.keyStoreMap[keyStoreId] = keyStore;
            
        }
    }
    else if(errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }

    return keyStore;
}

- (OMKeyStore*)updateKeyStore:(NSString *)keyStoreId kek:(NSData*)kek
                       newKek:(NSData*)newKek error:(NSError**)error
{
    OMKeyStore *keyStore = nil;
    NSInteger errorCode = 0;
    
    if (!keyStoreId || !kek || !newKek)
    {
        errorCode = OMERR_KEY_IS_NIL;
    }

    if (!errorCode)
    {
        keyStore = [self keyStore:keyStoreId kek:kek error:error];
      
        if (keyStore)
        {
           if ([self renameKeyStoreFile:kek withNewKek:newKek storeId:keyStoreId])
           {
               [keyStore updateKeyEncryptionKey:newKek];
               
           }
           else
           {
               errorCode = OMERR_PIN_CHANGE_FAILED;
           }
        }
    }
    else if(errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }
    
    return keyStore;
}

- (void)deleteKeyStore:(NSString *)keyStoreId kek:(NSData*)kek error:(NSError**)error;
{
    NSInteger errorCode = 0;
    
    if (!keyStoreId || !kek)
    {
        errorCode = OMERR_KEY_IS_NIL;
    }
    
    if (!errorCode)
    {
        BOOL keyStoreIsCreated = [self isKeyStoreCreated:keyStoreId kek:kek];
        
        if(keyStoreIsCreated)
        {
           // deleteFIle
          NSString *fileName = [self hashFileNameForKeystore:keyStoreId kek:kek];
         [[NSFileManager defaultManager] removeItemAtPath:[self
                                        filePathForfile:fileName] error:error];
        }
        
        if ([self.keyStoreMap valueForKey:keyStoreId])
        {
            [self.keyStoreMap removeObjectForKey:keyStoreId];
        }
    }

    if(errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }

}
- (BOOL)isKeyStoreCreated:(NSString *)keyStoreId kek:(NSData*)kek
{
    NSInteger errorCode = 0;
    BOOL created = NO;
    
    if (!keyStoreId || !kek)
    {
        errorCode = OMERR_KEY_IS_NIL;
    }
    
    if (!errorCode)
    {
       NSString *fileName = [self hashFileNameForKeystore:keyStoreId kek:kek];
        
        created = [[NSFileManager defaultManager] fileExistsAtPath:
                                                [self filePathForfile:fileName]];
    }
    
    return created;
}

- (BOOL)renameKeyStoreFile:(NSData*)kek withNewKek:(NSData*)newKek
                             storeId:(NSString *)storeId
{
    BOOL isRenamed = NO;
    
    NSString *oldFile = [self hashFileNameForKeystore:storeId kek:kek];
    NSString *oldFilepath = [self filePathForfile:oldFile];
    NSError *error = nil;
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:oldFilepath])
    {
        NSString *newFile = [self hashFileNameForKeystore:storeId kek:newKek];
        NSString *newFilePath = [self filePathForfile:newFile];

        isRenamed = [[NSFileManager defaultManager] moveItemAtPath:oldFilepath
                                                    toPath:newFilePath error:&error];
    }
    return isRenamed;
}

- (NSString *)filePathForfile:(NSString*)fileName
{
    NSString *directoryPath = [self keystoreDirectoryPath];
    NSString *filePath = [directoryPath stringByAppendingPathComponent:fileName];
    
    return filePath;
}

- (NSString*)hashFileNameForKeystore:(NSString *)keyStoreId kek:(NSData*)kek
{
    NSString *fileName = [keyStoreId stringByAppendingString:
                          [kek base64EncodedStringWithOptions:
                           NSDataBase64Encoding64CharacterLineLength]];
    
    NSError *error = nil;
    
   fileName = [OMCryptoService SHA256HashAndBase64EncodeData:[fileName dataUsingEncoding:NSUTF8StringEncoding] withSaltOfBitLength:0 outSalt:nil outError:&error];
    fileName = [fileName stringByReplacingOccurrencesOfString:@"/" withString:@""];
    return fileName;
}


- (NSString *)keystoreDirectoryPath
{
    @synchronized([NSFileManager class])
    {
        static NSString *secDirectory = nil;
        
        if (!secDirectory)
        {
            secDirectory = [[OMUtilities omaDirectoryPath]
                            stringByAppendingPathComponent:
                        [OMUtilities keystoreDirectoryName]];
            
            BOOL directoryCreated = NO;
            
            BOOL isExist =  [[NSFileManager defaultManager]
                             fileExistsAtPath:secDirectory
                            isDirectory:&directoryCreated];
            
            if (!isExist)
            {
                [[NSFileManager defaultManager] createDirectoryAtPath:secDirectory
                                        withIntermediateDirectories:YES
                                                    attributes:nil error:nil];
            }
            
        }
        
        return secDirectory;
    }
}
@end
