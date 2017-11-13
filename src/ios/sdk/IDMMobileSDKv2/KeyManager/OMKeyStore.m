/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMKeyStore.h"
#import "OMObject.h"
#import "OMErrorCodes.h"
#import "OMUtilities.h"
#import "OMCryptoService.h"
#import "OMDefinitions.h"
#import "OMKeyManager.h"
#import "OMDataSerializationHelper.h"

@interface OMKeyStore ()

@property (nonatomic, strong) NSString *storeId;
@property (nonatomic, strong) NSData *kek;
@property (nonatomic, strong) NSMutableDictionary *dek;
@end

@implementation OMKeyStore

- (id)initWithKeyStoreId:(NSString *)storeId kek:(NSData*)kek
{
    self = [super init];
    if (self)
    {
        _storeId = storeId;
        _kek = kek;
        _dek = [NSMutableDictionary dictionary];
    }
   
    return self;
}

- (NSData *)defaultKey
{
    return [self.dek valueForKey:OM_DEFAULT_KEY];
}

- (NSData *)getKey:(NSString *)keyId
{
    NSData *key = nil;

    if (keyId != nil)
    {
       key = [self.dek valueForKey:keyId];
    }

    return key;
}


- (void)createKeyForKeyId:(NSString*)keyId overWrite:(BOOL)overWrite
                    error:(NSError **)error
{
    if ([self.dek objectForKey:keyId] && !overWrite)
    {
        if (error)
        {
            *error = [OMObject createErrorWithCode:OMERR_KEY_ALREADY_FOUND];
        }
    }
    else
    {
        NSData *randomData = [OMCryptoService randomDataOfLength:DERIVED_KEY_LEN];
        [self.dek setObject:randomData forKey:keyId];
    }

}

- (void)createKey:(NSString*)keyId overwrite:(BOOL)overwrite
            error:(NSError **)error
{
    [self createKeyForKeyId:keyId overWrite:overwrite error:error];
    BOOL fileCreated = [self encryptAndStoreDek];
    
    if (!fileCreated && error)
    {
        *error = [OMObject createErrorWithCode:
                  OMERR_KEYSTORE_FILE_CREATION_FAILED];
    }
    
}

- (void)createKeys:(NSArray*)keysList overWrite:(BOOL)overWrite
             error:(NSError **)error
{
    
    for(NSString *key in keysList)
    {
        [self createKeyForKeyId:key overWrite:overWrite error:error];
    }
    
    [self encryptAndStoreDek];

}

- (void)deleteKey:(NSString*)keyId error:(NSError **)error
{
    if (keyId != nil && [self.dek valueForKey:keyId])
    {
        [self.dek removeObjectForKey:keyId];
        [self encryptAndStoreDek];
    }
    else if (error)
    {
        *error = [OMObject createErrorWithCode:OMERR_KEY_NOT_FOUND]; //to do
    }
    
}

- (void)deleteAllKeys:(NSError**)error
{
    [self.dek removeAllObjects];
    [self encryptAndStoreDek];
}

- (BOOL)isValidKek:(NSData*)kek
{
    BOOL valid = YES;
    
    if(kek == nil || self.kek == nil)
        valid = NO;
    
    if (![self.kek isEqualToData:kek])
    {
        valid = NO;
    }
    
    return valid;
}

- (void)updateKeyEncryptionKey:(NSData*)newKek;
{
    if (newKek && [newKek length])
    {
        self.kek = newKek;
        [self encryptAndStoreDek];
    }
}

- (BOOL)encryptAndStoreDek
{
    NSMutableDictionary *tempDict = [NSMutableDictionary dictionary];
    NSError *error;
    for (NSString *key in [self.dek allKeys])
    {
        tempDict[key] = [OMCryptoService encryptData:[self.dek valueForKey:key]
                                    withSymmetricKey:self.kek outError:&error];
    }
    
    NSLog(@"starts here");
    NSString *fileName = [[OMKeyManager sharedManager] hashFileNameForKeystore:
                          self.storeId kek:self.kek];
    
    NSString *path = [OMUtilities filePathForfile:fileName
                                inDirectory:[OMUtilities keystoreDirectoryName]
                                            error:&error];

   NSInteger attempts = 3;
    BOOL isStored = NO;
    
    do {
        
       isStored = [OMDataSerializationHelper serializeData:tempDict toFile:path];
        attempts --;
        NSLog(@"*****-serializeData== %d,",isStored);
    } while (!isStored && attempts > 0);

    return isStored;
}

- (void)copyKeysFromKeyStore:(OMKeyStore*)keyStore;
{
    
    for (NSString *key in [keyStore.dek allKeys])
    {
        self.dek[key] = [keyStore.dek valueForKey:key];
    }

    [self encryptAndStoreDek];
}
#pragma mark -
#pragma mark load and unload keys  Methods -

- (void)loadKeys
{
    NSString *fileName = [[OMKeyManager sharedManager] hashFileNameForKeystore:self.storeId kek:self.kek];
    NSString *path = [OMUtilities filePathForfile:fileName inDirectory:[OMUtilities keystoreDirectoryName] error:nil];

    NSDictionary *temp = [OMDataSerializationHelper deserializeDataFromFile:path];
    
    for (NSString *key in [temp allKeys])
    {
        self.dek[key] = [OMCryptoService decryptData:[temp valueForKey:key] withSymmetricKey:self.kek
                        outError:nil];
    }
}

- (void)unloadKeys
{
    self.dek = nil;
    self.kek = nil;
}

@end
