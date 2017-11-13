/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMSecureStorage.h"
#import "OMKeyStore.h"
#import "OMObject.h"
#import "OMErrorCodes.h"
#import "OMUtilities.h"
#import "OMDataSerializationHelper.h"
#import "OMCryptoService.h"
#import "OMDefinitions.h"
#import "OMCryptoService.h"

@interface OMSecureStorage ()

@property (nonatomic, weak) OMKeyStore *keyStore;
@property (nonatomic, strong) NSString *keyId;

@end

@implementation OMSecureStorage


- (id)initWithKeyStore:(OMKeyStore*)keyStore keyId:(NSString*)keyId
                 error:(NSError**)error;
{
    self = [super init];
    
    if (self)
    {
        
        _keyId = keyId;

        if (keyStore)
        {
            _keyStore = keyStore;
        }
        else
        {
            if (error)
                *error = [OMObject createErrorWithCode:OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
            self = nil;
        }
       
       
    }
    
    return self;
}

- (id)dataForId:(NSString *)dataId error:(NSError **)error
{
    NSData *data = nil;
    
    if (dataId)
    {
        NSData *encKey = nil;
        
        if (_keyId == nil)
        {
            encKey = [self.keyStore defaultKey];

        }
        else
        {
            encKey = [self.keyStore getKey:self.keyId];

        }

        NSString *filePath =[self filePathForDataId:[self fileNameForDataId:dataId]];
        NSData *fileData = [self dataForFilePath:filePath error:error];
        
        if (fileData)
        {
            
           NSData *decryptedData = [OMCryptoService decryptData:fileData withSymmetricKey:encKey
                                                       outError:error];
            data = [OMDataSerializationHelper deserializeData:decryptedData];

        }
        
    }
    else if(error)
    {
        *error = [OMObject
                  createErrorWithCode:
                  OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
    }
    
    return data;
}

- (BOOL)saveDataForId:(NSString *)dataId data:(id)data error:(NSError **)error
{
    BOOL isDataSaved = NO;
    
        if (dataId && data)
        {
            NSData *encKey = nil;
            
            if (_keyId == nil)
            {
                encKey = [self.keyStore defaultKey];
                
            }
            else
            {
                encKey = [self.keyStore getKey:self.keyId];
                
            }
            
            NSString *filePath =[self filePathForDataId:[self fileNameForDataId:dataId]];
            [self addMappingForDataId:dataId];
            NSData *archivedData = [OMDataSerializationHelper serializeData:data];
            NSData *encryptedData = [OMCryptoService encryptData:archivedData withSymmetricKey:encKey
                                                                outError:error];
            isDataSaved = [self saveData:encryptedData toFile:filePath error:error];
            
        }
        else if(error)
        {
            *error = [OMObject
                        createErrorWithCode:
                        OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
        }

    return isDataSaved;
}

- (BOOL)deleteDataForId:(NSString *)dataId error:(NSError **)error
{
    BOOL isFileRemoved = NO;
    
    if (dataId )
    {
        
        NSString *filePath =[self filePathForDataId:[self fileNameForDataId:dataId]];
        
        isFileRemoved = [[NSFileManager defaultManager] removeItemAtPath:filePath error:error];
        isFileRemoved?[self removeMappingForDataId:dataId]:nil;
        
    }
    else if(error)
    {
        *error = [OMObject
                    createErrorWithCode:
                    OMERR_INPUT_TEXT_CANNOT_BE_EMPTY];
    }
    
    return isFileRemoved;
}

#pragma mark -
#pragma mark Internal Methods -

- (BOOL)saveData:(NSData *)data toFile:(NSString *)filePath error:(NSError **)error
{
    return [data writeToFile:filePath options:NSDataWritingAtomic error:error];
}

- (NSData *)dataForFilePath:(NSString *)fliePath error:(NSError **)error
{
    NSData *fileContent = nil;
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:fliePath])
    {
       fileContent = [NSData dataWithContentsOfFile:fliePath options:NSDataReadingMappedIfSafe error:error];
    }
    else
    {
        if (error)
        {
            *error = [OMObject
                      createErrorWithCode:
                      OMERR_FILE_NOT_FOUND];

        }
    }
    
 return fileContent;
}

- (NSString *)fileNameForDataId:(NSString *)dataId
{
    // The file name should conatin less that 255 charachters, else the file
    // will not be stored on the disk.
    return [[OMCryptoService MD5HashAndBase64EncodeData:
      [dataId dataUsingEncoding:NSUTF8StringEncoding]
                             withSaltOfBitLength:0
                                         outSalt:nil
                                        outError:nil]
     stringByReplacingOccurrencesOfString:@"/"
     withString:@""];
}

- (NSString *)filePathForDataId:(NSString*)dataId
{
    NSString *directoryPath = [self secureDirectoryPath];
    NSString *filePath = [directoryPath stringByAppendingPathComponent:dataId];

    return filePath;
}

- (NSString *)secureDirectoryPath
{
    @synchronized([NSFileManager class])
    {
        static NSString *secDirectory = nil;
        
        if (!secDirectory)
        {
            secDirectory = [[OMUtilities omaDirectoryPath] stringByAppendingPathComponent:
                                                        [OMUtilities secureDirectoryName]];
            
            BOOL directoryCreated = NO;
            
            BOOL isExist =  [[NSFileManager defaultManager] fileExistsAtPath:secDirectory
                                                                 isDirectory:&directoryCreated];
            
            if (!isExist)
            {
                [[NSFileManager defaultManager] createDirectoryAtPath:secDirectory withIntermediateDirectories:NO attributes:nil error:nil];
            }
            
        }
        
        return secDirectory;
    }
}

- (NSString*)stringToBase64:(NSString*)fromString
{
    NSData *plainData = [fromString dataUsingEncoding:NSUnicodeStringEncoding];
    NSString *base64String;

    base64String = [plainData base64EncodedStringWithOptions:kNilOptions];  // iOS 7+
    
    return base64String;
}

-(void)addMappingForDataId:(NSString *)dataId
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableArray *array = [defaults objectForKey:OM_CRED_FILE_LIST];
    if (!array)
    {
        array = [NSMutableArray array];
    }
    else
    {
        array = [NSMutableArray arrayWithArray:array];
    }
    [array addObject:dataId];
    [defaults setObject:array forKey:OM_CRED_FILE_LIST];
    [defaults synchronize];
}

-(void)removeMappingForDataId:(NSString *)dataId
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableArray *array = [defaults objectForKey:OM_CRED_FILE_LIST];
    if (!array.count)
    {
        return;
    }
    else
    {
        array = [NSMutableArray arrayWithArray:array];
    }
    [array removeObject:dataId];
    [defaults setObject:array forKey:OM_CRED_FILE_LIST];
    [defaults synchronize];
}
@end
