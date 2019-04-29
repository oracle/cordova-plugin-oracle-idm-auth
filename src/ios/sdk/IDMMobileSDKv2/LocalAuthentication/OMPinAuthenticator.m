/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMPinAuthenticator.h"
#import "OMAuthData.h"
#import "OMCryptoService.h"
#import "OMDefinitions.h"
#import "OMKeyStore.h"
#import "OMSecureStorage.h"
#import "OMKeyManager.h"
#import "OMKeyChain.h"
#import "OMErrorCodes.h"
#import "OMObject.h"
#import "OMDataSerializationHelper.h"
#import "OMLocalAuthenticationManager.h"

@interface OMPinAuthenticator ()

@property (nonatomic, strong) NSData *kek;
@property (nonatomic, strong) OMKeyStore *keyStoreToBeCopied;

@end

@implementation OMPinAuthenticator

- (id)initWithInstanceId:(NSString *)instanceId
                   error:(NSError *__autoreleasing *)error
{
    self = [super init];
    
    if (self)
    {
        self.instanceId = instanceId;
    }
    
    return self;
}

- (void)copyKeysFromKeyStore:(OMKeyStore*)keyStore
{
 
    if (nil != keyStore)
    {
        self.keyStoreToBeCopied = keyStore;
    }
    
}

- (void)setAuthData:(OMAuthData *)authData error:(NSError **)error
{
    NSUInteger errorCode= 0;
    
    if (authData && [[authData data] length])
    {
        if (![self isAuthDataSet])
        {
            
            NSString *salt = [OMCryptoService generateSaltOfBitLength:PBKDF2_SALT_LENGTH
                                                             outError:error];
            
            //save the salt for later key generation during authentication
            [OMKeyChain setItem:salt forKey:[self saltKey] accessGroup:nil];
            
            
            NSString *passphrase = [authData authDataStr];
            
            _kek = [OMCryptoService generatePBKDF2EncryptionKeywithPassphrase:passphrase
                                    salt:salt hashAlgorithm:OMAlgorithmSSHA256
                                    iteration:PBKDF2_ITERATION_COUNT
                                    keySize:PBKDF2_KEY_LENGTH outError:error];
            
            OMKeyStore *keystore = [[OMKeyManager sharedManager]
                                    keyStore:self.instanceId kek:_kek error:error];
            if (!keystore)
            {
               keystore =[[OMKeyManager sharedManager] createKeyStore:self.instanceId
                            kek:self.kek overWrite:YES error:error];
                
                if (self.keyStoreToBeCopied != nil)
                {
                    [keystore copyKeysFromKeyStore:self.keyStoreToBeCopied];
                    self.keyStoreToBeCopied = nil;
                }

                if (nil == [keystore defaultKey])
                {
                    [keystore createKey:OM_DEFAULT_KEY overwrite:NO error:error];
                }

            }
            
            self.keyStore = keystore;
            
            

            self.secureStorage = [[OMSecureStorage alloc] initWithKeyStore:
                                  self.keyStore keyId:nil error:error];
            NSData *pinValidationData = [OMCryptoService  randomDataOfLength:
                                                    PIN_VALIDATION_DATA_LENGTH];
            
            [self.secureStorage saveDataForId:[self pinValidationKey]
                                         data:pinValidationData error:error];
            
            [OMKeyChain setItem:pinValidationData forKey:[self pinValidationKey]
                    accessGroup:nil];
            [[OMLocalAuthenticationManager sharedManager]
             addAuthKeyToList:[self pinValidationKey]];
            [self setIsAuthenticated:YES];
            
            [self.secureStorage saveDataForId:[self pinLengthKey]
                                data:[NSNumber numberWithInteger:[passphrase length]]
                                        error:error];
        }
        else
        {
            errorCode = OMERR_AUTHDATA_ALREADY_SET;
        }
    }
    else
    {
        errorCode = OMERR_INPUT_TEXT_CANNOT_BE_EMPTY;

    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }
}

- (void)updateAuthData:(OMAuthData *)currentAuthData
           newAuthData:(OMAuthData *)newAuthData
                        error:(NSError **)error;
{
    NSUInteger errorCode= 0;
    
    if ((currentAuthData && [[currentAuthData data] length]) &&
        (newAuthData &&[[newAuthData data] length]))
    {

        if ([self authenticate:currentAuthData error:error])
        {
            NSString *newPin = [newAuthData authDataStr];
            NSString *salt = [OMKeyChain itemForKey:[self saltKey]
                                        accessGroup:nil];
            NSData *newKek = [OMCryptoService
                              generatePBKDF2EncryptionKeywithPassphrase:newPin
                              salt:salt hashAlgorithm:OMAlgorithmSSHA256
                              iteration:PBKDF2_ITERATION_COUNT
                              keySize:PBKDF2_KEY_LENGTH outError:error];
            
            OMKeyStore *currentKeyStrore = [[OMKeyManager sharedManager]
                                            updateKeyStore:self.instanceId
                                        kek:self.kek newKek:newKek error:error];

            if (currentKeyStrore)
            {
            _kek = newKek;
            [self.secureStorage saveDataForId:[self pinLengthKey]
                                    data:[NSNumber numberWithInteger:[newPin length]]
                                    error:error];
            }
        }
        else
        {
            errorCode = OMERR_INCORRECT_CURRENT_AUTHDATA;
        }
    }
    else
    {
        errorCode = OMERR_INCORRECT_CURRENT_AUTHDATA;

    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }

}

- (void)deleteAuthData:(NSError **)error
{
    if (self.isAuthenticated)
    {
        [self.secureStorage deleteDataForId:[self pinLengthKey] error:error];
        [[OMKeyManager sharedManager] deleteKeyStore:self.instanceId
                                                 kek:self.kek error:error];
        [OMKeyChain deleteItemForKey:[self pinValidationKey] accessGroup:nil];
        [[OMLocalAuthenticationManager sharedManager]
                removeAuthKeyFromList:[self pinValidationKey]];
        self.isAuthenticated = NO;
        self.kek = nil;
    }
    
}
- (BOOL)authenticate:(OMAuthData*)authData error:(NSError**)error
{
    NSUInteger errorCode= 0;
    error = nil;
    
    BOOL authenticated = NO;
    
    if (authData && [[authData data] length])
    {
        if ([self isAuthDataSet])
        {
            NSString *salt = [OMKeyChain itemForKey:[self saltKey]
                                        accessGroup:nil];
            NSString *currentPin = [authData authDataStr];
            
            NSData *newKek = [OMCryptoService
                             generatePBKDF2EncryptionKeywithPassphrase:currentPin
                             salt:salt hashAlgorithm:OMAlgorithmSSHA256
                             iteration:PBKDF2_ITERATION_COUNT
                             keySize:PBKDF2_KEY_LENGTH outError:error];
            
            OMKeyStore *keystore = [[OMKeyManager sharedManager] keyStore:
                                    self.instanceId kek:newKek error:nil];
            
            OMSecureStorage *secureStore = [[OMSecureStorage alloc]
                                            initWithKeyStore:keystore
                                                keyId:nil error:error];
            NSData *validationData = [secureStore dataForId:
                                      [self pinValidationKey] error:error];

            NSData *previousData = [OMKeyChain itemForKey:[self pinValidationKey]
                                               accessGroup:nil];
            
            

            if ([validationData isEqualToData:previousData])
            {
                self.isAuthenticated = YES;
                authenticated = YES;
                self.secureStorage = secureStore;
                self.kek = newKek;
            }
            
        }else
        {
            errorCode = OMERR_AUTHDATA_NOT_SET;
        }
    }
    else
    {
        errorCode = OMERR_INPUT_TEXT_CANNOT_BE_EMPTY;
        
    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }

    return authenticated;
}

- (void)inValidate;
{
    self.isAuthenticated = false;
    [[self keyStore] unloadKeys];

}

- (BOOL)isAuthDataSet
{
    BOOL isDataSet = NO;
  
    NSString *pinKey = [self pinValidationKey];
    
    if (([[OMKeyChain itemForKey:pinKey accessGroup:nil] length] > 0) &&
        [[OMLocalAuthenticationManager sharedManager] isAuthKeyEnabled:pinKey])
    {
        isDataSet = YES;
    }
    
    return isDataSet;
}

- (NSInteger)authDataLength
{
    NSError *error = nil;
    
    NSNumber *pinLength = [self.secureStorage dataForId:[self pinLengthKey]
                                                  error:&error];
    return   (pinLength != nil) ? [pinLength integerValue] : -1 ;
}

#pragma mark -

- (NSString*)pinValidationKey
{
    return [NSString stringWithFormat:@"%@%@",self.instanceId, OM_PIN_VALIDATION_DATA_ID];
}

- (NSString*)saltKey
{
    return [NSString stringWithFormat:@"%@%@",self.instanceId,OM_PBKDF2_SALT_ID];
}

- (NSString*)pinLengthKey
{
    return [NSString stringWithFormat:@"%@%@",self.instanceId, OM_PIN_LENGTH_KEY];
}

- (OMKeyStore*)keyStore;
{
    return [[OMKeyManager sharedManager] keyStore:self.instanceId kek:self.kek error:nil];
}
@end
