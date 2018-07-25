/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMTouchIDAuthenticator.h"
#import <LocalAuthentication/LocalAuthentication.h>
#import "OMAuthenticator.h"
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

@interface OMTouchIDAuthenticator ()

@property (nonatomic, strong) NSData *kek;
@property (nonatomic, strong) OMKeyStore *keyStoreToBeCopied;

@end

@implementation OMTouchIDAuthenticator


- (id)initWithInstanceId:(NSString *)instanceId error:(NSError *__autoreleasing *)error
{
    self = [super initWithInstanceId:instanceId error:error];
    
    if (self)
    {
        self.instanceId = instanceId;
        _localizedFallbackTitle = NSLocalizedString(@"Enter Pin",@"Enter Pin");
        _localizedTouchIdUsingReason = NSLocalizedString
                                       (@"Unlock access to locked feature",
                                        @"Unlock access to locked feature");

        
        if (![OMTouchIDAuthenticator canEnableTouchID:error])
        {
            self = nil;
        }
    }
    
    return self;
}

+ (BOOL)canEnableTouchID:(NSError **)error
{
    BOOL success = NO;
    NSError *touchIdError = nil;

    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"8.0"))
    {
        success = [[[LAContext alloc] init] canEvaluatePolicy: LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&touchIdError];
    }
    // test if we can evaluate the policy, this test will tell us if Touch ID is available and enrolled
    
    if (touchIdError && error)
    {
        *error = touchIdError;
    }

    return success;
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
            
            NSString *salt = [OMCryptoService
                              generateSaltOfBitLength:PBKDF2_SALT_LENGTH
                              outError:error];
            
            //save the salt for later key generation during authentication
            [OMKeyChain setItem:salt forKey:[self saltKey] accessGroup:nil];
            
            
            NSString *passphrase = [authData authDataStr];
            
            _kek = [OMCryptoService generatePBKDF2EncryptionKeywithPassphrase:passphrase
                                                salt:salt
                                                hashAlgorithm:OMAlgorithmSSHA256
                                                iteration:PBKDF2_ITERATION_COUNT
                                                keySize:PBKDF2_KEY_LENGTH outError:error];
            
            OMKeyStore *keystore = [[OMKeyManager sharedManager]
                                    keyStore:self.instanceId
                                    kek:_kek error:error];
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
            
            [OMKeyChain setItem:_kek forKey:[self kekKey] accessGroup:nil
            dataAccessibleLevel:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
            
            self.secureStorage = [[OMSecureStorage alloc]
                                  initWithKeyStore:self.keyStore
                                keyId:nil error:error];
            NSData *touchValidationData = [OMCryptoService  randomDataOfLength:
                                           PIN_VALIDATION_DATA_LENGTH];
            
            [self.secureStorage saveDataForId:[self touchValidationKey] data:
                                                touchValidationData error:error];
            
            [OMKeyChain setItem:touchValidationData forKey:[self touchValidationKey]
                        accessGroup:nil];
            [[OMLocalAuthenticationManager sharedManager]
             addAuthKeyToList:[self touchValidationKey]];
            self.isAuthenticated = YES;
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


- (BOOL)authenticate:(OMAuthData *)authData error:(NSError **)error
{
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    LAContext *context = [[LAContext alloc] init];
    context.localizedFallbackTitle = self.localizedFallbackTitle;
    
    // Show the authentication UI with our reason string.
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:self.localizedTouchIdUsingReason
                      reply:^(BOOL success, NSError *authenticationError)
    {
        if (success)
        {
            self.isAuthenticated = YES;
            dispatch_semaphore_signal(semaphore);

        }
        else
        {
            
            if ([self needsPinAuthentication:authenticationError])
            {
                __block OMTouchIDAuthenticator *weekSelf = self;
                
                //give call back to app to to pin auth
                [self.delegate didSelectFallbackAuthentication:authenticationError
                                completionHandler:^(BOOL authenticated)
                {
                    
                    if (authenticated)
                    {
                        weekSelf.isAuthenticated = YES;
                    }
                    else
                    {
                        weekSelf.isAuthenticated = NO;
                    }
                    dispatch_semaphore_signal(semaphore);
                }];
            }
            else if (error)
            {
                *error = authenticationError;
            }

        }
        
    }];
    
    
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    
    if (self.isAuthenticated)
    {
        self.kek = [OMKeyChain itemForKey:[self kekKey] accessGroup:nil];
        
        OMKeyStore *keystore = [[OMKeyManager sharedManager]
                                keyStore:self.instanceId
                                kek:self.kek error:nil];
        if(!self.secureStorage)
        {
            self.secureStorage = [[OMSecureStorage alloc]
                                  initWithKeyStore:keystore
                                  keyId:nil error:error];
        }
        
    }

    return self.isAuthenticated;
}

- (void)updateAuthData:(OMAuthData *)currentAuthData
                        newAuthData:(OMAuthData *)newAuthData
                        error:(NSError **)error;
{
    NSUInteger errorCode= 0;
    
    if ((currentAuthData && [[currentAuthData data] length]) &&
        (newAuthData &&[[newAuthData data] length]))
    {
        
        NSString *newPin = [newAuthData authDataStr];
        NSString *salt = [OMKeyChain itemForKey:[self saltKey] accessGroup:nil];
        
        NSData *newKek = [OMCryptoService
                          generatePBKDF2EncryptionKeywithPassphrase:newPin
                          salt:salt
                          hashAlgorithm:OMAlgorithmSSHA256
                         iteration:PBKDF2_ITERATION_COUNT
                        keySize:PBKDF2_KEY_LENGTH outError:error];
       
        self.kek = [OMKeyChain itemForKey:[self kekKey] accessGroup:nil];
        
        [[OMKeyManager sharedManager] updateKeyStore:self.instanceId
                                kek:self.kek newKek:newKek error:error];
        
        if (!*error)
        {
            _kek = newKek;
            [OMKeyChain setItem:_kek forKey:[self kekKey] accessGroup:nil
            dataAccessibleLevel:kSecAttrAccessibleWhenUnlockedThisDeviceOnly];
            [self.secureStorage saveDataForId:[self pinLengthKey]
                                data:[NSNumber numberWithInteger:[newPin length]]
                                error:error];
            
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

- (void)deleteAuthData:(NSError **)error
{
    if (self.isAuthenticated)
    {
        [self.secureStorage deleteDataForId:[self pinLengthKey] error:error];
        [[OMKeyManager sharedManager] deleteKeyStore:self.instanceId
                                                 kek:self.kek error:error];
        [OMKeyChain deleteItemForKey:[self touchValidationKey] accessGroup:nil];
        [[OMLocalAuthenticationManager sharedManager]
         removeAuthKeyFromList:[self touchValidationKey]];
              
        [OMKeyChain deleteItemForKey:[self kekKey] accessGroup:nil];
        
        self.isAuthenticated = NO;
        self.kek = nil;
    }

    
}

- (BOOL)needsPinAuthentication:(NSError*)authenticationError
{
    BOOL isPinRequired = NO;
   
    if (authenticationError.code == LAErrorUserFallback ||
        authenticationError.code == LAErrorTouchIDNotAvailable ||
        authenticationError.code == LAErrorTouchIDNotEnrolled ||
        authenticationError.code == LAErrorUserCancel ||
        authenticationError.code == LAErrorTouchIDLockout)
    {
        isPinRequired = YES;
    }
    else if (authenticationError.code == -1 &&
             (NSOrderedSame == [[authenticationError domain] caseInsensitiveCompare:@"com.apple.LocalAuthentication"]))
    {
        isPinRequired = YES;
    }
    
    return isPinRequired;
}

#pragma mark -

- (void)inValidate;
{
    self.isAuthenticated = false;
    [[self keyStore] unloadKeys];
    
}

- (BOOL)isAuthDataSet
{
    BOOL isDataSet = NO;
    
    NSString *key = [self touchValidationKey];
    
    if (([[OMKeyChain itemForKey:key accessGroup:nil] length] > 0) &&
        [[OMLocalAuthenticationManager sharedManager] isAuthKeyEnabled:key])
    {
        isDataSet = YES;
    }
    
    return isDataSet;
}

#pragma mark -

- (NSString*)touchValidationKey
{
    return [NSString stringWithFormat:@"%@%@",self.instanceId,OM_Touch_VALIDATION_DATA_ID];
}

- (NSString*)saltKey
{
    return [NSString stringWithFormat:@"%@%@",self.instanceId,OM_PBKDF2_SALT_ID];
}

- (NSString*)kekKey
{
    return [NSString stringWithFormat:@"%@%@",self.instanceId,OM_KEK_ID];
}

- (OMKeyStore*)keyStore;
{
    return [[OMKeyManager sharedManager] keyStore:self.instanceId
                                              kek:self.kek error:nil];
}

- (NSInteger)authDataLength
{
    NSError *error = nil;
    
    NSNumber *pinLength = [self.secureStorage dataForId:[self pinLengthKey]
                                                  error:&error];
    return   (pinLength != nil) ? [pinLength integerValue] : -1 ;
}
- (NSString*)pinLengthKey
{
    return [NSString stringWithFormat:@"%@%@",self.instanceId,OM_PIN_LENGTH_KEY];
}

@end
