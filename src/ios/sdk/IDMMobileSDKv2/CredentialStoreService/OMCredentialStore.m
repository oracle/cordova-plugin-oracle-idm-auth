/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMCredentialStore.h"
#import "OMCredential.h"
#import "KeychainItemWrapper.h"
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMJSONUtlity.h"
#import "OMCryptoService.h"
#import "OMErrorCodes.h"
#import "OMAuthenticator.h"
#import "OMLocalAuthenticationManager.h"
#import "OMKeyStore.h"
#import "OMSecureStorage.h"
#import "OMDefaultAuthenticator.h"

NSString *defaultHeadlessAuthenticator = @"authenticator_default_headless";

@interface  OMCredentialStore()

@property (nonatomic, copy) NSString *localAuthenticatorInstanceId;
@property (nonatomic, strong) OMAuthenticator *localAuthenticator;
@end

@implementation OMCredentialStore

+ (OMCredentialStore*)sharedCredentialStore
{
    static OMCredentialStore *kSharedStore = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        kSharedStore = [[self alloc] init];
    });
    
    return kSharedStore;
}

- (id)init
{
    if (self = [super init])
    {
        
        defaultKeychainAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    }
    return self;
}

- (void)setLocalAuthenticatorInstanceId:(NSString *)instanceId
{
    if (nil != instanceId)
    {
        _localAuthenticatorInstanceId = instanceId;
        _localAuthenticator = nil;
    }
    
}
- (void)setKeychainDataProtectionType:(CFTypeRef )keychainDataProtection
{
    
    if (nil != keychainDataProtection)
    {
        defaultKeychainAccessible = keychainDataProtection;
        
    }
}

- (NSError *)saveCredential:(OMCredential*)credential forKey:(NSString*)key;
{
    
    if (key == nil || [key length] == 0)
        return [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
      
    NSError *error = nil;
    
    if ([self.localAuthenticator isAuthenticated])
    {
        [self.localAuthenticator.secureStorage saveDataForId:key data:credential
                                                       error:&error];
    }
    else
    {
        OMDebugLog(@"save credential failed");
        error = [OMObject createErrorWithCode:OMERR_LOCAL_AUTH_NOT_AUTHENTICATED];
    }
    return error;
    
}



////////////////////////////////////////////////////////////////////////////////
// Retrieves the username, password, and tenant name for a given key
////////////////////////////////////////////////////////////////////////////////
- (OMCredential *)getCredential:(NSString*)key
{
    if (key == nil || [key length] == 0)
        return nil;
    
    NSError *error = nil;
    OMCredential *cred = nil;
    
    if ([self.localAuthenticator isAuthenticated])
    {
        cred = [self.localAuthenticator.secureStorage dataForId:key error:&error];
    }
    else
    {
        OMDebugLog(@"getCredential credential failed");

    }
    
    return cred;
}


////////////////////////////////////////////////////////////////////////////////
// Adds a property to KeyChainItem against a given key
////////////////////////////////////////////////////////////////////////////////
- (NSError *)addProperty:(NSString*)key
            propertyName:(id)propertyName
           propertyValue:(id)propertyValue
{
    if (key == nil || [key length] == 0)
        return [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
    // [self checkAndSetAccessibilityForKey:key];
    KeychainItemWrapper *keychain = [[KeychainItemWrapper alloc]
                                     initWithIdentifier:key accessGroup:nil];
    [keychain setObject:propertyValue forKey:propertyName];
    return nil;
}


////////////////////////////////////////////////////////////////////////////////
// Modifies a property in KeyChainItem for a given key
////////////////////////////////////////////////////////////////////////////////
- (NSError *)modifyProperty:(NSString*)key
               propertyName:(id)propertyName
              propertyValue:(id)propertyValue
{
    return [self addProperty:key propertyName:propertyName
               propertyValue:propertyValue];
}

////////////////////////////////////////////////////////////////////////////////
// Deletes a property in KeyChainItem
////////////////////////////////////////////////////////////////////////////////
- (NSError *)deleteProperty:(NSString*)key
               propertyName:(id)propertyName
{
    if (key == nil || [key length] == 0)
        return [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
    KeychainItemWrapper *keychain = [[KeychainItemWrapper alloc]
                                     initWithIdentifier:key accessGroup:nil];
    [keychain setObject:(id)@"" forKey:propertyName];
    return nil;
}

////////////////////////////////////////////////////////////////////////////////
// Gets a property to KeyChainItem
////////////////////////////////////////////////////////////////////////////////
- (id)getProperty:(NSString*)key
     propertyName:(id)propertyName
{
    if (key == nil || [key length] == 0)
        return nil;
    KeychainItemWrapper *keychain = [[KeychainItemWrapper alloc]
                                     initWithIdentifier:key accessGroup:nil];
    id returnObj = (id)[keychain objectForKey:(id)propertyName];
    return returnObj;
}

////////////////////////////////////////////////////////////////////////////////
// Modify protection level of an entry
// Wrt to issue in iOS 8,persisted values are recorded and deleted from
// keychain and readded.
////////////////////////////////////////////////////////////////////////////////
- (NSError *)modifyProperty:(NSString*)key
                 protection:(NSString*)protection
{
    if (key == nil || [key length] == 0)
        return [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
    KeychainItemWrapper *keychain = [[KeychainItemWrapper alloc]
                                     initWithIdentifier:key accessGroup:nil];
    
    // verify presence before update
    id returnObj = (id)[keychain objectForKey:(id)kSecAttrAccessible];
    if (nil == returnObj)
    {
        return [OMObject createErrorWithCode:OMERR_KEYCHAIN_ITEM_NOT_FOUND];
    }
    
    id currObj = nil; //[OMCredentialStore protectionInternalRepresentation:protection];
    if (nil == currObj)
    {
        return [OMObject createErrorWithCode:OMERR_INVALID_KEYCHAIN_DATA_PROTECTION_LEVEL];
    }
    
    if (![returnObj isEqual:currObj])
    {
        //Record values
        id username = [keychain objectForKey:(__bridge NSString *)kSecAttrAccount];
        id userpwd = [keychain objectForKey:(__bridge NSString *)kSecValueData];
        id servicename = [keychain objectForKey:(__bridge NSString *)kSecAttrService];
        id comment = [keychain objectForKey:(__bridge NSString *)kSecAttrComment];
        id label = [keychain objectForKey:(__bridge NSString *)kSecAttrLabel];
        id desc = [keychain objectForKey:(__bridge NSString *)kSecAttrDescription];
        
        //clear existing keychain item.
        [keychain resetKeychainItem];
        
        //set recorded values
        KeychainItemWrapper *tempKeychain = [[KeychainItemWrapper alloc]
                                             initWithIdentifier:key
                                             accessGroup:nil];
        [tempKeychain setObject:currObj forKey:(__bridge NSString *)kSecAttrAccessible];
        [tempKeychain setObject:(id)username forKey:(__bridge NSString *)kSecAttrAccount];
        [tempKeychain setObject:userpwd forKey:(__bridge NSString *)kSecValueData];
        [tempKeychain setObject:(id)servicename forKey:(id)kSecAttrService];
        [tempKeychain setObject:(id)comment forKey:(__bridge NSString *)kSecAttrComment];
        [tempKeychain setObject:(id)label forKey:(__bridge NSString *)kSecAttrLabel];
        [tempKeychain setObject:(id)desc forKey:(__bridge NSString *)kSecAttrDescription];
    }
    return nil;
}

+ (NSString *)protectionSDKRepresentation:(NSString *)protection
{
    NSString *sdkRepresentatiom = nil;
    
    // internal representation
    if (nil == protection)
    {
        // default
        sdkRepresentatiom = (__bridge NSString *)kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    }
    else if (NSOrderedSame == [protection caseInsensitiveCompare:
                               (__bridge NSString *)kSecAttrAccessibleWhenUnlocked])
    {
        sdkRepresentatiom = OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED;
        
    }
    else if (NSOrderedSame == [protection caseInsensitiveCompare:
                               (__bridge NSString *)kSecAttrAccessibleAfterFirstUnlock])
    {
        sdkRepresentatiom = OM_KEYCHAIN_DATA_ACCESSIBLE_AFTER_FIRST_UNLOCK;
        
    }
    else if (NSOrderedSame == [protection caseInsensitiveCompare:
                               (__bridge NSString *) kSecAttrAccessibleAlways])
    {
        sdkRepresentatiom = OM_KEYCHAIN_DATA_ACCESSIBLE_ALWAYS;
        
    }
    else if (NSOrderedSame == [protection caseInsensitiveCompare:
                               (__bridge NSString *)kSecAttrAccessibleWhenUnlockedThisDeviceOnly])
    {
        // default
        sdkRepresentatiom = OM_KEYCHAIN_DATA_ACCESSIBLE_WHEN_UNLOCKED_THIS_DEVICE_ONLY;
        
    }
    else if (NSOrderedSame == [protection caseInsensitiveCompare:
                               (__bridge NSString *)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly])
    {
        sdkRepresentatiom = OM_KEYCHAIN_DATA_ACCESSIBLE_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY;
        
    }
    else if (NSOrderedSame == [protection caseInsensitiveCompare:
                               (__bridge NSString *)kSecAttrAccessibleAlwaysThisDeviceOnly])
    {
        sdkRepresentatiom = OM_KEYCHAIN_DATA_ACCESSIBLE_ALWAYS_THIS_DEVICE_ONLY;
        
    }
    return sdkRepresentatiom;
}

////////////////////////////////////////////////////////////////////////////////
// It is due to issue specific to iOS8,Where modifying kSecAttrAccessible leads
// to crash with keyhainitemwrapper class.This will set to higher priority
// valued accessibilty.
////////////////////////////////////////////////////////////////////////////////
- (void)checkAndSetAccessibilityForKey:(NSString *)key
{
    KeychainItemWrapper *keychain = [[KeychainItemWrapper alloc]
                                     initWithIdentifier:key accessGroup:nil];
    id currAccessible = [keychain objectForKey:(__bridge NSString *)kSecAttrAccessible];
    
    //Modify Only if it is already existing.
    if (currAccessible)
    {
        NSString *sdkRepresentation = [OMCredentialStore
                                       protectionSDKRepresentation:
                                       (__bridge NSString *)defaultKeychainAccessible];
        
        [self modifyProperty:key protection:sdkRepresentation];
    }
    else //Set to default
    {
        [keychain setObject: (__bridge NSString *)defaultKeychainAccessible forKey:(__bridge NSString *)kSecAttrAccessible];
    }
}

////////////////////////////////////////////////////////////////////////////////
// deletes credential from KeyChainItem. There is no delete operation. It just
// sets username and password to null value
////////////////////////////////////////////////////////////////////////////////
- (NSError *)deleteCredential:(NSString*)key
{
    if (key == nil || [key length] == 0)
        return [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
    
    NSError *error = nil;
    
    if ([self.localAuthenticator isAuthenticated])
    {
        [self.localAuthenticator.secureStorage deleteDataForId:key error:&error];
    }
    return error;
}

 ///////////////////////////////////////////////////////////////////////////////
 // Encrypt a string with AES128
 ///////////////////////////////////////////////////////////////////////////////
- (NSString *) encryptString:(NSString *) string outError:(NSError **) error
{
    NSData *key = [self symmetricEncryptionKey];
    
    if (!key)
    {
        return nil;
    }
    NSString *protectedString = [OMCryptoService encryptData:[string
                                                              dataUsingEncoding:NSUTF8StringEncoding]
                                            withSymmetricKey:key
                                        initializationVector:nil
                                                   algorithm:OMAlgorithmAES128
                                                     padding:OMPaddingPKCS7
                                                        mode:OMModeCBC
                                          base64EncodeOutput:YES
                               prefixOutputWithAlgorithmName:YES
                                                    outError:error];
    return protectedString;
}
                             
 ///////////////////////////////////////////////////////////////////////////////
 // Decrypt an AES128 encrypted string
 ///////////////////////////////////////////////////////////////////////////////
 - (NSString *) decryptString:(NSString *) string outError:(NSError **) error
{
    NSData *key = [self symmetricEncryptionKey];
    
    if (!key || [string length] == 0)
    {
        return nil;
    }
    NSUInteger algorithmLength = [OM_PROP_CRYPTO_AES length] + 2;
    NSData *decryptedData = [OMCryptoService decryptData:[string
                                                          substringFromIndex:
                                                          algorithmLength]
                                        withSymmetricKey:key
                                    initializationVector:nil
                                               algorithm:OMAlgorithmAES128
                                                 padding:OMPaddingPKCS7
                                                    mode:OMModeCBC
                        isInputPrefixedWithAlgorithmName:NO
                                    isInputBase64Encoded:YES
                                                outError:error];
    if (!decryptedData)
    {
        return nil;
    }
    NSString *decryptedString = [[NSString alloc]
                                 initWithData:decryptedData
                                 encoding:NSUTF8StringEncoding];
    return decryptedString;
}
                             
 // Symmetric encyption key:
- (NSData *)symmetricEncryptionKey
{
    NSError *error = nil;
    NSString *uuid =  nil;
    //simulator returns a new vendor identifier on every launch,
    // which results in a different symmetric key and the decryption of already
    // stored data fails
#if TARGET_IPHONE_SIMULATOR
    uuid = @"04A9A9FE-9816-49AF-B20D-EC0526CE080F";
#else
    uuid = [[UIDevice currentDevice] identifierForVendor].UUIDString;
#endif
    NSData *key = [OMCryptoService SHA256HashData:[uuid
                                                   dataUsingEncoding:
                                                   NSUTF8StringEncoding]
                                         outError:&error];
    if (!error)
        return key;
    else
        return nil;
}

#pragma mark -
#pragma mark - Secure storage related
// secure

- (OMAuthenticator*)currentLocalAuthenticator
{
    if (nil != self.localAuthenticatorInstanceId)
    {
       self.localAuthenticator = [[OMLocalAuthenticationManager sharedManager] authenticatorForInstanceId:self.localAuthenticatorInstanceId error:nil];
    }
    else
    {
        [self createDefaultAutenticator];
        [self.localAuthenticator authenticate:nil error:nil];
    }
    
    return self.localAuthenticator;
}

- (OMAuthenticator *)localAuthenticator
{
    if (nil == _localAuthenticator)
    {
       _localAuthenticator = [self currentLocalAuthenticator];
    }
    
    return _localAuthenticator;
}

- (void)createDefaultAutenticator
{
    NSError *error = nil;
    
    id auth = [[OMLocalAuthenticationManager sharedManager] authenticatorForInstanceId:
               [self headlessDefaultAuthenticatorId] error:&error];

    if (auth && [auth isKindOfClass:[OMDefaultAuthenticator class]])
    {
        self.localAuthenticator = auth;
    }
    else
    {
        error = nil;
        
        if (![[OMLocalAuthenticationManager sharedManager] isAuthenticatorRegistered:defaultHeadlessAuthenticator])
        {
            [[OMLocalAuthenticationManager sharedManager] registerAuthenticator:
             defaultHeadlessAuthenticator className:NSStringFromClass([OMDefaultAuthenticator class])
                                                                          error:&error];
        }
        
        if (!error)
        {
            BOOL isEnabled = [[OMLocalAuthenticationManager sharedManager]
                              enableAuthentication:defaultHeadlessAuthenticator
                              instanceId:[self headlessDefaultAuthenticatorId]
                                                                error:&error];
            
            if (isEnabled)
            {
                self.localAuthenticator = [[OMLocalAuthenticationManager sharedManager] authenticatorForInstanceId:[self headlessDefaultAuthenticatorId]
                                                                error:&error];
                
            }
        }

    }

}

- (NSString *)headlessDefaultAuthenticatorId
{
    
    return [NSString stringWithFormat:@"%@.headless",[[NSBundle mainBundle]
                                                      bundleIdentifier]];
}

- (NSUInteger)deleteCredentialForProperties:(NSDictionary *)properties
{
    NSUInteger deletedCreds = 0;
    NSString *loginURL = [properties valueForKey:OM_PROP_LOGIN_URL];
    NSString *appName = [properties valueForKey:OM_PROP_APPNAME];
    NSString *idDomain = [properties valueForKey:OM_PROP_IDENTITY_DOMAIN_NAME];
    NSString *offlineAuthKey = nil;
    NSString *authKey = [properties valueForKey:OM_PROP_AUTH_KEY];
    
    if ([loginURL length])
    {
        NSString *credentialKey = (authKey != nil)?authKey:appName;
        
        if (credentialKey)
        {
            offlineAuthKey = [NSString stringWithFormat:@"%@_%@",
                              loginURL,credentialKey];
        }
    }
    if (![offlineAuthKey length])
    {
        return -1;
    }
    offlineAuthKey = [NSString
                      stringWithFormat:@"%@_offlineAuth",offlineAuthKey];

    if ([idDomain length])
    {
        offlineAuthKey = [NSString
                          stringWithFormat:@"%@_%@::",offlineAuthKey,
                          [idDomain length]?idDomain:@""];
    }

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSArray *keys = [defaults objectForKey:OM_CRED_FILE_LIST];
    if (keys.count)
    {
        OMCredentialStore *credStore = [OMCredentialStore
                                        sharedCredentialStore];
        for (NSString *key in keys)
        {
            if ([key hasPrefix:offlineAuthKey])
            {
                [credStore deleteCredential:key]?false:deletedCreds++;
            }
        }
    }
    return deletedCreds;
}

- (NSError *)saveAuthenticationContext:(OMAuthenticationContext*)context
                                forKey:(NSString*)key
{
    if (key == nil || [key length] == 0)
        return [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
    
    NSError *error = nil;
    
    if ([self.localAuthenticator isAuthenticated])
    {
        [self.localAuthenticator.secureStorage saveDataForId:key data:context
                                                       error:&error];
    }
    else
    {
        OMDebugLog(@"save AuthenticationContext failed");
        error = [OMObject createErrorWithCode:OMERR_LOCAL_AUTH_NOT_AUTHENTICATED];
    }
    return error;

}

- (OMAuthenticationContext *)retriveAuthenticationContext:(NSString*)key
{
    if (key == nil || [key length] == 0)
        return nil;
    
    NSError *error = nil;
    OMAuthenticationContext *context = nil;
    
    if ([self.localAuthenticator isAuthenticated])
    {
        context = [self.localAuthenticator.secureStorage dataForId:key error:&error];
    }
    else
    {
        OMDebugLog(@"getCredential credential failed");
        
    }
    
    return context;

}
- (NSError *)deleteAuthenticationContext:(NSString*)key;
{
    if (key == nil || [key length] == 0)
        return [OMObject createErrorWithCode:OMERR_KEY_IS_NIL];
    
    NSError *error = nil;
    
    if ([self.localAuthenticator isAuthenticated])
    {
        [self.localAuthenticator.secureStorage deleteDataForId:key error:&error];
    }
    return error;

}

@end
