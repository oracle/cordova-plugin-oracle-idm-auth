/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>

@class OMCredential,OMAuthenticationContext;

@interface OMCredentialStore : NSObject
{
@private
    CFTypeRef defaultKeychainAccessible;
    
}

/**
 * @brief Returns the shared OMCredentialStore Object
 *
 * @return OMCredentialStore object
 */
+ (OMCredentialStore*)sharedCredentialStore;

/**
 * @brief sets the keychain data protection type
 *
 * @param keychain data ProtectionType
 */

- (void)setKeychainDataProtectionType:(CFTypeRef )keychainDataProtection;

/**
 * @brief Saves the credential
 *
 * @param credentail - OMCredentail Object to be saved
 *
 * @param key - Key of the KeyChainItem for savng
 *
 * @return Error object if there is error while saving credential otherwise nil
 */
- (NSError *)saveCredential:(OMCredential*)credential forKey:(NSString*)key;


/**
 * @brief Returns the credential
 *
 * @param key - Key of the KeyChainItem to be retrieved
 *
 * @return OMCredential object
 */
- (OMCredential *)getCredential:(NSString*)key;

/**
 * @brief Deletes an entry in KeyChainItem
 *
 * Delets all details stored in KeyChainItem against given key
 *
 * @param key - key using secure details are stored
 * @return NSError object if the KeyChainItem key passed is nil
 */
- (NSError *)deleteCredential:(NSString*)key;

/**
 * @brief sets the local authenticator instanceId
 *
 * @param instance id name
 */

- (void)setLocalAuthenticatorInstanceId:(NSString *)instanceId;

- (NSUInteger)deleteCredentialForProperties:(NSDictionary *)properties;

/**
 * @brief Saves the OMAuthenticationContext
 *
 * @param context - OMAuthenticationContext Object to be saved
 *
 * @param key - Key for saving for data
 *
 * @return Error object if there is error while saving credential otherwise nil
 */
- (NSError *)saveAuthenticationContext:(OMAuthenticationContext*)context
                                forKey:(NSString*)key;


/**
 * @brief Returns the OMAuthenticationContext
 *
 * @param key - Key of the data to be retrieved
 *
 * @return OMAuthenticationContext object
 */
- (OMAuthenticationContext *)retriveAuthenticationContext:(NSString*)key;

/**
 * @brief Deletes an entry in secure store
 *
 * Delets all details stored in secure store against given key
 *
 * @param key - key using secure details are stored
 * @return NSError object if the secure store key passed is nil
 */
- (NSError *)deleteAuthenticationContext:(NSString*)key;


@end
