/* Copyright (c) 2011, 2016, Oracle and/or its affiliates.
 All rights reserved. */

/*
 NAME
 OMCredentialStore.h - Oracle Mobile Credential Store
 
 DESCRIPTION
 Wrapper class on top of KeyChainItemWrapper
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 shivap    13/01/16 - Creation
 */


#import <Foundation/Foundation.h>

@class OMCredential;

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



@end
