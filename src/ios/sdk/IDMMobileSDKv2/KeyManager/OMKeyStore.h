/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>

@class OMKeyStore;

@interface OMKeyStore : NSObject

- (id)initWithKeyStoreId:(NSString *)storeId kek:(NSData*)kek;
- (NSData *)defaultKey;
- (NSData *)getKey:(NSString *)keyId;
- (void)createKey:(NSString*)keyId overwrite:(BOOL)overwrite error:(NSError **)error;
- (BOOL)isValidKek:(NSData*)kek;
- (void)updateKeyEncryptionKey:(NSData*)newKek;

- (void)copyKeysFromKeyStore:(OMKeyStore*)keyStore;

- (void)unloadKeys;
- (void)loadKeys;

@end
