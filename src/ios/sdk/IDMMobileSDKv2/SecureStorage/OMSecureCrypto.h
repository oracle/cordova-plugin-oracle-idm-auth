/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@class OMKeyStore;

@interface OMSecureCrypto : NSObject

- (id)initWithKeyStore:(OMKeyStore*)keyStore error:(NSError**)error;

- (NSData*)encryptData:(id)data withKey:(NSString*)encryptKey
                 error:(NSError**)error;
- (id)decryptData:(NSData*)data withKey:(NSString*)encryptKey
                 error:(NSError**)error;

- (NSString*)encryptString:(NSString*)plainText withKey:(NSString*)encryptKey
                 error:(NSError**)error;

@end
