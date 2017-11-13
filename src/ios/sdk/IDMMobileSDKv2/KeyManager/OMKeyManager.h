/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import <Foundation/Foundation.h>

@class OMKeyStore;

@interface OMKeyManager : NSObject

+ (OMKeyManager *)sharedManager;

- (OMKeyStore*)createKeyStore:(NSString *)keyStoreId kek:(NSData*)kek
                    overWrite:(BOOL)overWrite error:(NSError**)error;
- (OMKeyStore*)updateKeyStore:(NSString *)keyStoreId kek:(NSData*)kek
                       newKek:(NSData*)newKek error:(NSError**)error;
- (void)deleteKeyStore:(NSString *)keyStoreId kek:(NSData*)kek error:(NSError**)error;
- (OMKeyStore *)keyStore:(NSString *)keyStoreId kek:(NSData*)kek error:(NSError**)error;

- (NSString*)hashFileNameForKeystore:(NSString *)keyStoreId kek:(NSData*)kek;

@end
