/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@class OMKeyStore;

@interface OMSecureStorage : NSObject

- (id)initWithKeyStore:(OMKeyStore*)keyStore keyId:(NSString*)keyId
                 error:(NSError**)error;

/**
 * This method retrieves the data from the secure storage and returns the same

 * @param dataid represents the id against which data has been saved in the storage
 * @param error Refrence to a NSError object that will contain any error
 *                 while retriving the data
 * @return         data
 */

- (id)dataForId:(NSString *)dataId error:(NSError **)error;

/**
 * This method encrypts the data and stores it in secure storage
 
 * @param dataid represents the id against which data has been saved in the storage
 * @param data represents the  data to be saved in the storage
 * @param error Refrence to a NSError object that will contain any error
 *                 while retriving the data
 * @return         BOOL Yes if saved no if its not 
 */

- (BOOL)saveDataForId:(NSString *)dataId data:(id)data error:(NSError **)error;

/**
 * This method deletes the data against given dataid
 
 * @param dataid represents the id against which data has been saved in the storage
 * @param error Refrence to a NSError object that will contain any error
 *                 while retriving the data
 * @return         BOOL Yes if date deleted no if its not
 */

- (BOOL)deleteDataForId:(NSString *)dataId error:(NSError **)error;

- (NSString *)fileNameForDataId:(NSString *)dataId;
- (NSString *)filePathForDataId:(NSString*)dataId;
@end
