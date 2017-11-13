/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@interface OMCredential : NSObject

@property (nonatomic, strong) NSString *userName;
@property (nonatomic, strong) NSString *userPassword;
@property (nonatomic, strong) NSString *tenantName;
@property (nonatomic, strong) NSDictionary *properties;

/**
 * Initializer method of OMCredential, which initializes
 * this object by taking username, password, tenantName
 * and custom user objects
 *
 * @param userName - Username
 * @param userPassword - Password for user
 * @param tenantName - Tenant name where the user belongs
 * @param properties - Custom user properties
 *
 * @return OMCredential object
 */
- (id) initWithUserName:(NSString*)userName
               password:(NSString*)userPassword
             tenantName:(NSString*)tenantName
             properties:(NSDictionary*)properties;

@end
