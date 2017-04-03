/* Copyright (c) 2011, 2016, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMCredential.h - Oracle Mobile Credential Object
 
 DESCRIPTION
 Credential object
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 shivap    10/01/16 - Creation
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
