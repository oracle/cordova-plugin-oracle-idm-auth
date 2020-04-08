/**
* Copyright (c) 2017, Oracle and/or its affiliates.
* The Universal Permissive License (UPL), Version 1.0
*/

#import "OMClassicCredential.h"
#import "KeychainItemWrapper.h"
#import "OMCredential.h"

@implementation OMClassicCredential

- (id)getCredentialForKey:(NSString*)key
{
    if (key == nil || [key length] == 0)
        return nil;
    NSString *userName = (NSString*)[self getProperty:key
                                         propertyName:(id)kSecAttrAccount];
    NSString *userPassword = (NSString*)[self getProperty:key
                                             propertyName:(id)kSecValueData];
    NSString *tenantName = (NSString *)[self getProperty:key
                                            propertyName:(id)kSecAttrDescription];
    NSString *propertyString = (NSString *)[self getProperty:key
                                                propertyName:kSecAttrLabel];
    NSDictionary *properties = nil;
    if (propertyString != nil && [propertyString length] > 0)
        properties = [NSJSONSerialization JSONObjectWithData:
                      [propertyString dataUsingEncoding:NSUTF8StringEncoding]
                                                options:0 error:nil];
    if([userName length] == 0 && [userPassword length] == 0 &&
       [tenantName length] == 0 && properties == nil)
        return nil;
    OMCredential *cred = [[OMCredential alloc]
                          initWithUserName:userName password:userPassword
                          tenantName:tenantName properties:properties];
    return cred;
}

////////////////////////////////////////////////////////////////////////////////
// Gets a property to KeyChainItem
////////////////////////////////////////////////////////////////////////////////
- (id)getProperty:(NSString*)key
     propertyName:(id)propertyName
{
    if (key == nil || [key length] == 0)
        return nil;
    KeychainItemWrapper *keychain = [[KeychainItemWrapper alloc] initWithIdentifier:key accessGroup:nil classicRecords:YES];
    id returnObj = (id)[keychain objectForKey:(id)propertyName];
    return returnObj;
}

@end
