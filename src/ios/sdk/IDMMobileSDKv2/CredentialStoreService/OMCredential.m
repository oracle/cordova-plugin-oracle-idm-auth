/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMCredential.h"

NSString  *kCredentialUsername = @"cred_username";
NSString  *kCredentialPassword = @"cred_password";
NSString  *kCredentialTenantName = @"cred_tenantname";
NSString  *kCredentialProperties= @"cred_properties";

@implementation OMCredential

- (id) initWithUserName:(NSString*)userName
               password:(NSString*)userPassword
             tenantName:(NSString*)tenantName
             properties:(NSDictionary*)properties{
    
    self = [super init];
    
    if (self){
        _userName = userName;
        _userPassword = userPassword;
        _tenantName = tenantName;
        _properties = properties;
    }
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
    self = [super init];
    if (self)
    {
        _userName = [coder decodeObjectForKey:kCredentialUsername];
        _userPassword = [coder decodeObjectForKey:kCredentialPassword];
        _tenantName = [coder decodeObjectForKey:kCredentialTenantName];
        _properties = [coder decodeObjectForKey:kCredentialProperties];
    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)enCoder
{
    [enCoder encodeObject:_userName forKey:kCredentialUsername];
    [enCoder encodeObject:_userPassword forKey:kCredentialPassword];
    [enCoder encodeObject:_tenantName forKey:kCredentialTenantName];
    [enCoder encodeObject:_properties forKey:kCredentialProperties];
}


@end
