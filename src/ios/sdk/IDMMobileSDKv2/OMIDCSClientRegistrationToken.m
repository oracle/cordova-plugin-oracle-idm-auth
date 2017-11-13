/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMIDCSClientRegistrationToken.h"

NSString *const kClientID = @"client_id";
NSString *const kClientName = @"client_name";
NSString *const kClientSecret = @"client_secret";
NSString *const kClientDeviceID = @"device_id";
NSString *const kClientScope = @"scope";
NSString *const kRedirectURL = @"redirect_uris";
NSString *const kGrantTypes = @"grant_types";
NSString *const kAppID = @"ios_bundle_id";
NSString *const kClientSecretExpiryDate = @"client_secret_expires_at";

@implementation OMIDCSClientRegistrationToken

- (id)initWithInfo:(NSDictionary*)info;
{
    self = [super init];
    
    if (self)
    {
        _clientID = [info valueForKey:kClientID];
        _clientName = [info valueForKey:kClientName];
        _clientSecret = [info valueForKey:kClientSecret];
        _redirectUris = [info valueForKey:kRedirectURL];
        _grantTypes = [info valueForKey:kGrantTypes];
        _scope = [info valueForKey:kClientScope];
        _deviceID = [info valueForKey:kClientDeviceID];
        
        NSTimeInterval seconds = [[info valueForKey:kClientSecretExpiryDate]
                                  doubleValue];
        NSDate *epochNSDate = [[NSDate alloc] initWithTimeIntervalSince1970:
                               seconds];
        
        _clientSecretExpiryDate = epochNSDate;
        _appBundleID = [info valueForKey:kAppID];
    }
    
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
    self = [super initWithCoder:coder];
    if (self)
    {
        _clientID = [coder decodeObjectForKey:kClientID];
        _clientName = [coder decodeObjectForKey:kClientName];
        _clientSecret = [coder decodeObjectForKey:kClientSecret];
        _redirectUris = [coder decodeObjectForKey:kRedirectURL];
        _grantTypes = [coder decodeObjectForKey:kGrantTypes];
        _scope = [coder decodeObjectForKey:kClientScope];
        _deviceID = [coder decodeObjectForKey:kClientDeviceID];
        _clientSecretExpiryDate = [coder decodeObjectForKey:kClientSecretExpiryDate];
        _appBundleID = [coder decodeObjectForKey:kAppID];

    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder
{
    [super encodeWithCoder:coder];
    
    [coder encodeObject:_clientID forKey:kClientID];
    [coder encodeObject:_clientName forKey:kClientName];
    [coder encodeObject:_clientSecret forKey:kClientSecret];
    [coder encodeObject:_redirectUris forKey:kRedirectURL];
    [coder encodeObject:_grantTypes forKey:kGrantTypes];
    [coder encodeObject:_scope forKey:kClientScope];
    [coder encodeObject:_deviceID forKey:kClientDeviceID];
    [coder encodeObject:_clientSecretExpiryDate forKey:kClientSecretExpiryDate];
    [coder encodeObject:_appBundleID forKey:kAppID];
}

- (NSMutableDictionary*)jsonInfo;
{
    NSMutableDictionary *jsonMap = [NSMutableDictionary dictionary];
    
    [jsonMap setValue:_clientID forKey:kClientID];
    [jsonMap setValue:_clientName forKey:kClientName];
    [jsonMap setValue:_clientSecret forKey:kClientSecret];
    [jsonMap setObject:_redirectUris forKey:kRedirectURL];
    [jsonMap setObject:_grantTypes forKey:kGrantTypes];
    [jsonMap setValue:_scope forKey:kClientScope];
    [jsonMap setValue:_deviceID forKey:kClientDeviceID];
    [jsonMap setObject:[NSString stringWithFormat:@"%f",[_clientSecretExpiryDate timeIntervalSince1970]] forKey:kClientSecretExpiryDate];
    [jsonMap setObject:_appBundleID forKey:kAppID];
    
    return jsonMap;
}

- (BOOL)isTokenValid
{
    NSTimeInterval interval = [[NSDate date]
                               timeIntervalSinceDate:self.clientSecretExpiryDate];
    
    return (interval > 0) ? NO : YES;

}

@end
