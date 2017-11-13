/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMKeyChain.h"
#import "KeychainItemWrapper.h"

@implementation OMKeyChain

+ (void)setItem:(id)item forKey:(NSString*)key
    accessGroup:(NSString *)accessGroup dataAccessibleLevel:(CFTypeRef)protectionLevel
{
    KeychainItemWrapper *wrapper = [[KeychainItemWrapper alloc]
                                    initWithIdentifier:key
                                    accessGroup:accessGroup];
    
    id currAccessible = [wrapper objectForKey:(__bridge NSString *)kSecAttrAccessible];
    
    if (!currAccessible && protectionLevel)
    {
        [wrapper setObject: (__bridge NSString *)protectionLevel
                         forKey:(__bridge NSString *)kSecAttrAccessible];
    }

    [wrapper setObject:item forKey:(id)kSecValueData];
}


+ (void)setItem:(id)item forKey:(NSString*)key
    accessGroup:(NSString *)accessGroup
{
    [OMKeyChain setItem:item forKey:key accessGroup:accessGroup
                                        dataAccessibleLevel:nil];
}

+ (id)itemForKey:(NSString*)key accessGroup:(NSString *)accessGroup;
{
    KeychainItemWrapper *wrapper = [[KeychainItemWrapper alloc]
                                    initWithIdentifier:key
                                    accessGroup:accessGroup];
    return [wrapper objectForKey:(id)kSecValueData];
}

+ (void)deleteItemForKey:(NSString*)key accessGroup:(NSString *)accessGroup;
{
    KeychainItemWrapper *wrapper = [[KeychainItemWrapper alloc]
                                    initWithIdentifier:key
                                    accessGroup:accessGroup];;
     [wrapper resetKeychainItem];
}
@end
