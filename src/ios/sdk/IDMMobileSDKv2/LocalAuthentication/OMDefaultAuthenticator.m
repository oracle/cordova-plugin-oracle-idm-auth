/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMDefaultAuthenticator.h"
#import "OMAuthData.h"
#import "OMCryptoService.h"
#import "OMDefinitions.h"
#import "OMKeyManager.h"

@implementation OMDefaultAuthenticator

- (id)initWithInstanceId:(NSString *)instanceId error:(NSError *__autoreleasing *)error
{
    self = [super initWithInstanceId:instanceId error:error];
    
    if (self)
    {
        self.instanceId = instanceId;
        
    }
    
    return self;
}

- (OMAuthData *)authDataForKey:(NSString*)key
{
    OMAuthData *auth = [[OMAuthData alloc] initWithData:[self passwordForKey:key]];
    return auth;
}

- (NSData*)passwordForKey:(NSString*)key
{
    NSString *passForKey = [OMCryptoService SHA1HashAndBase64EncodeData:
                            [key dataUsingEncoding:NSUTF8StringEncoding]
                            withSaltOfBitLength:0 outSalt:nil outError:nil];
    
    return [passForKey dataUsingEncoding:NSUTF8StringEncoding];
}

#pragma mark -
#pragma mark Overide -

- (BOOL)isAuthDataSet
{
    return [super isAuthDataSet];
}

- (OMKeyStore*)keyStore;
{
   return [super keyStore];
}
- (void)inValidate
{
    //override to avoid calling base class methods
}

- (BOOL)authenticate:(OMAuthData *)authData error:(NSError *__autoreleasing *)error
{
    if (![self isAuthDataSet])
    {
        [super setAuthData:[self authDataForKey:self.instanceId] error:error];
        
    }

  return [super authenticate:[self authDataForKey:self.instanceId] error:error];
}

- (void)setAuthData:(OMAuthData *)authData error:(NSError *__autoreleasing *)error
{

    //override to avoid calling base class methods

}

- (void)updateAuthData:(OMAuthData *)currentAuthData newAuthData:(OMAuthData *)newAuthData
                 error:(NSError *__autoreleasing *)error
{
    //override to avoid calling base class methods
  
}

- (void)deleteAuthData:(NSError *__autoreleasing *)error
{
    //override to avoid calling base class methods

}

@end
