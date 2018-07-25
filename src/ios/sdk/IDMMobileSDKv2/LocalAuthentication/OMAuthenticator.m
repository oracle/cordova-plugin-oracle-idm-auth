/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMAuthenticator.h"

@implementation OMAuthenticator

- (id)initWithInstanceId:(NSString *)instanceId error:(NSError **)error
{
    self = [super init];
    
    if (self)
    {
        
    }
    
    return self;
}
- (void)setAuthData:(OMAuthData *)authData error:(NSError **)error
{
    
}

- (void)deleteAuthData:(NSError **)error
{
    
}

- (void)updateAuthData:(OMAuthData *)currentAuthData newAuthData:
    (OMAuthData *)newAuthData error:(NSError **)error;
{
    
}

- (BOOL)authenticate:(OMAuthData*)authData error:(NSError**)error
{
    
    return NO;
}

- (BOOL)isAuthDataSet
{
    return NO;
}


- (void)inValidate
{
    
}

- (OMKeyStore*)keyStore
{
    return nil;
}

- (void)copyKeysFromKeyStore:(OMKeyStore*)keyStore
{
    
}

- (NSInteger)authDataLength;
{
    return -1;
}
@end
