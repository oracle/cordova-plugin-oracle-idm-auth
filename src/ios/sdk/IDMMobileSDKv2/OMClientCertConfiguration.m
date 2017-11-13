/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMClientCertConfiguration.h"
#import "OMObject.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"

@implementation OMClientCertConfiguration

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error
{
    self = [super initWithProperties:properties error:error];
    if (self)
    {
        NSUInteger errorCode = -1;

        NSString *authServerType = [properties
                                    valueForKey:OM_PROP_AUTHSERVER_TYPE];
        if ([OM_PROP_AUTHSERVER_CLIENT_CERT
             caseInsensitiveCompare:authServerType] == NSOrderedSame)
        {
            id requiredTokens = [properties
                                 valueForKey:OM_PROP_REQUIRED_TOKENS];
            id loginURL = [properties valueForKey:OM_PROP_LOGIN_URL];
            id logoutURL = [properties valueForKey:OM_PROP_LOGOUT_URL];

            if ((requiredTokens &&
                 [requiredTokens isKindOfClass:[NSSet class]] == false))
            {
                errorCode =  OMERR_INVALID_REQUIRED_TOKENS ;

            }
            else
            {
                _requiredTokens = requiredTokens;

            }
            
            if([self isValidString:loginURL] && [self isValidUrl:loginURL])
            {
                _loginURL = [NSURL URLWithString:loginURL];
            }
            else
            {
                errorCode =  OMERR_LOGIN_URL_IS_INVALID ;
            }
            
            if([self isValidString:logoutURL] && [self isValidUrl:logoutURL])
            {
                _logoutURL =[NSURL URLWithString:logoutURL];
            }
            else
            {
                errorCode = OMERR_LOGOUT_URL_IS_INVALID;
            }
            
        }
        else
        {
            errorCode = OMERR_INVALID_AUTH_SERVER_TYPE;

        }
        
        if (errorCode !=-1)
        {
            self = nil;
            
            if (error)
            {
                *error = [OMObject createErrorWithCode:errorCode];
            }
        }
        
    }
    
    return self;
}
@end
