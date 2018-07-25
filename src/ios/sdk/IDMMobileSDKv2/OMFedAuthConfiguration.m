/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMFedAuthConfiguration.h"
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMErrorCodes.h"

@implementation OMFedAuthConfiguration

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error
{
    self = [super initWithProperties:properties error:error];
    if (self)
    {
     NSInteger errorCode = -1;
        NSString *authServerType = [properties
                                    valueForKey:OM_PROP_AUTHSERVER_TYPE];
        if ([OM_PROP_AUTHSERVER_FED_AUTH
             caseInsensitiveCompare:authServerType] == NSOrderedSame)
        {
            id loginSucessesURL = [properties valueForKey:OM_PROP_LOGIN_SUCCESS_URL];
            id loginFailureURL = [properties valueForKey:OM_PROP_LOGIN_FAILURE_URL];

            id requiredTokens = [properties
                                 valueForKey:OM_PROP_REQUIRED_TOKENS];
            id loginURL = [properties valueForKey:OM_PROP_LOGIN_URL];
            id logoutURL = [properties valueForKey:OM_PROP_LOGOUT_URL];
            id logoutSucessesURL = [properties valueForKey:OM_PROP_LOGOUT_SUCCESS_URL];
            id logoutFailureURL = [properties valueForKey:OM_PROP_LOGOUT_FAILURE_URL];

            id parseTokenRelayResponse = [properties
                                          valueForKey:
                                          OM_PROP_PARSE_TOKEN_RELAY_RESPONSE];
            id usernameParamName = [properties
                                    valueForKey:OM_PROP_USERNAME_PARAM_NAME];
            if (requiredTokens &&
                [requiredTokens isKindOfClass:[NSSet class]] == true)
            {
                _fedAuthUsernameParamName = usernameParamName;
            }
            if (requiredTokens &&
                [requiredTokens isKindOfClass:[NSSet class]] == false)
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
                
            if([self isValidString:loginSucessesURL] &&
               [self isValidUrl:loginSucessesURL])
            {
                _loginSuccessURL = [NSURL URLWithString:loginSucessesURL];
            }
            else
            {
                errorCode =  OMERR_FEDAUTH_LOGIN_SUCCESS_URL_IS_INVALID;
            }

            if([self isValidString:loginFailureURL] &&
               [self isValidUrl:loginFailureURL])
            {
                _loginFailureURL = [NSURL URLWithString:loginFailureURL];
            }
            else
            {
                errorCode =  OMERR_FEDAUTH_LOGIN_FAILURE_URL_IS_INVALID;

            }
            
            if([self isValidString:logoutURL] && [self isValidUrl:logoutURL])
            {
                _logoutURL =[NSURL URLWithString:logoutURL];
            }
            else
            {
                errorCode = OMERR_LOGOUT_URL_IS_INVALID;
            }
            
            if([self isValidString:logoutSucessesURL] &&
               [self isValidUrl:logoutSucessesURL])
            {
                _logoutSuccessURL = [NSURL URLWithString:logoutSucessesURL];
            }
            
            if([self isValidString:logoutFailureURL] &&
               [self isValidUrl:logoutFailureURL])
            {
                _logoutFailureURL = [NSURL URLWithString:loginFailureURL];
            }

            _parseTokenRelayResponse = [OMMobileSecurityConfiguration
                                        boolValue:parseTokenRelayResponse];
        }
        else
        {
            errorCode = OMERR_INVALID_AUTH_SERVER_TYPE;

        }
        
        id enableWebkit = [properties valueForKey:OM_PROP_ENABLE_WKWEBVIEW];
        BOOL enable = [OMMobileSecurityConfiguration boolValue:enableWebkit];

        if (enable && [OMMobileSecurityConfiguration
                                    isWKWebViewAvailable])
        {
            _enableWKWebView = [OMMobileSecurityConfiguration
                                boolValue:enableWebkit];
            
        }
        
        id autoConfirmLogout = [properties valueForKey:OM_PROP_CONFIRM_LOGOUT_AUTOMATICALLY];
        
        _autoConfirmLogout = [OMMobileSecurityConfiguration boolValue:autoConfirmLogout];
        
        id logoutButtonList = [properties valueForKey:OM_PROP_CONFIRM_LOGOUT_BUTTON_ID];

        if (logoutButtonList &&
            [logoutButtonList isKindOfClass:[NSSet class]])
        {
            _confirmLogoutButtons = logoutButtonList;
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
