/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMMobileSecurityConfiguration.h"
#import "OMObject.h"
#import "OMDefinitions.h"
#import "OMErrorCodes.h"
#import "OMIdentityContext.h"
#import <WebKit/WebKit.h>

#define MIN_TIMEOUT_TIME 10

@implementation OMMobileSecurityConfiguration

+ (NSDictionary *)parseConfigurationURL: (NSURL *)configURL
                  persistInUserDefaults: (BOOL)persist
                                withKey: (NSString *)key
{
    NSString            *queryParams = [configURL query];
    NSMutableDictionary *dictionary  = [[NSMutableDictionary alloc] init];
    NSArray *configArray = [queryParams componentsSeparatedByString:@"&"];
    
    for (NSString *value in configArray)
    {
        NSArray *configParam = [value componentsSeparatedByString:@"::="];
        if ([configParam count] == 2)
        {
            NSString *name = [configParam objectAtIndex:0];
            NSString *value = [configParam objectAtIndex:1];
            [self property:name value:value toDictionary:dictionary];
        } //if block
    } //for loop
    
    
    
    if ([dictionary count] == 0)
    {
        dictionary = nil;
    }
    else if (persist)
    {
        //Store in NSUserDefaults and save it
        NSUserDefaults      *userDefaults = [NSUserDefaults
                                             standardUserDefaults];
        NSData *configData = nil;
        /* Not all objects can be stored in NSUSerDefaults. Hence to store
         unsupported objects(NSSet in this case) we need to archive it as NSData
         and then store it*/
        @try
        {
            configData = [NSKeyedArchiver
                          archivedDataWithRootObject:dictionary];
        }
        @catch (NSException *exception)
        {
            if([[exception name]
                isEqualToString:NSInvalidArchiveOperationException])
            {
                NSLog(@"Exception in archiving Config Dictionary: %@",
                           exception.reason);
            }
        }
        if (key)
            [userDefaults setObject:configData forKey:key];
        else
            [userDefaults setObject:configData
                             forKey:OM_PROP_NSUSERDEFAULTS_KEY];
        [userDefaults synchronize];
    }
    
    return dictionary;
}

+ (void)property:(NSString *)name value:(NSString *)value
    toDictionary:(NSMutableDictionary *)dictionary
{
    if (NSOrderedSame ==
        [name caseInsensitiveCompare:OM_PROP_REQUIRED_TOKENS])
    {
        NSArray *tokens = [value componentsSeparatedByString:@","];
        [dictionary setObject:tokens forKey:OM_PROP_REQUIRED_TOKENS];
    }
    else if ([self urlDecodeValueForParameter:name])
    {
        NSString *decodedVal = [value stringByRemovingPercentEncoding];
        [dictionary setObject:decodedVal forKey:name];
    }
    else if(NSOrderedSame ==
            [name caseInsensitiveCompare:OM_PROP_OAUTH_SCOPE])
    {
        NSArray *tokens = [value componentsSeparatedByString:@","];
        NSSet *oauthScopes = [NSSet setWithArray:tokens];
        [dictionary setObject:oauthScopes forKey:OM_PROP_OAUTH_SCOPE];
    }
    else
        [dictionary setObject:value forKey:name];
}

+ (BOOL)urlDecodeValueForParameter:(NSString *)name
{
    if([name isEqualToString:OM_PROP_LOGIN_URL])
        return true;
    else if([name isEqualToString:OM_PROP_LOGOUT_URL])
        return true;
    else
        return false;
}

- (BOOL)isValueInRange:(NSInteger)value range:(NSRange)range
{
    BOOL valid = NO;
    
    valid = NSLocationInRange(value, range);

    return valid;
}

- (BOOL)isValidString:(NSString*)str
{
    BOOL valid = NO;
    
    if ((YES == [str isKindOfClass:[NSString class]]) &&  [str length] > 0)
    {
        valid = YES;
    }
    return valid;
}

+ (BOOL)isWKWebViewAvailable;
{
    BOOL enbale = NO;
  
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"9.0") && ([WKWebView class]))
    {
        enbale = YES;
    }
    
    return enbale;
}

+ (BOOL)isValidTimeOutInterval:(id)timeInterval
{
    NSRange range = NSMakeRange(MIN_TIMEOUT_TIME, INT_MAX);
    return [OMMobileSecurityConfiguration isValidNumber:timeInterval
                                                inRange:range];
}

- (BOOL)isValidUrl:(NSString *)url
{
    BOOL valid = NO;
    
    if (url != nil)
    {
        NSURL *resultantUrl = [NSURL URLWithString:url];
        
        //Added More validations 
        if (resultantUrl && resultantUrl.scheme && resultantUrl.host)
        {
            valid = YES;
        }
    }
    return valid;
}

+ (BOOL)isValidNumber:(id)object inRange:(NSRange)range
{
    NSRange localRange = range;
    if (range.length == 0 && range.location == 0)
    {
        localRange = NSMakeRange(INT_MIN, INT_MAX);
    }
    if (([object isKindOfClass:[NSString class]] ||
         [object isKindOfClass:[NSNumber class]]) &&
        NSLocationInRange([object intValue], localRange))
    {
        return true;
    }
    return false;
}

+ (BOOL)isValidUnsignedNumber:(id)object
{
     return [OMMobileSecurityConfiguration isValidNumber:object
                                          inRange:NSMakeRange(0, INT_MAX)];
}

+ (BOOL)boolValue:(id)object
{
    if ([object isKindOfClass:[NSString class]] &&
        [@"TRUE" caseInsensitiveCompare:object] == NSOrderedSame)
    {
        return true;
    }
    if ([object isKindOfClass:[NSNumber class]] &&
        [object boolValue])
    {
        return true;
    }
    return false;
}

-(id)initWithProperties:(NSDictionary *)properties error:(NSError **)error;
{
    self = [super init];
    
    if (self)
    {
        
     NSInteger errorCode = -1;
                
        id appName = [properties valueForKey:OM_PROP_APPNAME];
        id idleTimeout = [properties
                          valueForKey:OM_PROP_IDLE_TIMEOUT_VALUE];
        id sessionTimeout = [properties
                             valueForKey:OM_PROP_SESSION_TIMEOUT_VALUE];
        id idleTimeOutPercent = [properties
                                 valueForKey:OM_PROP_PERCENTAGE_TO_IDLE_TIMEOUT];
        id authRetryCount = [properties
                             valueForKey:OM_PROP_MAX_LOGIN_ATTEMPTS];

        id presentClientIdentityOnDemand = [properties valueForKey:
                                            OM_PROP_PRESENT_CLIENT_IDENTITY_ON_DEMAND];
        id cryptoScheme = [properties valueForKey:OM_PROP_CRYPTO_SCHEME];
        
        id sendCustomHeadersLogout = [properties valueForKey:
                                    OM_PROP_SEND_CUSTOM_AUTH_HEADERS_IN_LOGOUT];
        id sendAuthHeaderLogout = [properties valueForKey:
                                OM_PROP_SEND_AUTHORIZATION_HEADER_DURING_LOGOUT];
        id customHeaders = [properties valueForKey:OM_PROP_CUSTOM_AUTH_HEADERS];
        
        id localAuthInstanceId = [properties valueForKey:
                                    OM_PROP_LOCAL_AUTHENTICATOR_INSTANCE_ID];

        
        if([self isValidString:appName])
        {
            _appName = appName;
        }
        else
        {
            errorCode = OMERR_INVALID_APP_NAME;

        }

        if (sessionTimeout)
        {
            if([OMMobileSecurityConfiguration
                isValidTimeOutInterval:sessionTimeout])
            {
                _sessionTimeout = [sessionTimeout intValue];
            }
            else
            {
                errorCode = OMERR_INVALID_SESSION_TIMEOUT_TIME;
            }
        }

        if (idleTimeout)
        {
            if([OMMobileSecurityConfiguration
                isValidTimeOutInterval:idleTimeout])
            {
                _idleTimeout = [idleTimeout intValue];
            }
            else
            {
                errorCode = OMERR_INVALID_IDLE_TIMEOUT_TIME;
                
            }
        }
        
        if (_idleTimeout > 0 && _sessionTimeout > 0 &&
            _idleTimeout > _sessionTimeout)
        {
            errorCode = OMERR_INVALID_IDLE_TIMEOUT_TIME;
        }

        if (idleTimeOutPercent)
        {
            if ([OMMobileSecurityConfiguration
                 isValidNumber:idleTimeOutPercent inRange:NSMakeRange(1, 99)])
            {
                _percentageToIdleTimeout = [idleTimeOutPercent intValue];
            }
            else
            {
                errorCode = OMERR_OUT_OF_RANGE;
            }
        }
        else
        {
            _percentageToIdleTimeout = 10;
        }

        if ([OMMobileSecurityConfiguration
             isValidUnsignedNumber:authRetryCount])
        {
            _authenticationRetryCount = [authRetryCount intValue];
        }
        else
        {
            _authenticationRetryCount = 3;
        }
        
        if ([localAuthInstanceId isValidString:localAuthInstanceId])
        {
            _localAuthenticatorIntanceId = localAuthInstanceId;
        }
        
        _presentIdentityOnDemand = [OMMobileSecurityConfiguration
                                    boolValue:presentClientIdentityOnDemand];
        
        
        if (cryptoScheme)
        {
            if ([cryptoScheme isKindOfClass:[NSString class]])
            {
                if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_PLAINTEXT])
                    _cryptoScheme = PlainText;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SHA1])
                    _cryptoScheme = SHA1;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SHA224])
                    _cryptoScheme = SHA224;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SHA256])
                    _cryptoScheme = SHA256;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SHA384])
                    _cryptoScheme = SHA384;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SHA512])
                    _cryptoScheme = SHA512;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SSHA1])
                    _cryptoScheme = SSHA1;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SSHA224])
                    _cryptoScheme = SSHA224;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SSHA256])
                    _cryptoScheme = SSHA256;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SSHA384])
                    _cryptoScheme = SSHA384;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_SSHA512])
                    _cryptoScheme = SSHA512;
                else if (NSOrderedSame == [cryptoScheme
                                           caseInsensitiveCompare:OM_PROP_CRYPTO_AES])
                    _cryptoScheme = AES;
            }
            else
            {
                errorCode = OMERR_INVALID_CRYPTO_SCHEME;
            }
        }
        else
        {
            self.cryptoScheme = SSHA512;
        }
        _sendCustomHeadersLogout = [OMMobileSecurityConfiguration
                                    boolValue:sendCustomHeadersLogout];
        _sendAuthHeaderLogout = [OMMobileSecurityConfiguration
                                 boolValue:sendAuthHeaderLogout];
        if ([customHeaders isKindOfClass:[NSDictionary class]])
        {
            _customHeaders = customHeaders;
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

- (NSDictionary *)getIdentityClaims
{
    OMIdentityContext *identityContext = [OMIdentityContext sharedInstance];
    [identityContext setApplicationID:self.appName];
    NSDictionary *deviceClaims = [identityContext
                                  getJSONDictionaryForAuthentication:nil];
    return deviceClaims;
}

+ (NSDictionary *)initializationConfigurationForKey:(NSString *)key
{
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    id retrievedConfig = nil;
    NSData *propertyData = nil;
    NSDictionary *properties = nil;
    if(key)
    {
        retrievedConfig = [userDefaults objectForKey:key];
    }
    else
    {
        retrievedConfig = [userDefaults objectForKey:OM_PROP_NSUSERDEFAULTS_KEY];
    }
    if([retrievedConfig isKindOfClass:[NSDictionary class]]) /* For bacward
                                                              compatibility */
    {
        properties = (NSDictionary *)retrievedConfig;
    }
    else if([retrievedConfig isKindOfClass:[NSData class]])
    {
        propertyData = (NSData *)retrievedConfig;
        /* As the config was stored as NSData it is unarchived to get back the
         config dictionary */
        @try
        {
            properties = [NSKeyedUnarchiver
                          unarchiveObjectWithData:propertyData];
        }
        @catch (NSException *exception)
        {
            if([[exception name]
                isEqualToString:NSInvalidUnarchiveOperationException])
            {
                OMDebugLog(@"Exception in unarchiving Authentication Context: %@",
                           exception.reason);
            }
        }
    }
    return properties;
}

+ (BOOL)deleteInitializationConfigurationForKey:(NSString *)key
{
    NSDictionary *confDict = [OMMobileSecurityConfiguration
                              initializationConfigurationForKey:key];
    if(!confDict)
        return FALSE;
    NSString *removeKey = nil;
    if(key)
        removeKey = key;
    else
        removeKey = OM_PROP_NSUSERDEFAULTS_KEY;
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    [userDefaults removeObjectForKey:removeKey];
    [userDefaults synchronize];
    return true;
}

@end
