/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticationService.h"
#import "OMCryptoService.h"
#import "OMHTTPBasicConfiguration.h"
#import "OMDefinitions.h"
#import "OMCredential.h"
#import "OMCredentialStore.h"
#import "OMHTTPBasicAuthenticationService.h"
#import "NSData+OMBase64.h"
#import "OMObject.h"
#import "OMErrorCodes.h"
#import "OMOAuthConfiguration.h"
#define OM_CRYPTO_HASH_SALT_LENGTH_IN_BITS         128
#define MASK_PASSWORD @"********"

@implementation OMAuthenticationService
-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
             authenticationRequest:(OMAuthenticationRequest *)authReq
                          delegate:(id<OMAuthenticationDelegate>)delegate
{
    self = [super init];
    if (self)
    {
        _mss = mss;
        _request = authReq;
        _delegate = delegate;
        _context = [[OMAuthenticationContext alloc] initWithMss:mss];
    }
    return self;
}

-(void)performAuthentication:(NSMutableDictionary *)authData
                       error:(NSError *__autoreleasing *)error
{
    return;
}

-(BOOL)isInputRequired:(NSMutableDictionary *)authData
{
    return false;
}

- (NSString *)retrieveRememberPassword
{
    NSString *rememberCredKey = [self.mss rememberCredKey];
    
    if (![rememberCredKey length])
    {
        return nil;
    }
    
    OMCredential *cred = [[OMCredentialStore sharedCredentialStore]
                          getCredential:rememberCredKey];

    return cred.userPassword;
}

- (void) retrieveRememberCredentials:(NSMutableDictionary *) authnData
{
    NSString *currentUser = [authnData valueForKey:OM_USERNAME];
    NSString *currentTenant = [authnData valueForKey:OM_IDENTITY_DOMAIN];
    
    NSString *rememberCredKey = @"";

    rememberCredKey = [self.mss rememberCredKey];

    
    if (![rememberCredKey length])
    {
        return;
    }
    
    if (!authnData)
    {
        return;
    }
    
    OMCredential *cred = [[OMCredentialStore sharedCredentialStore]
                          getCredential:rememberCredKey];
    
    [authnData setValue:cred.userName forKey:OM_USERNAME];
    
    if(![currentUser length])
    {
        [authnData setValue:cred.userName forKey:OM_USERNAME];
    }
    
    if (![currentUser length] && [cred.userPassword length])
    {
        [authnData setValue:cred.userPassword forKey:OM_PASSWORD];
    }
    else
    {
        [authnData setValue:@"" forKey:OM_PASSWORD];
    }
    
    OMMobileSecurityConfiguration *config = self.mss.configuration;
    
    if ([config isKindOfClass:[OMHTTPBasicConfiguration class]])
    {
        [authnData setValue:[NSNumber numberWithBool:
                             ((OMHTTPBasicConfiguration *)config).
                             collectIdentityDomain]
                     forKey:OM_PROP_COLLECT_IDENTITY_DOMAIN];
        if([currentTenant length])
        {
            [authnData setValue:currentTenant forKey:OM_IDENTITY_DOMAIN];
        }
        else if ([cred.tenantName length])
        {
            [authnData setValue:cred.tenantName forKey:OM_IDENTITY_DOMAIN];
        }
        else if ([self.request.identityDomain length])
        {
            [authnData setValue:self.request.identityDomain
                         forKey:OM_IDENTITY_DOMAIN];
        }
        else if([((OMHTTPBasicConfiguration *)config).identityDomain length])
        {
            [authnData setValue:((OMHTTPBasicConfiguration *)config).
             identityDomain forKey:OM_IDENTITY_DOMAIN];
        }
        else
        {
            [authnData setValue:@"" forKey:OM_IDENTITY_DOMAIN];
        }
    }
    [authnData setValue:[NSNumber numberWithBool:config.autoLoginAllowed]
                 forKey:OM_PROP_AUTO_LOGIN_ALLOWED] ;
    [authnData setValue:[NSNumber numberWithBool:config.rememberCredAllowed]
                 forKey:OM_PROP_REMEMBER_CREDENTIALS_ALLOWED];
    [authnData setValue:[NSNumber numberWithBool:config.rememberUsernameAllowed]
                 forKey:OM_PROP_REMEMBER_USERNAME_ALLOWED];
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    BOOL rememberCredPrefSet = [[defaults objectForKey:
                                 [NSString stringWithFormat:@"%@_%@",
                                  rememberCredKey,OM_REMEMBER_CRED_PREF_SET]]
                                boolValue];
    if (rememberCredPrefSet)
    {
        NSNumber *autoLoginState = [defaults objectForKey:
                                    [NSString stringWithFormat:@"%@_%@",
                                     rememberCredKey,OM_AUTO_LOGIN_PREF]];
        [authnData setValue:autoLoginState
                     forKey:OM_AUTO_LOGIN_PREF];
        
        NSNumber *rememberCredState = [defaults objectForKey:
                                       [NSString stringWithFormat:@"%@_%@",
                                        rememberCredKey,
                                        OM_REMEMBER_CREDENTIALS_PREF]];
        [authnData setValue:rememberCredState
                     forKey:OM_REMEMBER_CREDENTIALS_PREF];
        
        NSNumber *rememberUsernameState = [defaults objectForKey:
                                           [NSString stringWithFormat:@"%@_%@",
                                            rememberCredKey,
                                            OM_REMEMBER_USERNAME_PREF]];
        [authnData setValue:rememberUsernameState
                     forKey:OM_REMEMBER_USERNAME_PREF];
    }
    else
    {
        [authnData setValue:[NSNumber numberWithBool:config.autoLoginDefault]
                     forKey:OM_AUTO_LOGIN_PREF];
        [authnData setValue:[NSNumber numberWithBool:config.rememberCredDefault]
                     forKey:OM_REMEMBER_CREDENTIALS_PREF];
        [authnData setValue:[NSNumber numberWithBool:
                             config.rememberUsernameDefault]
                     forKey:OM_REMEMBER_USERNAME_PREF];
    }
    NSNumber *authSuccess = [defaults
                             objectForKey:[NSString stringWithFormat:@"%@_%@",
                                           rememberCredKey,OM_AUTH_SUCCESS]];
    [authnData setValue:authSuccess forKey:OM_AUTH_SUCCESS];
}

///////////////////////////////////////////////////////////////////////////////
// Store user credentials in keychain for remember credentials
///////////////////////////////////////////////////////////////////////////////
- (void) storeRememberCredentials:(NSMutableDictionary *) authnData
{
    if (![authnData count])
    {
        return;
    }
    
    NSString *rememberCredKey = [self.mss rememberCredKey];
    if (![rememberCredKey length])
    {
        return;
    }
    // get preference from auth data dictionary
    id autoLoginState = [authnData
                         valueForKey:OM_AUTO_LOGIN_PREF];
    id rememberCredState = [authnData
                            valueForKey:OM_REMEMBER_CREDENTIALS_PREF];
    id rememberUsernameState = [authnData
                                valueForKey:OM_REMEMBER_USERNAME_PREF];
    
    // if a prefernce is not set then get its old value
    // this value can either be in user defaults or app profile configuration
    if (!autoLoginState || !rememberCredState || !rememberUsernameState)
    {
        NSMutableDictionary *oldPreferences = [[NSMutableDictionary alloc]init];
        [self retrieveRememberCredentials:oldPreferences];
        if (!autoLoginState)
        {
            autoLoginState = [oldPreferences
                              valueForKey:OM_AUTO_LOGIN_PREF];
        }
        if (!rememberCredState)
        {
            rememberCredState = [oldPreferences
                                 valueForKey:OM_REMEMBER_CREDENTIALS_PREF];
        }
        if (!rememberUsernameState)
        {
            rememberUsernameState = [oldPreferences
                                     valueForKey:OM_REMEMBER_USERNAME_PREF];
        }
    }
    // preference set as [NSNull null] is treated as false
    if (autoLoginState == [NSNull null])
    {
        autoLoginState = [NSNumber numberWithBool:false];
    }
    if (rememberCredState == [NSNull null])
    {
        rememberCredState = [NSNumber numberWithBool:false];
    }
    if (rememberUsernameState == [NSNull null])
    {
        rememberUsernameState = [NSNumber numberWithBool:false];
    }
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    OMMobileSecurityConfiguration *config = self.mss.configuration;
    
    NSString *username = [authnData valueForKey:OM_USERNAME];
    NSString *password = [authnData valueForKey:OM_PASSWORD];
    NSString *tenant = [authnData valueForKey:OM_IDENTITY_DOMAIN];
    
    BOOL storeUsername = false;
    BOOL storePassword = false;
    
    if (config.rememberUsernameAllowed && [rememberUsernameState boolValue])
    {
        storeUsername = true;
    }
    if ((config.rememberCredAllowed && [rememberCredState boolValue]) ||
        (config.autoLoginAllowed && [autoLoginState boolValue]))
    {
        storePassword = TRUE;
    }
    if (storePassword)
    {
        
        OMCredential *currentCread = [[OMCredential alloc] initWithUserName:username password:password tenantName:tenant properties:nil];
        [[OMCredentialStore sharedCredentialStore] saveCredential:currentCread forKey:rememberCredKey];
        
    }
    else if (storeUsername)
    {
        OMCredential *currentCread = [[OMCredential alloc] initWithUserName:username password:nil tenantName:tenant properties:nil];
        [[OMCredentialStore sharedCredentialStore] saveCredential:currentCread forKey:rememberCredKey];

    }
    else
    {
        [[OMCredentialStore sharedCredentialStore] deleteCredential:rememberCredKey];
    }
    [defaults setObject:[NSNumber numberWithBool:TRUE]
                 forKey:[NSString stringWithFormat:@"%@_%@",
                         rememberCredKey,OM_AUTH_SUCCESS]];
    [defaults synchronize];
}

- (void)cancelAuthentication;
{
    
}
-(void)sendFinishAuthentication:(id)object
{
    // do nothing 
}

///////////////////////////////////////////////////////////////////////////////
// Store user preferences of remember credentials in NSUserDefaults
///////////////////////////////////////////////////////////////////////////////
- (void) storeRememberCredentialsPreference:(NSDictionary *) authnData
{
    if (![authnData count])
    {
        return;
    }
    NSString *rememberCredKey = [self.mss rememberCredKey];
    
    if (![rememberCredKey length])
    {
        return;
    }
    id autoLoginState = [authnData
                         valueForKey:OM_AUTO_LOGIN_PREF];
    id rememberCredState = [authnData
                            valueForKey:OM_REMEMBER_CREDENTIALS_PREF];
    id rememberUsernameState = [authnData
                                valueForKey:OM_REMEMBER_USERNAME_PREF];
    // preference set as [NSNull null] is treated as false
    if (autoLoginState == [NSNull null])
    {
        autoLoginState = [NSNumber numberWithBool:false];
    }
    if (rememberCredState == [NSNull null])
    {
        rememberCredState = [NSNumber numberWithBool:false];
    }
    if (rememberUsernameState == [NSNull null])
    {
        rememberUsernameState = [NSNumber numberWithBool:false];
    }

    OMMobileSecurityConfiguration *config =  self.mss.configuration;
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    
    // if a feature is allowed and its preference is given then store
    if (config.autoLoginAllowed && autoLoginState)
    {
        [defaults setObject:autoLoginState
                     forKey:[NSString stringWithFormat:@"%@_%@",
                             rememberCredKey, OM_AUTO_LOGIN_PREF]];
    }
    if (config.rememberCredAllowed && rememberCredState)
    {
        [defaults setObject:rememberCredState
                     forKey:[NSString stringWithFormat:@"%@_%@",
                             rememberCredKey, OM_REMEMBER_CREDENTIALS_PREF]];
    }
    if (config.rememberUsernameAllowed && rememberUsernameState)
    {
        [defaults setObject:rememberUsernameState
                     forKey:[NSString stringWithFormat:@"%@_%@",
                             rememberCredKey,OM_REMEMBER_USERNAME_PREF]];
    }
    
    if (autoLoginState || rememberCredState || rememberUsernameState)
    {
        [defaults setObject:[NSNumber numberWithBool:TRUE]
                     forKey: [NSString stringWithFormat:@"%@_%@",
                              rememberCredKey,OM_REMEMBER_CRED_PREF_SET]];
    }
    [defaults setObject:[NSNumber numberWithBool:FALSE]
                 forKey:[NSString stringWithFormat:@"%@_%@",
                         rememberCredKey,OM_AUTH_SUCCESS]];
    [defaults synchronize];
}

- (BOOL) shouldPerformAutoLogin:(NSDictionary *)authnData
{
    return ([[authnData valueForKey:OM_AUTH_SUCCESS] boolValue] &&
            [[authnData valueForKey:OM_AUTO_LOGIN_PREF] boolValue]) ;
}

///////////////////////////////////////////////////////////////////////////////
// protect password for storage
///////////////////////////////////////////////////////////////////////////////
-(NSString *)protectPassword:(NSString *)password
                cryptoScheme:(NSUInteger)scheme
                    outError:(NSError **)error
{
    NSString *protectedPassword = nil;
    
    // Pick hashing scheme based on user preference and store password's hash
    switch (scheme)
    {
        case SHA1:
            protectedPassword = [OMCryptoService SHA1HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                         withSaltOfBitLength:0
                                                                     outSalt:nil
                                                                    outError:error];
            break;
        case SHA224:
            protectedPassword = [OMCryptoService SHA224HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:0
                                                                       outSalt:nil
                                                                      outError:error];
            break;
        case SHA256:
            protectedPassword = [OMCryptoService SHA256HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:0
                                                                       outSalt:nil
                                                                      outError:error];
            break;
        case SHA384:
            protectedPassword = [OMCryptoService SHA384HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:0
                                                                       outSalt:nil
                                                                      outError:error];
            break;
        case SHA512:
            protectedPassword = [OMCryptoService SHA512HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:0
                                                                       outSalt:nil
                                                                      outError:error];
            break;
            
            // auto-generate salt for salted algorithm
        case SSHA1:
            protectedPassword = [OMCryptoService SHA1HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                         withSaltOfBitLength:OM_CRYPTO_HASH_SALT_LENGTH_IN_BITS
                                                                     outSalt:nil
                                                                    outError:error];
            break;
        case SSHA224:
            protectedPassword = [OMCryptoService SHA224HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:OM_CRYPTO_HASH_SALT_LENGTH_IN_BITS
                                                                       outSalt:nil
                                                                      outError:error];
            break;
        case SSHA256:
            protectedPassword = [OMCryptoService SHA256HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:OM_CRYPTO_HASH_SALT_LENGTH_IN_BITS
                                                                       outSalt:nil
                                                                      outError:error];
            break;
        case SSHA384:
            protectedPassword = [OMCryptoService SHA384HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:OM_CRYPTO_HASH_SALT_LENGTH_IN_BITS
                                                                       outSalt:nil
                                                                      outError:error];
            break;
        case SSHA512:
            protectedPassword = [OMCryptoService SHA512HashAndBase64EncodeData:[password dataUsingEncoding:NSUTF8StringEncoding]
                                                           withSaltOfBitLength:OM_CRYPTO_HASH_SALT_LENGTH_IN_BITS
                                                                       outSalt:nil
                                                                      outError:error];
            break;
        case PlainText:
            protectedPassword = password;
            break;
        case AES:
            protectedPassword = [self encryptString:password outError:error];
            break;
        default:
            protectedPassword = nil;
            break;
    }
    
    return protectedPassword;
}

- (NSString *) encryptString:(NSString *) string outError:(NSError **) error
{
    NSData *key = [self.mss symmetricEncryptionKey];
    if (!key)
    {
        return nil;
    }
    NSString *protectedString = [OMCryptoService encryptData:[string
                                                              dataUsingEncoding:NSUTF8StringEncoding]
                                            withSymmetricKey:key
                                        initializationVector:nil
                                                   algorithm:OMAlgorithmAES128
                                                     padding:OMPaddingPKCS7
                                                        mode:OMModeCBC
                                          base64EncodeOutput:YES
                               prefixOutputWithAlgorithmName:YES
                                                    outError:error];
    return protectedString;
}

- (NSString *) decryptString:(NSString *) string outError:(NSError **) error
{
    NSData *key = [self.mss symmetricEncryptionKey];
    if (!key)
    {
        return nil;
    }
    NSUInteger algorithmLength = [OM_PROP_CRYPTO_AES length] + 2;
    NSData *decryptedData = [OMCryptoService decryptData:[string
                                                          substringFromIndex:
                                                          algorithmLength]
                                        withSymmetricKey:key
                                    initializationVector:nil
                                               algorithm:OMAlgorithmAES128
                                                 padding:OMPaddingPKCS7
                                                    mode:OMModeCBC
                        isInputPrefixedWithAlgorithmName:NO
                                    isInputBase64Encoded:YES
                                                outError:error];
    if (!decryptedData)
    {
        return nil;
    }
    NSString *decryptedString = [[NSString alloc]
                                 initWithData:decryptedData
                                 encoding:NSUTF8StringEncoding];
    return decryptedString;
}


///////////////////////////////////////////////////////////////////////////////
// unprotect password retrieved from storage for (offline) authentication
///////////////////////////////////////////////////////////////////////////////
-(BOOL) verifyPassword:(NSString *)userPassword
 withProtectedPassword:(NSString *)protectedPassword
              outError:(NSError **)error
{
    NSString *passwordToCompare;
    NSString *passwordForPrefixCheck;
    NSString *salt;
    OMCryptoAlgorithm cryptoAlgorithm = NSUIntegerMax;
    NSUInteger algorithmLength = 0;
    BOOL isPlainText = NO;
    
    // extract crypto scheme of stored password
    if (![protectedPassword length] || ![userPassword length])
        return FALSE;
    passwordForPrefixCheck = [protectedPassword substringFromIndex:1];
    if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SHA1])
    {
        cryptoAlgorithm = OMAlgorithmSHA1;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SHA224])
    {
        cryptoAlgorithm = OMAlgorithmSHA224;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SHA256])
    {
        cryptoAlgorithm = OMAlgorithmSHA256;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SHA384])
    {
        cryptoAlgorithm = OMAlgorithmSHA384;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SHA512])
    {
        cryptoAlgorithm = OMAlgorithmSHA512;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SSHA1])
    {
        cryptoAlgorithm = OMAlgorithmSSHA1;
        algorithmLength = [OM_PROP_CRYPTO_SSHA1 length] + 2;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SSHA224])
    {
        cryptoAlgorithm = OMAlgorithmSSHA224;
        algorithmLength = [OM_PROP_CRYPTO_SSHA224 length] + 2;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SSHA256])
    {
        cryptoAlgorithm = OMAlgorithmSSHA256;
        algorithmLength = [OM_PROP_CRYPTO_SSHA256 length] + 2;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SSHA384])
    {
        cryptoAlgorithm = OMAlgorithmSSHA384;
        algorithmLength = [OM_PROP_CRYPTO_SSHA384 length] + 2;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_SSHA512])
    {
        cryptoAlgorithm = OMAlgorithmSSHA512;
        algorithmLength = [OM_PROP_CRYPTO_SSHA512 length] + 2;
    }
    else if ([passwordForPrefixCheck hasPrefix:OM_PROP_CRYPTO_AES])
    {
        cryptoAlgorithm = OMAlgorithmAES128;
        algorithmLength = [OM_PROP_CRYPTO_AES length] + 2;
    }
    else
    {
        isPlainText = YES;
    }
    
    // Extract salt from stored password for salted algorithms
    // Protected password structure    {algorithm}<base64 encoded digest + salt>
    if (cryptoAlgorithm == OMAlgorithmSSHA1   ||
        cryptoAlgorithm == OMAlgorithmSSHA224 ||
        cryptoAlgorithm == OMAlgorithmSSHA256 ||
        cryptoAlgorithm == OMAlgorithmSSHA384 ||
        cryptoAlgorithm == OMAlgorithmSSHA512)
    {
        // base64 decode
        NSData *digest = [NSData dataFromBase64String:[protectedPassword substringFromIndex:algorithmLength]];
        // NSData+OMBase64 uses ASCII encoding while decoding
        NSString *digestString = [[NSString alloc] initWithData:digest encoding:NSASCIIStringEncoding];
        
        // extract salt
        // Salt's length is in bits convert it to length in hex value.
        salt = [digestString substringFromIndex:[digestString length] - OM_CRYPTO_HASH_SALT_LENGTH_IN_BITS/4];
    }
    
    // apply the same crypto scheme on user password
    switch (cryptoAlgorithm)
    {
        case OMAlgorithmSHA1:
        case OMAlgorithmSHA224:
        case OMAlgorithmSHA256:
        case OMAlgorithmSHA384:
        case OMAlgorithmSHA512:
            passwordToCompare = [OMCryptoService hashData:[userPassword dataUsingEncoding:NSUTF8StringEncoding]
                                                 withSalt:nil
                                                algorithm:cryptoAlgorithm
                                       appendSaltToOutput:NO base64Encode:YES prefixOutputWithAlgorithmName:YES
                                                 outError:error];
            break;
            // salted algorithms - use extracted salt
        case OMAlgorithmSSHA1:
        case OMAlgorithmSSHA224:
        case OMAlgorithmSSHA256:
        case OMAlgorithmSSHA384:
        case OMAlgorithmSSHA512:
            passwordToCompare = [OMCryptoService hashData:[userPassword dataUsingEncoding:NSUTF8StringEncoding]
                                                 withSalt:salt
                                                algorithm:cryptoAlgorithm
                                       appendSaltToOutput:YES base64Encode:YES prefixOutputWithAlgorithmName:YES
                                                 outError:error];
            break;
        case OMAlgorithmAES128:
            passwordToCompare = [self decryptString:protectedPassword
                                           outError:nil];
            break;
        default:
            passwordToCompare = nil;
            break;
    }
    
    // crypto shceme - plain text
    if (isPlainText)
    {
        passwordToCompare = userPassword;
    }
    
    // compare with decrypted password for encryption scheme
    if (cryptoAlgorithm == OMAlgorithmAES128 &&
        passwordToCompare != nil &&
        [passwordToCompare isEqualToString:userPassword])
    {
        return YES;
    }
    // compare with protected password for hashing & plaintext schemes
    else if (passwordToCompare != nil &&
             [passwordToCompare isEqualToString:protectedPassword])
    {
        return YES;
    }
    else
    {
        return NO;
    }
}

-(BOOL)isRequiredTokens:(NSSet *)tokens presentFor:(NSArray *)visitedHosts
{
    if ([tokens count] == 0)
    {
        return true;
    }
    NSHTTPCookieStorage *cookieStore = [NSHTTPCookieStorage
                                        sharedHTTPCookieStorage];
    NSMutableArray *cookieNames = [NSMutableArray array];
    for (NSURL *url in visitedHosts)
    {
        NSArray *cookies = [cookieStore cookiesForURL:url];
        for (NSHTTPCookie *cookie in cookies)
        {
            [cookieNames addObject:cookie.name];
        }
    }
    if ([cookieNames count] == 0)
    {
        return false;
    }
    for (NSString *tokenName in tokens)
    {
        if ([cookieNames containsObject:tokenName] == false)
        {
            return false;
        }
    }
    return true;
}

+ (NSError *)setErrorObject:(NSDictionary *)errorDict
              withErrorCode:(NSUInteger)code
{
    id errorName = [errorDict objectForKey:@"error"];
    NSUInteger errorCode;
    NSError *error = nil;
    
    if ([errorName isKindOfClass:[NSString class]])
    {
        errorCode = [self getErrorCodeForError:errorName];
        NSString *errorDesc = [errorDict objectForKey:@"error_description"];
        if(errorDesc == nil)
        {
            error = [OMObject createErrorWithCode:errorCode];
        }
        else
        {
            NSString *errorString = [errorDesc stringByRemovingPercentEncoding];
            if(code != -1)
                errorCode = code;
            errorString = [errorString
                           stringByReplacingOccurrencesOfString:@"+" withString:@" "];
            if([errorString isEqualToString:[OMObject
                                             messageForCode:OMERR_OAUTH_CLIENT_ASSERTION_REVOKED]])
            {
                errorCode = OMERR_OAUTH_CLIENT_ASSERTION_REVOKED;
            }
            error = [OMObject createErrorWithCode:errorCode
                                       andMessage:errorString];
        }

    }
    else if ([errorName isKindOfClass:[NSDictionary class]])
        {
            NSString *messgae = [errorName valueForKey:@"message"];
            
            if (messgae)
            {
                error = [OMObject createErrorWithCode:code
                                           andMessage:messgae];
            }
            
        }

    return error;
}

+ (NSUInteger)getErrorCodeForError:(NSString *)error
{
    if([error isEqualToString:OM_OAUTH_ERROR_INAVLID_REQUEST])
        return OMERR_OAUTH_INVALID_REQUEST;
    else if([error isEqualToString:OM_OAUTH_ERROR_UNAUTHORIZED_CLIENT])
        return OMERR_OAUTH_UNAUTHORIZED_CLIENT;
    else if([error isEqualToString:OM_OAUTH_ERROR_ACCESS_DENIED])
        return OMERR_OAUTH_ACCESS_DENIED;
    else if([error isEqualToString:OM_OAUTH_ERROR_UNSUPPORTED_RESPONSE])
        return OMERR_OAUTH_UNSUPPORTED_RESPONSE_TYPE;
    else if([error isEqualToString:OM_OAUTH_ERROR_SERVER_ERROR])
        return OMERR_OAUTH_SERVER_ERROR;
    else if([error isEqualToString:OM_OAUTH_ERROR_TEMPORARILY_UNAVAILABLE])
        return OMERR_OAUTH_TEMPORARILY_UNAVAILABLE;
    else if([error isEqualToString:OM_STATUS_DENIED])
        return OMERR_DENIED_ACTION;
    else if([error isEqualToString:OM_OAUTH_ERROR_TIMEOUT])
        return OMERR_AUTHENTICATION_TIMED_OUT;
    else if([error isEqualToString:OM_OAUTH_INVALID_SCOPE])
        return OMERR_OAUTH_INVALID_SCOPE;
    else
        return OMERR_OAUTH_OTHER_ERROR;
    return 0;
}

-(BOOL)isMaxRetryReached:(NSUInteger)maxRetry
{
    bool reached = false;
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [self.mss maxRetryKeyWithIdentityDomain:[self.authData
                                                valueForKey:OM_IDENTITY_DOMAIN]
                                                   username:[self.authData
                                                    valueForKey:OM_USERNAME]];
    NSUInteger storedCount = [defaults integerForKey:key];
    if (storedCount < maxRetry)
    {
        [defaults setInteger:storedCount+1 forKey:key];
    }
    else
    {
        [defaults setInteger:0 forKey:key];
        reached = true;
    }
    return reached;
}
- (BOOL)isMaxRetryReached:(NSInteger)previousFaliureCount maxRetryCount:
    (NSInteger)maxRetryCount
{
    if (!previousFaliureCount)
    {
        return NO;
    }
    BOOL reached = NO;
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [self.mss maxRetryKeyWithIdentityDomain:[self.authData
                                                valueForKey:OM_IDENTITY_DOMAIN]
                                                   username:[self.authData
                                                    valueForKey:OM_USERNAME]];
    NSInteger persistPreviousFaliureCount = [defaults integerForKey:key];
    NSInteger currentRetryCount = persistPreviousFaliureCount + 1;
    
    if (currentRetryCount >= maxRetryCount)
    {
        reached = YES;
        [defaults setInteger:0 forKey:key];
        [defaults synchronize];
    }
    else if(currentRetryCount > persistPreviousFaliureCount)
    {
        persistPreviousFaliureCount++;
        [defaults setInteger:persistPreviousFaliureCount forKey:key];
        [defaults synchronize];
    }
    
    return reached;
}

- (void)resetMaxRetryCount
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [self.mss maxRetryKeyWithIdentityDomain:[self.authData
                                                valueForKey:OM_IDENTITY_DOMAIN]
                                                   username:[self.authData
                                                valueForKey:OM_USERNAME]];
    [defaults setInteger:0 forKey:key];
    [defaults synchronize];
}

- (NSString *)maskPassword:(NSString *)password
{
    NSString *maskedPassword = nil;
    
    if ([password length])
    {
        maskedPassword = MASK_PASSWORD;
    }
  
    return maskedPassword;
}

- (NSString *)unMaskPassword:(NSString *)password
{
    if ([MASK_PASSWORD  isEqual:password])
    {
        password = [self retrieveRememberPassword];
    }
    return password;
}

@end
