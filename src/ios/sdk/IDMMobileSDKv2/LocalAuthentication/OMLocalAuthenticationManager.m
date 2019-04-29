/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMLocalAuthenticationManager.h"
#import "OMDataSerializationHelper.h"
#import "OMUtilities.h"
#import "OMAuthenticator.h"
#import "OMErrorCodes.h"
#import "OMDefinitions.h"
#import "OMObject.h"

static NSString *RegisteredAuthenticatorsFile = @"RegisteredAuthenticators";
static NSString *AuthenticatorsIdInfoFile = @"AuthenticatorsIdInfo";
static NSString *AuthIdList = @"authidlist";


@interface OMLocalAuthenticationManager()

@property(nonatomic, strong) NSMutableDictionary *registeredAuthenticators;
@property(nonatomic, strong) NSMutableDictionary *authenticatorIdInfo;
@property(nonatomic, strong) NSMutableDictionary *authenticator;
@property(nonatomic, strong) NSMutableArray *authIdList;

@end
@implementation OMLocalAuthenticationManager

+ (OMLocalAuthenticationManager *)sharedManager
{
    static OMLocalAuthenticationManager *kSharedManger = nil;
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        kSharedManger = [[self alloc] init];
    });
    
    return kSharedManger;
}

- (instancetype)init
{
    self = [super init];
    if (self)
    {
        [self initializeContainers];
        [self initalizeAuthenticator];
        _authIdList = [[[NSUserDefaults standardUserDefaults]
                        objectForKey:AuthIdList] mutableCopy];
        if (!_authIdList)
        {
           _authIdList = [NSMutableArray array];
        }
    }
    return self;
}

- (void)initalizeAuthenticator
{

    self.authenticator = [NSMutableDictionary dictionary];
    if ([self.registeredAuthenticators valueForKey:OM_PIN_AUTHENTICATOR])
    {
        [self registerAuthenticator:OM_PIN_AUTHENTICATOR
                          className:@"OMPinAuthenticator" error:nil];
    }
    
    if ([self.registeredAuthenticators valueForKey:OM_DEFAULT_AUTHENTICATOR])
    {
        [self registerAuthenticator:OM_DEFAULT_AUTHENTICATOR
                          className:@"OMDefaultAuthenticator" error:nil];

    }
}

- (void)initializeContainers
{
    NSString *filePath =  [OMUtilities filePathForfile:RegisteredAuthenticatorsFile inDirectory:
                                [OMUtilities localAuthDirectoryName] error:nil];
    
    if (filePath)
    {
        self.registeredAuthenticators = [[OMDataSerializationHelper
                                         deserializeDataFromFile:filePath] mutableCopy];
    }
    
    if(!self.registeredAuthenticators)
    {
        self.registeredAuthenticators = [NSMutableDictionary dictionary];
        
    }
    
    filePath = [OMUtilities filePathForfile:AuthenticatorsIdInfoFile inDirectory:[OMUtilities localAuthDirectoryName] error:nil];
    
    if (filePath)
    {
        self.authenticatorIdInfo = [[OMDataSerializationHelper
                                     deserializeDataFromFile:filePath] mutableCopy];
    }

    if(!self.authenticatorIdInfo)
    {
        self.authenticatorIdInfo = [NSMutableDictionary dictionary];
    }
}

- (BOOL)registerAuthenticator:(NSString*)authenticatorName
                   className:(NSString*)className error:(NSError **)error
{
    BOOL registered = NO;
    
    NSInteger errorCode = 0;
    
    if (authenticatorName == nil || className == nil)
    {
        errorCode = OMERR_INPUT_TEXT_CANNOT_BE_EMPTY;
    }
    
    if (!errorCode)
    {
        if ([self isAuthenticatorRegistered:authenticatorName])
        {
            errorCode = OMERR_AUTHENTICATOR_ALREADY_REGISTERED;

        }
        else
        {
            [self.registeredAuthenticators setObject:className forKey:authenticatorName];
            [self saveRegisteredAuthenticator];
            registered = YES;
        }

    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }
    
    return registered;
}

- (BOOL)unRegisterAuthenticator:(NSString*)authenticatorName error:(NSError **)error
{
    BOOL unregistered = NO;
    
    NSInteger errorCode = 0;
    
    if (authenticatorName == nil)
    {
        errorCode = OMERR_INPUT_TEXT_CANNOT_BE_EMPTY;
    }
    
    if (!errorCode)
    {
        if (![self.registeredAuthenticators valueForKey:authenticatorName])
        {
            errorCode = OMERR_AUTHENTICATOR_NOT_REGISTERED;
        }
        else
        {
            [self.registeredAuthenticators removeObjectForKey:authenticatorName];
            [self saveRegisteredAuthenticator];
            unregistered = YES;
        }
        
    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }
    
    return unregistered;
}

- (BOOL)enableAuthentication:(NSString*)authenticatorName instanceId:(NSString*)instanceId
                       error:(NSError **)error
{
    BOOL enabled = NO;
    
    NSInteger errorCode = 0;
    
    if (authenticatorName == nil || instanceId == nil)
    {
        errorCode = OMERR_INPUT_TEXT_CANNOT_BE_EMPTY;
    }
    
    if (!errorCode)
    {
        if ([self isAuthenticatorRegistered:authenticatorName])
        {
            AuthenticatorInstanceIdInfo *aiidInfo = [self.authenticatorIdInfo valueForKey:instanceId];
           
            //check if authenticator is already registred
            if (!(aiidInfo && NSOrderedSame != [aiidInfo.authenticatorName caseInsensitiveCompare:authenticatorName]))
            {
                //check if authenticator is already registred
                if ([self isAuthSchemaEnabled:instanceId])
                {
                    enabled = YES;
                }
                else
                {
                    AuthenticatorInstanceIdInfo *authInstanceId = [[AuthenticatorInstanceIdInfo alloc] initWithAuthenticatorName:authenticatorName enable:YES];
                    
                    self.authenticatorIdInfo[instanceId] = authInstanceId;
                    
                    [self saveAuthenticatorIdInfo];
                    
                    NSString *className = [self.registeredAuthenticators valueForKey:authInstanceId.authenticatorName];
                    
                    OMAuthenticator *authenticator = [self createAuthenticatorOfType:className
                                                                          instanceId:instanceId];
                    self.authenticator[instanceId] = authenticator;
                    enabled = YES;

                }
            }
        }
    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }
    
    return enabled;
}

- (BOOL)disableAuthentication:(NSString*)instanceId
                       error:(NSError **)error
{
    BOOL disabled = NO;
    NSInteger errorCode = 0;
    
    if (instanceId == nil)
    {
        errorCode = OMERR_INPUT_TEXT_CANNOT_BE_EMPTY;
    }
    
    if (!errorCode)
    {
        AuthenticatorInstanceIdInfo *authInstanceId = self.authenticatorIdInfo[instanceId];
        
        if (authInstanceId)
        {
            [self deleteAuthData:instanceId withError:error];
            if (error == NULL || !*error)
            {
                [self.authenticatorIdInfo[instanceId] setIsEnabled:NO];
                [self saveAuthenticatorIdInfo];
                [self.authenticator removeObjectForKey:instanceId];
                disabled = YES;

            }
        }
    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }

    return disabled;
}

- (void)deleteAuthData:(NSString*)instanceId withError:(NSError**)error
{
    OMAuthenticator * currentAuth = [self authenticatorForInstanceId:instanceId
                                                               error:error];
    [currentAuth deleteAuthData:error];
    
}

- (BOOL)isAuthenticatorRegistered:(NSString*)authenticatorName
{
    BOOL registered = NO;
    
    if (authenticatorName)
    {
       registered = ([self.registeredAuthenticators valueForKey:authenticatorName]
                                                            != nil) ? YES : NO;
        
    }
    return registered;
}

- (BOOL)isAuthenticatorClassRegistered:(NSString*)className
{
    BOOL registered = NO;
    
    if (className)
    {
        for (NSString *name in [self.registeredAuthenticators allValues])
        {
            if (NSOrderedSame == [name caseInsensitiveCompare:className])
            {
                registered = YES;
                break;
            }
        }
    }
    
    return registered;
}

#pragma mark -
#pragma mark praviate  methods -


- (BOOL)isAuthSchemaEnabled:(NSString*)instanceId
{
    BOOL enabled = NO;
    
    if (instanceId != nil && [instanceId length] > 0)
    {
        if ([self.authenticatorIdInfo valueForKey:instanceId])
        {
            enabled = [[self.authenticatorIdInfo valueForKey:instanceId]
                       isEnabled];

        }
    }
    
    return enabled;
}

- (NSString *)authenticationTypeForInstanceId:(NSString*)instanceId
{
    NSString *authType = nil;
    
    if (instanceId != nil && [instanceId length] > 0)
    {
        if ([self.authenticatorIdInfo valueForKey:instanceId])
        {
            authType = [[self.authenticatorIdInfo valueForKey:instanceId]
                        authenticatorName];
            
        }

    }

    return authType;
}

- (OMAuthenticator*)authenticatorForInstanceId:(NSString*)instanceId
                                         error:(NSError **)error
{
    NSInteger errorCode = 0;
    OMAuthenticator *currentAuthenticator = nil;
    
    if (instanceId)
    {
        
        if ([[self.authenticatorIdInfo valueForKey:instanceId] isEnabled])
        {
            if ([self.authenticator valueForKey:instanceId])
            {
                currentAuthenticator = [self.authenticator valueForKey:instanceId];
            }
            else
            {
                NSString *className = [self.registeredAuthenticators valueForKey:
                                    [[self.authenticatorIdInfo
                                      valueForKey:instanceId] authenticatorName]];

                OMAuthenticator *authenticator = [self createAuthenticatorOfType:
                                                className instanceId:instanceId];
                if (authenticator)
                {
                    self.authenticator[instanceId] = authenticator;
                    currentAuthenticator = authenticator;
                  
                    if ([authenticator isKindOfClass:
                         NSClassFromString(@"OMDefaultAuthenticator")] &&
                        ![authenticator isAuthenticated])
                    {
                        [authenticator authenticate:nil error:nil];
                    }
                }

            }
        }
        else
        {
            errorCode = OMERR_INPUT_TEXT_CANNOT_BE_EMPTY;
        }
        
    }
    
    if (errorCode && error)
    {
        *error = [OMObject createErrorWithCode:errorCode];
    }

    return currentAuthenticator;
}

- (OMAuthenticator *)createAuthenticatorOfType:(NSString*)type
                                    instanceId:(NSString*)instanceId
{
    
    OMAuthenticator *authenticator = [[NSClassFromString(type) alloc]
                                      initWithInstanceId:instanceId
                                                error:nil];
    
    return authenticator;
}
#pragma mark -

- (void)saveRegisteredAuthenticator
{
    NSString  *filePath = [self filePathForFileName:RegisteredAuthenticatorsFile];
    
    [OMDataSerializationHelper serializeData:self.registeredAuthenticators
                                      toFile:filePath];
    
}

- (void)saveAuthenticatorIdInfo
{
    NSString  *filePath = [self filePathForFileName:AuthenticatorsIdInfoFile];
    
    [OMDataSerializationHelper serializeData:self.authenticatorIdInfo toFile:filePath];

}

- (NSString *)filePathForFileName:(NSString*)fileName
{
    NSString *directoryPath = [self localAuthDirectoryPath];
    NSString *filePath = [directoryPath stringByAppendingPathComponent:fileName];
    
    return filePath;
}

- (NSString *)localAuthDirectoryPath
{
    @synchronized([NSFileManager class])
    {
        static NSString *localAuthDir = nil;
        
        if (!localAuthDir)
        {
            localAuthDir = [[OMUtilities omaDirectoryPath] stringByAppendingPathComponent:
                            [OMUtilities localAuthDirectoryName]];
            
            BOOL directoryCreated = NO;
            
            BOOL isExist =  [[NSFileManager defaultManager] fileExistsAtPath:localAuthDir
                                                                 isDirectory:&directoryCreated];
            
            if (!isExist)
            {
                [[NSFileManager defaultManager] createDirectoryAtPath:localAuthDir
                    withIntermediateDirectories:NO attributes:nil error:nil];
            }
            
        }
        
        return localAuthDir;
    }
}

- (void)addAuthKeyToList:(NSString*)key
{
    if (![self.authIdList containsObject:key])
    {
        [self.authIdList addObject:key];
        [[NSUserDefaults standardUserDefaults] setObject:self.authIdList
                                                  forKey:AuthIdList];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }

}

- (void)removeAuthKeyFromList:(NSString*)key
{
    if ([self.authIdList containsObject:key])
    {
        [self.authIdList removeObject:key];
        [[NSUserDefaults standardUserDefaults] setObject:self.authIdList
                                                  forKey:AuthIdList];
        [[NSUserDefaults standardUserDefaults] synchronize];
    }
}

- (BOOL)isAuthKeyEnabled:(NSString*)key
{
    return [self.authIdList containsObject:key];
}

@end


@implementation AuthenticatorInstanceIdInfo

 NSString  *kAuthenticatorNameKey = @"authenticatorName";
 NSString  *kisenabledKey = @"enable";

- (instancetype)initWithAuthenticatorName:(NSString *)authenticatorName
                                   enable:(BOOL)enable
{
    self = [super init];
    
    if (self)
    {
        _authenticatorName = authenticatorName;
        _isEnabled = enable;
    }
    
    return self;
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
    self = [super init];
    if (self)
    {
        _authenticatorName = [coder decodeObjectForKey:kAuthenticatorNameKey];
        _isEnabled = [coder decodeBoolForKey:kisenabledKey];

    }
    return self;
}

- (void)encodeWithCoder:(NSCoder *)enCoder
{
    
    [enCoder encodeObject:_authenticatorName forKey:kAuthenticatorNameKey];
    [enCoder encodeBool:_isEnabled forKey:kisenabledKey];

}

@end
