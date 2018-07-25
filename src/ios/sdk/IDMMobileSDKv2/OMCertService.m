/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMCertService.h"
#import "OMDefinitions.h"
#import "OMObject.h"
#import "OMErrorCodes.h"

@implementation OMCertService

+ (SecTrustResultType ) evaluateTrustResultForChallenge:
  (NSURLAuthenticationChallenge *) challenge withError:(OSStatus*)err
{
    
    // evaluate cert chain
    SecTrustRef trustRef = [[challenge protectionSpace]serverTrust];
    SecTrustResultType trustResult;
    NSArray *certs = [OMCertService allServerCertificates];
    *err =  SecTrustSetAnchorCertificates(trustRef, (CFArrayRef) certs);
    if(err)
    {
        OMDebugLog(@"Failed in setting anchor certificates");
    }
    SecTrustSetAnchorCertificatesOnly(trustRef, FALSE);
    
    
    *err = SecTrustEvaluate(trustRef,&trustResult);

    return trustResult;
}
///////////////////////////////////////////////////////////////////////////////
// Evaluate Server Trust challenge, throw alert to user if required
// and add certs to keychain
///////////////////////////////////////////////////////////////////////////////
+ (void) evaluateTrustAndRespondToChallenge:
(NSURLAuthenticationChallenge *) challenge
{
    OSStatus err;
    BOOL trusted = NO;
    
    // evaluate cert chain
    SecTrustRef trustRef = [[challenge protectionSpace]serverTrust];
    SecTrustResultType trustResult;
    NSArray *certs = [OMCertService allServerCertificates];
    err =  SecTrustSetAnchorCertificates(trustRef, (CFArrayRef) certs);
    if(err)
    {
        OMDebugLog(@"Failed in setting anchor certificates");
    }
    SecTrustSetAnchorCertificatesOnly(trustRef, FALSE);
    
    
    err = SecTrustEvaluate(trustRef,&trustResult);
    
    // cert chain invalid - alert user and get confirmation
    if ( err == noErr &&
        trustResult == kSecTrustResultRecoverableTrustFailure)
    {
        // human-readable summary of certificate
        NSString *certDesc;
        NSMutableDictionary *userInfo = nil;
        
        certDesc = [OMCertService certSummaryInTrust:trustRef];
        userInfo = [NSMutableDictionary dictionary];
        [userInfo setObject:challenge forKey:@"Challenge"];
        if (nil != certDesc)
            [userInfo setObject:certDesc forKey:@"CertDesc"];
        
        // prompt user
        [[NSNotificationCenter defaultCenter]
         postNotificationName:OM_NOTIFICATION_CERT_PROMPT
         object:nil
         userInfo:userInfo];
        return;
        
    }
    // cert chain ok
    else if ( err == noErr &&
             ((trustResult == kSecTrustResultProceed) ||
              (trustResult == kSecTrustResultUnspecified)))
    {
        trusted = YES;
    }
    // Failed: kSecTrustResultDeny, kSecTrustResultFatalTrustFailure,
    //         kSecTrustResultInvalid, kSecTrustResultOtherError
    //         kSecTrustResultConfirm - deprecated - iOS 7.0
    else
    {
        trusted = NO;
    }
    
    // add all certs
    if (trusted)
    {
        [[challenge sender]useCredential:
         [NSURLCredential credentialForTrust:trustRef]
              forAuthenticationChallenge:challenge];
        [[NSNotificationCenter defaultCenter]
         postNotificationName:OM_CHALLENGE_FINISHED
         object:nil];
        return;
    }
    // cancel or cert addition failed
    [[challenge sender]
     continueWithoutCredentialForAuthenticationChallenge:challenge];
    [[NSNotificationCenter defaultCenter]
     postNotificationName:OM_CHALLENGE_FINISHED
     object:nil];
}

///////////////////////////////////////////////////////////////////////////////
// Summary of certificate for showing in certificate alert to user
///////////////////////////////////////////////////////////////////////////////
+(NSString *) certSummaryInTrust:(SecTrustRef) trustRef
{
    NSString *certDesc = nil;
    CFIndex certCount = SecTrustGetCertificateCount(trustRef);
    
    if (certCount > 0)
    {
        // leaf cert
        SecCertificateRef leafCert = SecTrustGetCertificateAtIndex(trustRef, 0);
        CFStringRef summary = SecCertificateCopySubjectSummary(leafCert);
        if (nil != summary)
        {
            certDesc = [NSString stringWithString:(__bridge NSString *)summary];
            CFRelease(summary);
        }
    }
    return certDesc;
}

///////////////////////////////////////////////////////////////////////////////
// add all certs to keychain
///////////////////////////////////////////////////////////////////////////////
+(BOOL) addToKeyChainAllCertsInTrust:(SecTrustRef) trustRef
{
    CFIndex certCount = SecTrustGetCertificateCount(trustRef);
    int addedCertCount = 0 ;
    
    for (CFIndex i = 0; i < certCount; i++)
    {
        SecCertificateRef certRef = SecTrustGetCertificateAtIndex(trustRef, i);
        if (![OMCertService importServerCertificateFromRef:certRef error:nil])
        {
            return FALSE;
        }
        addedCertCount++;
    }
    // did we add any certs
    return (addedCertCount > 0);
}

+(BOOL) addLeafCertificateFromTrust:(SecTrustRef) trustRef
{
    CFIndex certCount = SecTrustGetCertificateCount(trustRef);
    if (certCount)
    {
        SecCertificateRef leaf = SecTrustGetCertificateAtIndex(trustRef, 0);
        return [OMCertService importServerCertificateFromRef:leaf error:nil];
    }
    return FALSE;
    
}

///////////////////////////////////////////////////////////////////////////////
// Retrurns all the certificates in keychain
///////////////////////////////////////////////////////////////////////////////
+(NSArray *) allServerCertificates
{
    
    NSMutableArray *certs = nil;
    NSDictionary *query = @{
                            (id)kSecClass            : (id)kSecClassCertificate,
                            (id)kSecReturnRef        : (id)kCFBooleanTrue,
                            (id)kSecReturnAttributes : (id)kCFBooleanTrue,
                            (id)kSecMatchLimit       : (id)kSecMatchLimitAll
                            };
    CFTypeRef results;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &results);
    if (status == errSecSuccess && results != NULL)
    {
        certs = [[NSMutableArray alloc]init];
        for (NSDictionary *result in (__bridge NSArray *)results)
        {
            [certs addObject:[result valueForKey:(id)kSecValueRef]];
        }
        CFRelease(results);
    }
    /*
     * An identity is comprise of a Certificate and Private key.
     * The above query returns client and server certs
     * We need to filter out the client certs, so that they are not deleted
     */
    NSArray *identities = [OMCertService allClientIdentities];
    for (id identity in identities)
    {
        SecCertificateRef certRef = nil;
        SecIdentityCopyCertificate((SecIdentityRef)identity, &certRef);
        NSUInteger index = [certs indexOfObject:(__bridge id)certRef];
        if (index != NSNotFound)
        {
            [certs removeObjectAtIndex:index];
        }
    }
    return certs.count?certs:nil;
}

///////////////////////////////////////////////////////////////////////////////
// Read certificate from file path and add it to keychain
///////////////////////////////////////////////////////////////////////////////
+(BOOL) importServerCertificateFromFilePath:(NSURL *)filePath
                                      error:(NSError **)error
{
    if ((!filePath || !CFURLResourceIsReachable((__bridge CFURLRef)filePath, nil)) &&
                                                                        error)
    {
            *error = [OMObject createErrorWithCode:OMERR_RESOURCE_FILE_PATH];
    }
    else
    {
        NSData *certData = [NSData dataWithContentsOfURL:filePath];
        SecCertificateRef certRef = SecCertificateCreateWithData(NULL,
                                                                 (CFDataRef)
                                                                 certData);
        BOOL result = false;
        if (certRef)
        {
            result = [OMCertService importServerCertificateFromRef:certRef
                                                             error:error];
            CFRelease(certRef);
        }
        
        [OMCertService infoForCertificate:certRef];
        return result;
    }
    if (error)
    {
        *error = [OMObject createErrorWithCode:OMERR_RESOURCE_FILE_PATH];
    }
    return FALSE;
}

///////////////////////////////////////////////////////////////////////////////
// add single certificate to keychain
///////////////////////////////////////////////////////////////////////////////
+(BOOL) importServerCertificateFromRef:(SecCertificateRef)certificate
                                    error:(NSError **)error
{
    if (certificate!=NULL)
    {
        OSStatus err = SecItemAdd((CFDictionaryRef)
                                  [NSDictionary
                                   dictionaryWithObjectsAndKeys:
                                   (id) kSecClassCertificate, kSecClass,
                                   (__bridge id) certificate, kSecValueRef,
                                   (id) kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                   kSecAttrAccessible, nil],
                                  NULL);
        if (err == errSecSuccess || err == errSecDuplicateItem)
        {
            return TRUE;
        }
        if (error)
        {
            if (err == errSecDecode)
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_INVALID_INPUT];
            }
            else if(err == errSecAllocate)
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_MEMORY_ALLOCATION_FAILURE];
            }
            else
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_KEYCHAIN_SYSTEM_ERROR, err];
            }
        }
    }
    if (error)
    {
        *error = [OMObject createErrorWithCode:OMERR_INVALID_INPUT];
    }
    return FALSE;
}

+(NSArray *) importClientCertificateFromFile:(NSURL *)fileURL
                                    password:(NSString *)password
                                       error:(NSError **)error
{
    NSError *localErr = nil;
    NSArray *identities = [OMCertService identitiesFromFile:fileURL
                                               withPassword:password
                                                      error:&localErr];
    if (error && localErr)
    {
        *error = localErr;
    }
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *key = [NSString stringWithFormat:@"%@_%@",
                     OM_CERT_IMPORT_RETRY,fileURL.path];
    if (![identities count])
    {
        int retryCount = [[defaults valueForKey:key] intValue];
        if (retryCount < 2 && localErr.code == OMERR_INVALID_PASSWORD)
        {
            [defaults setValue:[NSNumber numberWithInt:++retryCount]
                        forKey:key];
        }
        else
        {
            [defaults removeObjectForKey:key];
            [OMCertService deleteFile:fileURL error:nil];
        }
        return nil;
    }
    [defaults removeObjectForKey:key];
    [OMCertService deleteFile:fileURL error:nil];
    NSMutableArray *certInfoList = [NSMutableArray array];
    for (id identity in identities)
    {
        if ([OMCertService importClientCertificate:(SecIdentityRef)identity
                                             error:error])
        {
            [certInfoList addObject:[OMCertService infoForClientCertificate:
                                     (SecIdentityRef)identity]];
        }
    }
    return [certInfoList count]?certInfoList:nil;
}

+(BOOL) importClientCertificate:(SecIdentityRef)identity error:(NSError **)error
{
    if (identity != NULL)
    {
        OSStatus err = SecItemAdd((CFDictionaryRef)
                                  [NSDictionary
                                   dictionaryWithObjectsAndKeys:
                                   (__bridge id) identity, kSecValueRef,
                                   (id) kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                   kSecAttrAccessible,
                                   nil],
                                  NULL);
        
        if (err == errSecSuccess || err == errSecDuplicateItem)
        {
            return true;
        }
        if (error)
        {
            if (err == errSecDecode)
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_INVALID_INPUT];
            }
            else if(err == errSecAllocate)
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_MEMORY_ALLOCATION_FAILURE];
            }
            else
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_KEYCHAIN_SYSTEM_ERROR, err];
            }
        }
    }
    if (error)
    {
        *error = [OMObject createErrorWithCode:OMERR_INVALID_INPUT];
    }
    return FALSE;
}

+(NSArray *) identitiesFromFile:(NSURL *)fileURL
                   withPassword:(NSString *)password
                          error:(NSError **)error
{
    NSMutableArray *identities = nil;
    if ((!fileURL || !CFURLResourceIsReachable((__bridge CFURLRef)fileURL, NULL))
        && error)
    {
            *error = [OMObject createErrorWithCode:OMERR_RESOURCE_FILE_PATH];
    }
    else
    {
        CFStringRef passRef = CFStringCreateWithCString(NULL,
                                                        password.UTF8String,
                                                        kCFStringEncodingUTF8);
        const void *keys[] = {kSecImportExportPassphrase};
        const void *values[] = {passRef};
        CFDictionaryRef optionsDictionary =
        CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, NULL,
                           NULL);
        NSData *fileData = [NSData dataWithContentsOfURL:fileURL];
        CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
        OSStatus status = SecPKCS12Import((CFDataRef)fileData,
                                          optionsDictionary,
                                          &items);
        if (passRef)
        {
            CFRelease(passRef);
        }
        CFRelease(optionsDictionary);
        if (status == errSecSuccess)
        {
            long certEntries = CFArrayGetCount(items);
            if (certEntries)
            {
                identities = [[NSMutableArray alloc] init];
            }
            else if(error)
            {
                *error = [OMObject createErrorWithCode:OMERR_NO_IDENTITY];
            }
            for (int i = 0; i < certEntries; i++)
            {
                CFDictionaryRef certItem = CFArrayGetValueAtIndex(items, i);
                SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue
                                            (certItem, kSecImportItemIdentity);
                [identities addObject:(__bridge id)identity];
            }
        }
        else if (status == errSecDecode && error)
        {
            *error = [OMObject createErrorWithCode:OMERR_INVALID_INPUT];
        }
        else if(status == errSecAuthFailed && error)
        {
            *error = [OMObject createErrorWithCode:OMERR_INVALID_PASSWORD];
        }
        if (items)
        {
            CFRelease(items);
        }
    }
    
    return identities;
}

+(NSArray *)allClientIdentities
{
    NSMutableArray *identities = nil;
    NSDictionary *query = @{
                            (id)kSecClass               : (id)kSecClassIdentity,
                            (id)kSecReturnRef           : (id)kCFBooleanTrue,
                            (id)kSecReturnAttributes    : (id)kCFBooleanTrue,
                            (id)kSecMatchLimit          : (id)kSecMatchLimitAll
                            };
    CFTypeRef results;
    OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &results);
    if (status == errSecSuccess && results != NULL)
    {
        identities = [[NSMutableArray alloc] init];
        for (NSDictionary *result in (__bridge NSArray *)results)
        {
            [identities addObject:[result valueForKey:(id)kSecValueRef]];
        }
        CFRelease(results);
    }
    return identities;
}

+ (NSMutableArray *)getCertInfoForIdentities:(NSArray *)clientIdenties
{
    NSMutableArray *certInfoList = [NSMutableArray array];
    
    
    for (id identity in clientIdenties)
    {
        OMCertInfo *certInfo = [self infoForClientCertificate:
                                (__bridge SecIdentityRef)(identity)];
        
        if (certInfo) {
            [certInfoList addObject:certInfo];
        }
    }
    return certInfoList;
}

+(BOOL)isClientIdentityInstalled
{
    return [[OMCertService allClientIdentities] count]?true:false;
}

+(int) clearAllServerCertificates:(NSError **)error
{
    NSArray *certificates = [OMCertService allServerCertificates];
    int count = 0;
    for (id cert in certificates)
    {
        NSDictionary *query = @{
                                (id)kSecValueRef : cert,
                                };
        OSStatus err = SecItemDelete((CFDictionaryRef)query);
        if (err == errSecSuccess)
        {
            count ++;
        }
        else if(error)
        {
            *error = [OMObject createErrorWithCode:OMERR_KEYCHAIN_SYSTEM_ERROR,
                      err];
        }
    }
    return count;
}

+(int) clearAllClientCertificates:(NSError **)error
{
    NSArray *identities = [OMCertService allClientIdentities];
    int count = 0;
    for (id identity in identities)
    {
        NSDictionary *query = @{
                                (id)kSecValueRef : identity,
                                };
        OSStatus err = SecItemDelete((CFDictionaryRef)query);
        if (err == errSecSuccess)
        {
            count ++;
        }
        else if(error)
        {
            *error = [OMObject createErrorWithCode:OMERR_KEYCHAIN_SYSTEM_ERROR,
                      err];
        }
    }
    return count;
}


+(BOOL)deleteFile:(NSURL *)file error:(NSError **)error;
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    
    BOOL x =  [fileManager removeItemAtPath:file.path error:error];
    return x;
}

+(NSDate *)dateFromOpenSSLCharArray:(char *)array ofLength:(int)length
{
    NSString *dateFormat = @"yyMMddHHmmssZ";
    if (length < dateFormat.length)
    {
        return nil;
    }
    char nilTerminatedArray[[dateFormat length] + 1];
    strncpy(nilTerminatedArray, array, [dateFormat length]);
    nilTerminatedArray[[dateFormat length]] = '\0';
    NSString *dateString = [NSString stringWithCString:nilTerminatedArray
                                              encoding:NSASCIIStringEncoding];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:dateFormat];
    return [dateFormatter dateFromString:dateString];
}

+(NSDictionary *)parseDnNameArray:(char *)array
{
    NSString *str = [NSString stringWithCString:array
                                       encoding:NSUTF8StringEncoding];
    NSArray *components = [str componentsSeparatedByString:@"/"];
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
    for (NSString *field in components)
    {
        NSArray *arr = [field componentsSeparatedByString:@"="];
        if ([arr count]!= 2)
        {
            continue;
        }
        [dict setValue:arr[1] forKey:arr[0]];
    }
    if ([dict count])
    {
        return dict;
    }
    return nil;
}

+(OMCertInfo *)infoForCertificate:(SecCertificateRef)cert
{
    if (!cert)
    {
        return nil;
    }
    
    CFDataRef certDataRef = SecCertificateCopyData(cert);
    long certLen = CFDataGetLength(certDataRef);
    NSData *d = [NSData dataWithData:(__bridge NSData *)certDataRef];
    const unsigned char *x509Data = [d bytes];
    NSMutableString *certHex = [NSMutableString string];
    for (int i = 0 ; i < certLen; i++)
    {
        [certHex appendString:[NSString stringWithFormat:@"%02X",x509Data[i]]];
    }
    OMCertInfo *certInfo = [[OMCertInfo alloc] initWithCertHex:certHex];
    return certInfo;
}

+(OMCertInfo *)infoForServerTrustRef:(SecTrustRef)secTrustRef
{
    OMCertInfo *info = nil;
    
    CFIndex certCount = SecTrustGetCertificateCount(secTrustRef);
    
    if (certCount > 0)
    {
        // leaf cert
        SecCertificateRef certRef = SecTrustGetCertificateAtIndex(secTrustRef, 0);
        
        if (certRef)
        {
            info = [OMCertService infoForCertificate:certRef];
        }

    }
    return info;
}
+(OMCertInfo *)infoForClientCertificate:(SecIdentityRef)identity
{
    if (!identity)
    {
        return nil;
    }
    SecCertificateRef certRef = nil;
    SecIdentityCopyCertificate(identity, &certRef);
    if (certRef)
    {
        OMCertInfo *info = [OMCertService infoForCertificate:certRef];
        CFRelease(certRef);
        return info;
    }
    return nil;
}

+(void)persistClientCertChallengeReceivedForHost:(NSString *)host
                                            port:(NSInteger)port
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:@"TRUE" forKey:[NSString
                                        stringWithFormat:@"%@%ld",host,
                                                                (long)port]];
}

+(BOOL)wasClientCertChallengeReceivedPreviouslyForHost:(NSString *)host
                                                  port:(NSInteger)port
{
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *status = [defaults valueForKey:
                        [NSString stringWithFormat:@"%@%ld",host,(long)port]];
    return [status boolValue];
}

+(NSArray *)infoForAllClientCertificates
{
    NSArray *identities = [OMCertService allClientIdentities];
    NSMutableArray *infoList = [NSMutableArray array];
    for (id identity in identities)
    {
        [infoList addObject:[OMCertService infoForClientCertificate:
                             (SecIdentityRef)identity]];
    }
    return [infoList count]?infoList:nil;
}

+(BOOL)deleteClientCertificate:(OMCertInfo *)certInfo error:(NSError **)error
{
    NSArray *identities = [OMCertService allClientIdentities];
    for (id identity in identities)
    {
        OMCertInfo *info = [OMCertService
                            infoForClientCertificate:(SecIdentityRef)identity];
        if ([info isEqual:certInfo])
        {
            NSDictionary *query = @{
                                    (id)kSecValueRef : identity,
                                    };
            OSStatus err = SecItemDelete((CFDictionaryRef)query);
            if (err == errSecSuccess)
            {
                return true;
            }
            else if(error)
            {
                *error = [OMObject
                          createErrorWithCode:OMERR_KEYCHAIN_SYSTEM_ERROR, err];
                return false;
            }
        }
    }
    return false;
}

+(NSArray *)listOfConnectedCertsFor:(SecCertificateRef)cert
{
    NSArray *allCerts = [OMCertService allServerCertificates];
    
    NSMutableArray *connected = [NSMutableArray array];
    BOOL found = false;
    do
    {
        found = false;
        OMCertInfo *child = [OMCertService infoForCertificate:cert];
        for (id certObj in allCerts)
        {
            OMCertInfo *parent = [OMCertService
                                  infoForCertificate:(SecCertificateRef)
                                  certObj];
            if ([child.issuer isEqualToString:parent.commonName])
            {
                if (![connected containsObject:certObj])
                {
                    [connected addObject:certObj];
                    cert = (__bridge SecCertificateRef)certObj;
                    found = true;
                }
                break;
            }
        }
    } while (found);
    return connected.count?connected:nil;
}


+ (NSURLCredential *)getCretCredentialForIdentity:(SecIdentityRef)identityRef
{
    SecCertificateRef cert = nil;
    SecIdentityCopyCertificate(identityRef, &cert);
    NSArray *serverCerts = [OMCertService listOfConnectedCertsFor:cert];
    CFRelease(cert);
    NSURLCredential *clientCert = [NSURLCredential
                                   credentialWithIdentity:identityRef
                                   certificates:serverCerts
                                   persistence:
                                   NSURLCredentialPersistenceForSession];
    return clientCert;
}
@end
