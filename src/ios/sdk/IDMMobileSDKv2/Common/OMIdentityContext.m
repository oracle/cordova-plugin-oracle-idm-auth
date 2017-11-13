/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMIdentityContext.h"
#import "UIKit/UIDevice.h"
#import "OMDefinitions.h"
#import "OMCryptoService.h"

// For sysctl() calls
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#import "libkern/OSAtomic.h"
#import "OMCredentialStore.h"
#import "OMReachability.h"]
#import "OMCredential.h"

#define IFT_ETHER 0x6

///////////////////////////////////////////////////////////////////////////////
// Extensions to declare private methods & properties
///////////////////////////////////////////////////////////////////////////////
@interface OMIdentityContext()

@property (nonatomic, retain) NSMutableDictionary *deviceClaims;

- (void)computeClientInformation;
- (void)computeOperatingSystemInformation;
- (void)computeDeviceInformation;
- (void)computeHardwareInformation;
- (void)computeNetworkInformation;
- (void)computeLocaleInformation;
- (void)computeLocationInformation;
- (NSString *)getIPAddress;
- (NSDictionary *)computeClaims;
char*  getMacAddress(char* macAddress, char* ifName);

@end

static OMIdentityContext *singletonInstance = nil;
///////////////////////////////////////////////////////////////////////////////
// OMIdentityContext Implementation File
///////////////////////////////////////////////////////////////////////////////
@implementation OMIdentityContext


#pragma mark -
#pragma mark Memory Management Methods & Init Methods

+ (OMIdentityContext *)sharedInstance
{
    static dispatch_once_t once;
    dispatch_once(&once, ^ { singletonInstance = [[super allocWithZone:NULL] init];} );
    return singletonInstance;
}

+ (id)allocWithZone:(NSZone*)zone
{
    return [self sharedInstance] ;
}

- (id)copyWithZone:(NSZone *)zone
{
    return self;
}

- (id)init
{
    self = [super init];
    
    if (self)
    {
        _deviceClaims = [[NSMutableDictionary alloc] init];
    }
    
    return self;
}

#pragma mark -
#pragma mark device fingerprint compute methods
///////////////////////////////////////////////////////////////////////////////
// getDeviceCliams
///////////////////////////////////////////////////////////////////////////////
- (NSDictionary *)deviceClaims:(NSArray*) claimAttributes
{
    // Only populate device unique id for the benefit of HTTP basic auth
    if (  claimAttributes != nil &&
        [[claimAttributes objectAtIndex:0] isEqualToString:OM_DEVICE_UNIQUE_ID])
    {
        [self computeDeviceInformation];
        return self.deviceClaims;
    }
    
    // calculate all claims
    // deviceClaims can be partially populated. The max partial count is 5.
    if ([self.deviceClaims count] < 7)
    {
        [self computeClaims];
    }
    else
    {
        // Refreshed geographic location details everytime
        //[self computeLocationInformation];
    }
    
    return self.deviceClaims;
}

- (void) refresh
{
    [self computeClaims];
}

///////////////////////////////////////////////////////////////////////////////
// claimsURLForApplicationID
///////////////////////////////////////////////////////////////////////////////
- (NSString *)claimsURLForApplicationID: (NSString *)applicationID
                          serviceDomain: (NSString *)domain
                                 oicURL: (NSString *)oicURL
{
    // only populate what we need
    [self computeClientInformation];
    [self computeOperatingSystemInformation];
    
    NSString *url = [NSString stringWithFormat:@"%@%@%@?osType=%@&osVer=%@&clientSDKVersion=%@&serviceDomain=%@",
                     oicURL,
                     OM_APP_PROFILE,
                     applicationID,
                     [self.deviceClaims valueForKey:OM_OS_TYPE],
                     [self.deviceClaims valueForKey:OM_OS_VERSION],
                     [self.deviceClaims valueForKey:OM_CLIENT_SDK_VERSION],
                     domain];
    return [url stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
}

///////////////////////////////////////////////////////////////////////////////
// computeClaims
///////////////////////////////////////////////////////////////////////////////
- (NSDictionary *)computeClaims
{
    OMDebugLog("Computing claims...");
    //Client SDK Name and Version Details
    [self computeClientInformation];
    
    //OS Details - Name and Version
    [self computeOperatingSystemInformation];
    
    //Device name, type, unique id, type, orientation details and etc
    [self computeDeviceInformation];
    
    //CPU Frequency, Physical memory size, page size and etc
    //[self computeHardwareInformation];
    
    //MAC Address
    [self computeNetworkInformation];
    
    //Get Locale Details - Language, time preference details
    [self computeLocaleInformation];
    
    //Geographic location details
    //[self computeLocationInformation];
    
    //There are some attributes for which we do not have a way to compute
    //Hence for now hardcode them so that it is known to everyone that it
    //is yet to be added
    
    NSString *unknown = [[NSString alloc] initWithString:@"UNKNOWN"];
    [self.deviceClaims setValue:unknown forKey:OM_PHONENUM];
    [self.deviceClaims setValue:unknown forKey:OM_PHONECARRIER_NAME];
    [self.deviceClaims setValue:unknown forKey:OM_IMEI];
    NSNumber *number = [[NSNumber alloc]initWithBool:FALSE];
    [self.deviceClaims setObject:number forKey:OM_ISVPNENABLED];
    
    OMDebugLog(@"Computed device cliams. Claims Details %@", self.deviceClaims);
    return self.deviceClaims;
}

///////////////////////////////////////////////////////////////////////////////
// policies
///////////////////////////////////////////////////////////////////////////////
- (BOOL)evaluatePolicy:(NSDictionary*)policies
{
    return YES;
}


///////////////////////////////////////////////////////////////////////////////
- (NSDictionary *)getJSONDictionaryForAuthentication:(NSDictionary *)jailBreakDetectionPolicy
{
    // calculate all claims
    // deviceClaims can be partially populated. The max partial count is 6.
    if ([self.deviceClaims count] < 7)
    {
        [self computeClaims];
    }
    else
    {
        // Refreshed geographic location details everytime
//        [self computeLocationInformation];
    }
    
    NSMutableDictionary *deviceProfile = [[NSMutableDictionary alloc] init];
    NSMutableDictionary *hardwareIds = [[NSMutableDictionary alloc] init];
    BOOL isJailBrokenDetectionEnabled = FALSE;
    
    NSMutableDictionary *hardwareIDAttributesDict = [[NSMutableDictionary alloc]init];
    [hardwareIDAttributesDict setValue:OM_PHONENUM forKey:OM_PHONENUM];
    [hardwareIDAttributesDict setValue:OM_IMEI forKey:OM_IMEI];
    [hardwareIDAttributesDict setValue:OM_MACADDR forKey:OM_MACADDR];
    [hardwareIDAttributesDict setValue:OM_DEVICE_UNIQUE_ID forKey:OM_DEVICE_UNIQUE_ID];
    [hardwareIDAttributesDict setValue:OM_VENDOR_ID forKey:OM_VENDOR_ID];
    [hardwareIDAttributesDict setValue:OM_ADVERTISMENT_ID
                                forKey:OM_ADVERTISMENT_ID];
    
    for (int i = 0; i < [self.identityContextClaims count]; i++)
    {
        NSString *attr = [self.identityContextClaims objectAtIndex:i];
        if (NSOrderedSame == [attr compare:OM_ISJAILBROKEN])
        {
            isJailBrokenDetectionEnabled = TRUE;
            continue;
        }
        if ([hardwareIDAttributesDict valueForKey:attr] != nil)
        {
            [hardwareIds setValue:[self.deviceClaims valueForKey:attr]
                           forKey:attr];
        }
        else
        {
            [deviceProfile setValue:[self.deviceClaims valueForKey:attr]
                             forKey:attr];
        }
    }
    
    [deviceProfile setValue:hardwareIds forKey:OM_HARDWAREIDS];
    if (isJailBrokenDetectionEnabled)
    {
        BOOL isJailBroken = false;
        if (jailBreakDetectionPolicy != nil)
        {
            NSArray *detectionLocation = [jailBreakDetectionPolicy valueForKey:OM_DETECTION_LOCATION];
            if (detectionLocation != nil)
            {
                for (int i = 0; i < [detectionLocation count]; i++)
                {
                    NSDictionary *location = [detectionLocation objectAtIndex:i];
                    NSString *filePath = [location valueForKey:OM_FILE_PATH];
                    if (filePath != nil)
                    {
                        if ([[NSFileManager defaultManager] fileExistsAtPath:filePath])
                        {
                            isJailBroken = true;
                            break;
                        }
                    }
                }
            }
        }
        [deviceProfile setObject:[NSNumber numberWithBool:isJailBroken] forKey:OM_ISJAILBROKEN];
    }
    OMDebugLog(@"Device registration JSON Dictionary : %@", deviceProfile);
    return deviceProfile;
}

///////////////////////////////////////////////////////////////////////////////
// computeClientInformations
///////////////////////////////////////////////////////////////////////////////
- (void)computeClientInformation
{
    [self.deviceClaims setValue:OM_CLIENT_SDK_NAME_VALUE
                         forKey:OM_CLIENT_SDK_NAME];
    [self.deviceClaims setValue:OM_CLIENT_SDK_VERSION_VALUE
                         forKey:OM_CLIENT_SDK_VERSION];
}

///////////////////////////////////////////////////////////////////////////////
// computeOperatingSystemInformation
///////////////////////////////////////////////////////////////////////////////
- (void)computeOperatingSystemInformation
{
    UIDevice *device = [UIDevice currentDevice];
    [self.deviceClaims setValue:device.systemName forKey:OM_OS_TYPE];
    [self.deviceClaims setValue:device.systemVersion forKey:OM_OS_VERSION];
}

///////////////////////////////////////////////////////////////////////////////
// computeDeviceInforamation
///////////////////////////////////////////////////////////////////////////////
- (void)computeDeviceInformation
{
    /* Apple has deprecated usage of UDID. So, we cannot use the
     device UDID as it is */
    
    /*[self.deviceClaims setValue:[[UIDevice currentDevice]uniqueIdentifier]
     forKey:OM_DEVICE_UNIQUE_ID];*/
    
    
    /* Create and persist app specific UUID and use that as UDID
     in device profile */
    
    OMCredentialStore *credStore = [[OMCredentialStore alloc]init];
    NSString *uuidKey = [[NSString alloc]initWithFormat:@"%@-uuid", self.applicationID];
    NSString *uuid = [[[credStore getCredential:uuidKey] properties]
                      valueForKey:uuidKey];
    if (uuid == nil)
    {
        uuid = [[[UIDevice currentDevice]
                        identifierForVendor] UUIDString];
        OMCredential *cred = [[OMCredential alloc] init];
        cred.properties = @{uuidKey: uuid};
        [credStore saveCredential:cred forKey:uuidKey];
    
    }
    
    [self.deviceClaims setValue:uuid forKey:OM_DEVICE_UNIQUE_ID];
    
    // finger print is SHA256 of unique identifier
    NSError *cryptoError;
    NSString *fingerprint = [OMCryptoService hashData:[uuid
                                                       dataUsingEncoding:
                                                       NSUTF8StringEncoding]
                                             withSalt:nil
                                            algorithm:OMAlgorithmSHA256
                                   appendSaltToOutput:NO
                                         base64Encode:YES
                        prefixOutputWithAlgorithmName:NO
                                             outError:&cryptoError];
    
    if (fingerprint != nil)
        [self.deviceClaims setObject:fingerprint forKey:OM_FINGERPRINT];
    else
        OMLogError(cryptoError);
    
    [self.deviceClaims setObject:uuid forKey:OM_VENDOR_ID];
    /* Not setting Advertisment ID as apple can reject apps using this property
     */
}

///////////////////////////////////////////////////////////////////////////////
// computeHardwareInformation
///////////////////////////////////////////////////////////////////////////////
- (void)computeHardwareInformation
{
    NSString *tempStr = nil;
    
    size_t resultLen = 0;
    int result = 0;
    int mib[3] = {0};
    struct utsname sysInfo;
    
    // Hardware Properties
    mib[0] = CTL_HW;
    resultLen = sizeof(result);
    
    // Page Size
    mib[1] = HW_PAGESIZE;
    if (sysctl(mib, 2, &result, &resultLen, NULL, 0) == 0)
    {
        tempStr = [[NSString alloc] initWithFormat:@"%d", result];
        if (self.identityContextClaims == nil ||
            [self.identityContextClaims containsObject:OM_HARDWARE_PAGE_SIZE])
        {
            [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_PAGE_SIZE];
        }
    }
    
    // Physical Memory Size
    mib[1] = HW_PHYSMEM;
    if (sysctl(mib, 2, &result, &resultLen, NULL, 0) == 0)
    {
        tempStr = [[NSString alloc] initWithFormat:@"%d", result];
        if (self.identityContextClaims == nil ||
            [self.identityContextClaims containsObject:OM_HARDWARE_PHYSICAL_MEMORY])
        {
            [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_PHYSICAL_MEMORY];
        }
    }
    
    // CPU Frequency
    mib[1] = HW_CPU_FREQ;
    if (sysctl(mib, 2, &result, &resultLen, NULL, 0) == 0)
    {
        tempStr = [[NSString alloc] initWithFormat:@"%d", result];
        if (self.identityContextClaims == nil ||
            [self.identityContextClaims containsObject:OM_HARDWARE_CPU_FREQ])
        {
            [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_CPU_FREQ];
        }
    }
    
    // Bus Frequency
    mib[1] = HW_BUS_FREQ;
    if (sysctl(mib, 2, &result, &resultLen, NULL, 0) == 0)
    {
        tempStr = [[NSString alloc] initWithFormat:@"%d", result];
        if (self.identityContextClaims == nil ||
            [self.identityContextClaims containsObject:OM_HARDWARE_BUS_FREQ])
        {
            [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_BUS_FREQ];
        }
    }
    
    // System Name
    uname(&sysInfo);
    tempStr = [[NSString alloc] initWithFormat:@"%s",sysInfo.sysname];
    [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_SYSTEM];
    
    // Node Name
    tempStr = [[NSString alloc] initWithFormat:@"%s",sysInfo.nodename];
    [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_NODE];
    
    // Release
    tempStr = [[NSString alloc] initWithFormat:@"%s",sysInfo.release];
    [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_RELEASE];
    
    // Version
    tempStr = [[NSString alloc] initWithFormat:@"%s",sysInfo.version];
    [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_VERSION];
    
    // Machine
    tempStr = [[NSString alloc] initWithFormat:@"%s",sysInfo.machine];
    [self.deviceClaims setObject:tempStr forKey:OM_HARDWARE_MACHINE];
    
}

///////////////////////////////////////////////////////////////////////////////
// getMacAddress
///////////////////////////////////////////////////////////////////////////////
char*  getMacAddress(char* macAddress, char* ifName)
{
    
    int  success;
    struct ifaddrs * addrs;
    struct ifaddrs * cursor;
    const struct sockaddr_dl * dlAddr;
    const unsigned char* base;
    int i;
    
    success = getifaddrs(&addrs) == 0;
    if (success)
    {
        cursor = addrs;
        while (cursor != 0)
        {
            if ( (cursor->ifa_addr->sa_family == AF_LINK)
                && (((const struct sockaddr_dl *) cursor->ifa_addr)->sdl_type == IFT_ETHER) && strcmp(ifName,  cursor->ifa_name)==0 )
            {
                dlAddr = (const struct sockaddr_dl *) cursor->ifa_addr;
                base = (const unsigned char*) &dlAddr->sdl_data[dlAddr->sdl_nlen];
                strcpy(macAddress, "");
                for (i = 0; i < dlAddr->sdl_alen; i++)
                {
                    if (i != 0)
                    {
                        strcat(macAddress, ":");
                    }
                    char partialAddr[3];
                    sprintf(partialAddr, "%02X", base[i]);
                    strcat(macAddress, partialAddr);
                    
                }
            }
            cursor = cursor->ifa_next;
        }
        
        freeifaddrs(addrs);
    }
    return macAddress;
}

- (NSString *)getIPAddress
{
    NSString *address = nil;
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    
    // retrieve the current interfaces - returns 0 on success
    success = getifaddrs(&interfaces);
    if (success == 0)
    {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while(temp_addr != NULL)
        {
            if(temp_addr->ifa_addr->sa_family == AF_INET)
            {
                // Check if interface is en0 which is the wifi connection on the iPhone
                if([[NSString stringWithUTF8String:temp_addr->ifa_name] isEqualToString:@"en0"])
                {
                    // Get NSString from C String
                    address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                }
            }
            
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    // Free memory
    freeifaddrs(interfaces);
    
    return address;
}

///////////////////////////////////////////////////////////////////////////////
// computeNetworkInformation
///////////////////////////////////////////////////////////////////////////////
- (void)computeNetworkInformation
{
    char* macAddressString= (char*)malloc(18);
    NSString* macAddress= [[NSString alloc] initWithCString:getMacAddress(macAddressString,"en0")
                                                   encoding:NSMacOSRomanStringEncoding];
    free(macAddressString);
    if( macAddress )
    {
        // add MAC address
        [self.deviceClaims setObject:macAddress forKey:OM_MACADDR];
    }
    
    // Reachability
    if ([[OMReachability reachabilityForLocalWiFi]
         currentReachabilityStatus] != ReachableViaWiFi)
    {
        [self.deviceClaims setValue:@"PHONE_CARRIER" forKey:OM_NETWORKTYPE];
    }
    else
        [self.deviceClaims setValue:@"WIFI" forKey:OM_NETWORKTYPE];
    
}

///////////////////////////////////////////////////////////////////////////////
// computeLocaleInformation
///////////////////////////////////////////////////////////////////////////////
- (void)computeLocaleInformation
{
    NSLocale *locale = [NSLocale currentLocale];
    [self.deviceClaims setObject:[locale objectForKey:NSLocaleIdentifier]
                          forKey:OM_LOCALE];
}

@end
///////////////////////////////////////////////////////////////////////////////
// End of OMIdentityContext.m
///////////////////////////////////////////////////////////////////////////////

