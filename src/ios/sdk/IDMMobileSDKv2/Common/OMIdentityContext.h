/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMObject.h"

/**
 * The IdentityContext class provides mechanism to collect Device specific
 * claims, which can be sent to OIC during authentication flow to provide
 * additional layer of security.
 */
@interface OMIdentityContext : NSObject

@property (nonatomic, strong) NSArray *identityContextClaims;
@property (nonatomic, strong) NSString *applicationID;

/**
 * Returns true if the attributes collected from the device is compliant with
 * the security policy configured in OIC for this application.
 *
 * @return true if the device is compliant with the configured policy;
 false otherwise.
 * @param policies The policies that need to be evaluated in the device.
 */
- (BOOL)evaluatePolicy:(NSDictionary*)policies;

/**
 * Returns the requested claims collected from the device in a JSON format
 * @return Claims collected from the device in JSON format.
 * @param  Claim attributes
 */
- (NSDictionary *)deviceClaims:(NSArray*) claimAttributes;

/**
 * Refresh the claims information which are already collected
 */
- (void)refresh;

/**
 * Returns claims in the format given below, which needs to be appended
 * osType=type&osVer=ver&clientSDKVersion=1.0&serviceDomain=default
 */
- (NSString *)claimsURLForApplicationID: (NSString *)applicationID
                          serviceDomain: (NSString *)domain
                                 oicURL: (NSString *)oicURL;

/**
 * Returns claims in the format required by device registration and
 * authentication service
 */
- (NSDictionary *)getJSONDictionaryForAuthentication:(NSDictionary *)jailBreakDetectionPolicy;

/**
 * Returns the singleton instance of OMIdentityContext class
 */
+ (id)sharedInstance;
@end
///////////////////////////////////////////////////////////////////////////////
// End of OMIdentityContext Header File
///////////////////////////////////////////////////////////////////////////////
