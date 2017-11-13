/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticationService.h"

typedef void (^OMServiceDiscoveryCallback)(NSDictionary * propertiesJSON,
NSError * discoveryError);

@interface OMServiceDiscoveryHandler : OMAuthenticationService

+ (OMServiceDiscoveryHandler *)sharedHandler;

- (void)discoverConfigurationWithURL:(NSURL *)discoveryURL
                             withMss:(OMMobileSecurityService*)mss
                          completion:(OMServiceDiscoveryCallback )completion;

@end
