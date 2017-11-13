/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMDefinitions.h"
#import "OMErrorCodes.h"

typedef void (^OMOpenIDCDiscoveryCallback)(NSMutableDictionary *_Nullable propertiesJSON,
                                     NSError *_Nullable discoveryError);


@interface OMOpenIDCServiceDiscovery : NSObject

+ (void)discoverConfigurationWithURL:(NSURL * _Nonnull)discoveryURL
        completion:(OMOpenIDCDiscoveryCallback _Null_unspecified)completion;

@end
