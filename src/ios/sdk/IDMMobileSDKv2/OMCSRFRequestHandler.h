//
//  OMCSRFRequestHandler.h
//  IDMMobileSDKv2
//
//  Created by Shiva Prasad on 17/02/20.
//  Copyright © 2020 Oracle. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OMFedAuthConfiguration.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^TokenRelayHandler)(id response, NSError *error);

@interface OMCSRFRequestHandler : NSObject

- (NSDictionary*)extractTokenRelayTokensWithConfig:(OMFedAuthConfiguration*)config error:(NSError**)error;

@end

NS_ASSUME_NONNULL_END
