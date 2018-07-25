/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@class OMAuthenticationService;
@interface OMURLProtocol : NSURLProtocol
{

}


+ (void)setOMAObject:(OMAuthenticationService *)obj;
+ (OMAuthenticationService *)currentOMAObject;
@end
