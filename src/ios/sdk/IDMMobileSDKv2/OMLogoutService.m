/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMLogoutService.h"
@implementation OMLogoutService
-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss
{
    self = [super init];
    if (self)
    {
        _mss = mss;
    }
    return self;
}
-(void)performLogout:(BOOL)clearRegistrationHandles
{
    return;
}
@end
