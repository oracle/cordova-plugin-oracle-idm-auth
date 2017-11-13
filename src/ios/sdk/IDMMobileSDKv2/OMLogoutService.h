/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMMobileSecurityService.h"

@interface OMLogoutService : NSObject
@property(nonatomic, weak) OMMobileSecurityService *mss;
@property(nonatomic, weak) NSThread *callerThread;
-(id)initWithMobileSecurityService:(OMMobileSecurityService *)mss;
-(void)performLogout:(BOOL)clearRegistrationHandles;
@end
