/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


static void *AssociationKey;
static void *OldFireDateKey;

#import "NSTimer+OMTimes.h"
#import <objc/runtime.h>

@implementation NSTimer (OMTimes)

- (void)pauseOrResume
{
    if ([self isPaused])
    {
        self.fireDate			= [[NSDate date] dateByAddingTimeInterval:self.timeDeltaNumber.doubleValue];
        self.timeDeltaNumber	= nil;
        self.oldFireDate		= nil;
    }
    else
    {
        self.timeDeltaNumber	= @(self.fireDate.timeIntervalSinceNow);
        self.oldFireDate		= self.fireDate;
        self.fireDate			= [NSDate distantFuture];
    }
}

- (BOOL)isPaused
{
    return (self.timeDeltaNumber != nil);
}

- (void)setOldFireDate:(NSDate *)oldFireDate
{
    objc_setAssociatedObject(self, &OldFireDateKey, oldFireDate, OBJC_ASSOCIATION_RETAIN);
}

- (NSDate *)oldFireDate
{
    NSDate *oldFireDate = objc_getAssociatedObject(self, &OldFireDateKey);
    
    if (oldFireDate)
        return oldFireDate;
    
    return self.fireDate;
}

- (NSNumber *)timeDeltaNumber
{
    return objc_getAssociatedObject(self, &AssociationKey);
}

- (void)setTimeDeltaNumber:(NSNumber *)timeDeltaNumber
{
    objc_setAssociatedObject(self, &AssociationKey, timeDeltaNumber, OBJC_ASSOCIATION_RETAIN);
}

@end
