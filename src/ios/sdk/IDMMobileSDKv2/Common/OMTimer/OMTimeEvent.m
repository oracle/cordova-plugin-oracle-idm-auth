/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMTimeEvent.h"

@implementation OMTimeEvent

+ (OMTimeEvent *)eventAtTime:(NSTimeInterval)time withEventBlock:(timeEventBlock)eventBlock
{
    OMTimeEvent *event	= [[OMTimeEvent alloc] init];
    event.eventBlock			= eventBlock;
    event.time					= time;
    event.willRepeat			= NO;
    
    return event;
}

@end
