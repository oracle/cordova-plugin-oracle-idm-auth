/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


//	Got this from: http://stackoverflow.com/questions/347219/how-can-i-programmatically-pause-an-nstimer

#import <Foundation/Foundation.h>

@interface NSTimer (OMTimes)

@property (nonatomic, readonly) NSDate *oldFireDate;
@property (nonatomic) NSNumber *timeDeltaNumber;

- (void)pauseOrResume;
- (BOOL)isPaused;


@end
