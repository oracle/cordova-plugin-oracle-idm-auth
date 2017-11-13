/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@class OMTimer;
@class OMTimeEvent;

typedef void (^OMTimerCompletionBlock)(OMTimer *timeline);

@interface OMTimer : NSObject
{
    NSTimer *_mainTimer;
    
    NSTimeInterval _startTime;
    NSTimeInterval _pausedTime;
    
    NSMutableArray *_events;
    NSMutableArray *_eventTimers;
    
    NSInteger _loop;
    
}


@property (nonatomic, assign) NSTimeInterval duration;
@property (nonatomic, assign) BOOL willLoop; // Default to NO
@property (nonatomic, assign) BOOL autoPauseWhenAppGoesBackground; // Default to NO
@property (nonatomic, assign) NSTimeInterval tickPeriod;
@property (nonatomic, readonly) NSArray *events;
@property (nonatomic, copy) OMTimerCompletionBlock completionBlock;


@property (nonatomic, readonly) NSTimeInterval currentTime;
@property (nonatomic, readonly) NSInteger currentLoopCount;
@property (nonatomic, readonly) BOOL isRunning;
@property (nonatomic, readonly) BOOL hasStarted;

- (void)start;
- (void)pause;
- (void)resume;
- (void)stop;
- (void)skipForwardSeconds:(NSTimeInterval)seconds;
- (void)clear;
- (NSTimeInterval)remainingTime;
#pragma mark  Time Events

// Adding or removing events while timeline is running won't work
- (void)addEvent:(OMTimeEvent *)event;
- (void)removeEvent:(OMTimeEvent *)event;


@end
