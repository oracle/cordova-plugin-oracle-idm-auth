/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

#import "OMTimer.h"
#import "OMTimeEvent.h"
#import "NSTimer+OMTimes.h"

@implementation OMTimer

- (id)init
{
    if (!(self = [super init]))
        return self;
    
    self.willLoop	= NO;
    _events			= [[NSMutableArray alloc] init];
    _eventTimers	= [[NSMutableArray alloc] init];
    _startTime		= 0;
    _isRunning		= NO;
    _loop			= 0;
    _hasStarted		= NO;
    
    return self;
}

- (void)dealloc
{
    // Invalidate all the timers when this object is being deallocated.
    [self stop];
}

#pragma mark Easy Timeline Controllers

- (void)start
{
    if (_duration <= 0.0)
        return;
    
    // If starting it again, restart from beginning
    [self stop];
    
    _isRunning	= YES;
    
    // Do main timeline timer
    _mainTimer	= [NSTimer timerWithTimeInterval:_duration target:self selector:@selector(finishedTimer:) userInfo:nil repeats:self.willLoop];
    
    [[NSRunLoop currentRunLoop] addTimer:_mainTimer forMode:NSDefaultRunLoopMode];
    
    _startTime	= [NSDate timeIntervalSinceReferenceDate];
        
    if(_autoPauseWhenAppGoesBackground)
    {
        [[NSNotificationCenter defaultCenter] addObserver: self
                                                 selector: @selector(handleEnteredBackground:)
                                                     name: UIApplicationDidEnterBackgroundNotification
                                                   object: nil];

        [[NSNotificationCenter defaultCenter] addObserver: self
                                                 selector: @selector(handleEnterForeground:)
                                                     name: UIApplicationWillEnterForegroundNotification
                                                   object: nil];

    }
    // Do timers for events
    if (_events.count > 0)
    {
        for (OMTimeEvent *event in _events)
        {
            if (event.time > 0.0 && (event.time <= self.duration || self.willLoop))
            {
                NSTimer *eventTimer = [NSTimer scheduledTimerWithTimeInterval:event.time
                                                                       target:self
                                                                     selector:@selector(runEvent:)
                                                                     userInfo:event repeats:event.willRepeat];
                [_eventTimers addObject:eventTimer];
            }
        }
    }
    
    _hasStarted = YES;
}

- (void)pause
{
    if (!_isRunning && _startTime > 0)
        return;
    
    _isRunning	= NO;
    
    [_mainTimer pauseOrResume];
    
    [_eventTimers enumerateObjectsUsingBlock:^(NSTimer *eventTimer, NSUInteger idx, BOOL *stop) {
        [eventTimer pauseOrResume];
    }];
    
    _pausedTime	= [NSDate timeIntervalSinceReferenceDate];
}

- (void)resume
{
    if (_isRunning)
        return;
    
    _isRunning	= YES;
    _startTime	= _startTime + ([NSDate timeIntervalSinceReferenceDate] - _pausedTime);
    _pausedTime	= 0;
    
    [_mainTimer pauseOrResume];
    
    [_eventTimers enumerateObjectsUsingBlock:^(NSTimer *eventTimer, NSUInteger idx, BOOL *stop) {
        [eventTimer pauseOrResume];
    }];
}

- (void)stop
{
    [_mainTimer invalidate];
    
    for (NSTimer *eventTimer in _eventTimers)
        [eventTimer invalidate];
    
    _mainTimer	= nil;
    
    _pausedTime	= 0;
    _isRunning	= NO;
    _loop		= 0;
    _hasStarted	= NO;
}

- (void)skipForwardSeconds:(NSTimeInterval)seconds
{
    // Don't skip before you start
    if (_startTime <= 0.0)
        return;
    
    // If you're skipping past the end of the timeline, finish the timeline
    if (!self.willLoop && (_mainTimer.oldFireDate.timeIntervalSinceReferenceDate - [NSDate timeIntervalSinceReferenceDate] <= seconds))
    {
        [self stop];
        
        if (self.completionBlock)
            self.completionBlock(self);
        
        return;
    }
    
    // Stop all the other timers and save the fire date
    NSDate *mainFireDate			= _mainTimer.oldFireDate;
    [_mainTimer invalidate];
    
    
    __block NSMutableArray *eventFireDate	= [[NSMutableArray alloc] init];
    [_eventTimers enumerateObjectsUsingBlock:^(NSTimer *eventTimer, NSUInteger idx, BOOL *stop) {
        [eventFireDate addObject:eventTimer.oldFireDate];
        [eventTimer invalidate];
    }];
    
    // Reset all timers with a shorter first fire date
    // Do main timeline timer
    _mainTimer			= [NSTimer timerWithTimeInterval:_duration target:self selector:@selector(finishedTimer:) userInfo:nil repeats:self.willLoop];
    _mainTimer.fireDate	= [mainFireDate dateByAddingTimeInterval:-seconds];
    
    [[NSRunLoop currentRunLoop] addTimer:_mainTimer forMode:NSDefaultRunLoopMode];
    
    if (_pausedTime > 0.0)
        [_mainTimer pauseOrResume];
    
    // Do timers for events
    if (_events.count > 0)
    {
        _eventTimers	= [[NSMutableArray alloc] init];
        
        for (NSInteger i = 0; i < _events.count; i++)
        {
            OMTimeEvent *event = _events[i];
            
            if (event.time > 0.0)
            {
                NSTimer *eventTimer = [NSTimer scheduledTimerWithTimeInterval:event.time
                                                                       target:self
                                                                     selector:@selector(runEvent:)
                                                                     userInfo:event repeats:event.willRepeat];
                eventTimer.fireDate	= [eventFireDate[i] dateByAddingTimeInterval:-seconds];
                
                // If the fired time is negative, then don't let it fire ever.
                if ([eventTimer.fireDate timeIntervalSinceReferenceDate] < 0)
                {
                    
                }
                  //  eventTimer.fireDate = [NSDate distantFuture]; need to tell
                
                [_eventTimers addObject:eventTimer];
                
                if (_pausedTime > 0.0)
                    [eventTimer pauseOrResume];
            }
        }
    }
    
    _startTime -= seconds;
}

- (void)clear
{
    [self stop];
    [_events removeAllObjects];
    [_eventTimers removeAllObjects];
}

#pragma mark  OMTimeEvent Events

- (void)addEvent:(OMTimeEvent *)event
{
    [_events addObject:event];
}

- (void)removeEvent:(OMTimeEvent *)event
{
    [_events removeObject:event];
}

#pragma mark Status

- (NSTimeInterval)currentTime
{
    if (_startTime)
        return (_pausedTime > 0.0 ? _pausedTime :[NSDate timeIntervalSinceReferenceDate]) - _startTime;
    else
        return 0.0;
}

- (NSTimeInterval)remainingTime;
{
    // used for debuging
//    NSLog(@"remaining time = %f current time = %f",
//          (self.duration - [self currentTime]) ,[self currentTime]);
    return self.duration - [self currentTime];
}

- (NSInteger)currentLoopCount
{
    return _loop;
}

#pragma mark Helper functions

- (void)finishedTimer:(NSTimer *)timer
{
    if (self.completionBlock)
    {
        _isRunning = NO;
        self.completionBlock(self);
    }
    
    if (!self.willLoop)
    {
        [self stop];
    }
    else
    {
        _isRunning = YES;
        _loop++;
    }

}

- (void)runEvent:(NSTimer *)timer
{
    OMTimeEvent *event = (OMTimeEvent *)timer.userInfo;
    
    if (event.eventBlock)
        event.eventBlock(event, self);
}



- (void)handleEnterForeground:(NSNotification *)info
{
    
    if ([_mainTimer.fireDate compare:[NSDate date]] == NSOrderedAscending)
    {
        [self finishedTimer:_mainTimer];
    }
    
}
- (void)handleEnteredBackground:(NSNotification *)info
{
//    [self pause];
}

@end
