/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@class OMTimer;
@class OMTimeEvent;

typedef void (^timeEventBlock)(OMTimeEvent *event, OMTimer *timer);

@interface OMTimeEvent : NSObject

@property (nonatomic, copy) timeEventBlock eventBlock;
@property (nonatomic, assign) NSTimeInterval time;
@property (nonatomic, assign) BOOL willRepeat; // Default to NO

+ (OMTimeEvent *)eventAtTime:(NSTimeInterval)time withEventBlock:(timeEventBlock)completionBlock;

@end



