/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@protocol OMAuthenticationDelegate <NSObject>

- (void)didFinishCurrentStep: (id)object
                    nextStep: (NSUInteger)nextStep
                authResponse: (NSDictionary *)data
                       error: (NSError *)error;
@end
