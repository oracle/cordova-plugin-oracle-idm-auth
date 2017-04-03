/* Copyright (c) 2011, 2012, Oracle and/or its affiliates.
 All rights reserved. */

/*
 NAME
 OMAuthenticationDelegate.h - Oracle Mobile Authentication Delegate
 
 DESCRIPTION
 Authentication delegate to be implemented by OMAuthenticationManager class for
 receiving updates about the current authentication
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 OMAuthenticationDelegate
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    02/04/16 - Creation
 */

#import <Foundation/Foundation.h>

@protocol OMAuthenticationDelegate <NSObject>

- (void)didFinishCurrentStep: (id)object
                    nextStep: (NSUInteger)nextStep
                authResponse: (NSDictionary *)data
                       error: (NSError *)error;
@end
