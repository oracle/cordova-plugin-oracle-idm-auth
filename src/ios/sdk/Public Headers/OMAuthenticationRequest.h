/* Copyright (c) 2011, 2015, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMAuthenticationRequest.h - Oracle Mobile Authentication Request
 
 DESCRIPTION
 Authentication Request object that can be sent by client to customize
 authentication
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    02/12/16 - Connectivity mode
 shivap      02/10/16 - Added identityDomain property
 asashiss    02/04/16 - Creation
 */

#import <Foundation/Foundation.h>
#import "OMObject.h"

@interface OMAuthenticationRequest : NSObject
@property(nonatomic) OMConnectivityMode connectivityMode;
@property(nonatomic, retain) NSString *userName;
@property(nonatomic, retain) NSString *password;

@property (nonatomic, copy) NSString *identityDomain;

@end
