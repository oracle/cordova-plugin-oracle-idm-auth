/* Copyright (c) 2011, 2014, Oracle and/or its affiliates. 
All rights reserved.*/

/*
 NAME
 OMCertInfo.h - Oracle Mobile Certificate Information
 
 DESCRIPTION
 Certificate information object that contains user readable information about a
 certificate
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS DEFINED
 None
 
 PROTOCOLS IMPLEMENTED
 
 CATEGORIES/EXTENSIONS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    08/08/14 - Creation
 */

#import <Foundation/Foundation.h>

@interface OMCertInfo : NSObject
{
@private
    NSString *_commonName;
    NSString *_organizationalUnit;
    NSString *_location;
    NSString *_organization;
    NSString *_state;
    NSString *_country;
    NSString *_serialNumber;
    NSDate *_issuedOn;
    NSDate *_expiresOn;
    NSString *_issuer;
}

@property(nonatomic, retain) NSString *commonName;
@property(nonatomic, retain) NSString *organizationalUnit;
@property(nonatomic, retain) NSString *organization;
@property(nonatomic, retain) NSString *location;
@property(nonatomic, retain) NSString *state;
@property(nonatomic, retain) NSString *country;
@property(nonatomic, retain) NSString *serialNumber;
@property(nonatomic, retain) NSDate *issuedOn;
@property(nonatomic, retain) NSDate *expiresOn;
@property(nonatomic, retain) NSString *issuer;

-(id)initWithCertHex:(NSString *)hexString;
@end
