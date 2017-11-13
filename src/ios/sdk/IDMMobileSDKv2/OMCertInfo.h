/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
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
