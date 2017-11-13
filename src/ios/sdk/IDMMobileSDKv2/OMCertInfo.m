/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMCertInfo.h"
#import "OMASN1Node.h"
#define ASNCommonName           @"commonName"
#define ASNOrganizationUnit     @"organizationalUnitName"
#define ASNOrganisation         @"organizationName"
#define ASNLocation             @"localityName"
#define ASNState                @"stateOrProvinceName"
#define ASNCountry              @"countryName"

@implementation OMCertInfo

@synthesize commonName = _commonName;
@synthesize organizationalUnit = _organizationalUnit;
@synthesize location = _location;
@synthesize organization = _organization;
@synthesize state = _state;
@synthesize country = _country;
@synthesize serialNumber = _serialNumber;
@synthesize issuedOn = _issuedOn;
@synthesize expiresOn = _expiresOn;
@synthesize issuer = _issuer;

-(id)initWithASN1:(OMASN1Node *)node
{
    self = [super init];
    if (self && node)
    {
        NSArray *infoList = [[[[[node childList] firstObject] childList]
                              objectAtIndex:0] childList];
        self.serialNumber =  [(OMASN1Node*)[infoList objectAtIndex:1]
                                value];
        OMASN1Node *certNode = [infoList objectAtIndex:5];
        OMASN1Node *issuerNode = [infoList objectAtIndex:3];
        OMASN1Node *dateNode = [infoList objectAtIndex:4];
        NSArray *certFields = [NSArray arrayWithObjects:ASNCommonName,
                               ASNOrganizationUnit,ASNOrganisation,ASNLocation,
                               ASNState,ASNCountry,nil];
        for (OMASN1Node *tempNode in [certNode childList])
        {
            NSString *tag = [(OMASN1Node*)[[[[tempNode childList] firstObject] childList]
                              firstObject] value];
            if ([certFields containsObject:tag])
            {
                OMASN1Node *valueNode = [[[[tempNode childList] firstObject]
                                          childList] objectAtIndex:1];
                if ([tag isEqual:ASNCommonName])
                {
                    self.commonName = [valueNode value];
                }
                else if ([tag isEqualToString:ASNOrganizationUnit])
                {
                    self.organizationalUnit = [valueNode value];
                }
                else if ([tag isEqualToString:ASNOrganisation])
                {
                    self.organization = [valueNode value];
                }
                else if ([tag isEqualToString:ASNLocation])
                {
                    self.location = [valueNode value];
                }
                else if ([tag isEqualToString:ASNState])
                {
                    self.state = [valueNode value];
                }
                else if ([tag isEqualToString:ASNCountry])
                {
                    self.country = [valueNode value];
                }
            }
        }
        for (OMASN1Node *tempNode in [issuerNode childList])
        {
            NSString *tag = [(OMASN1Node*)[[[[tempNode childList] firstObject] childList]
                              firstObject] value];
            if ([tag isEqualToString:ASNCommonName])
            {
                self.issuer = [(OMASN1Node*)[[[[tempNode childList] firstObject]
                                 childList] objectAtIndex:1] value];
                break;
            }
        }
        //ASN1 can represent date in any of the following formats
        NSArray *dateFormats = [NSArray arrayWithObjects:@"yyMMddhhmmssZ",
                                @"yyMMddhhmmZ",@"yyMMddhhmm+hh'mm'",
                                @"yyMMddhhmm-hh'mm'",@"yyMMddhhmmss+hh'mm'",
                                @"yyMMddhhmmss-hh'mm'",@"yyyyMMddHHmmssZ", nil];
        for (int i  = 0; i < dateFormats.count; i++)
        {
            NSString *dateFormat = [dateFormats objectAtIndex:i];
            NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
            [dateFormatter setDateFormat:dateFormat];
            self.issuedOn = [dateFormatter dateFromString:
                             [(OMASN1Node*)[[dateNode childList] firstObject] value]];
            self.expiresOn = [dateFormatter dateFromString:
                              [(OMASN1Node*)[[dateNode childList] objectAtIndex:1] value]];
            if (self.issuedOn && self.expiresOn)
            {
                break;
            }
        }
    }
    else
    {
        self = nil;
    }
    return self;
}

-(id)initWithCertHex:(NSString *)hexString
{
    OMASN1Node *node = [[OMASN1Node alloc] initWithHexString:hexString];
    return [self initWithASN1:node];
}

-(BOOL)isEqual:(id)object
{
    if (self == object)
    {
        return true;
    }
    if (![object isKindOfClass:[self class]])
    {
        return false;
    }
    OMCertInfo *infoObj = (OMCertInfo *)object;
    return ((_commonName == infoObj.commonName) ||
            ([_commonName isEqual:infoObj.commonName])) &&
    ((_organizationalUnit == infoObj.organizationalUnit) ||
     ([_organizationalUnit isEqual:infoObj.organizationalUnit])) &&
    ((_organization == infoObj.organization) ||
     ([_organization isEqual:infoObj.organization])) &&
    ((_location == infoObj.location) ||
     ([_location isEqual:infoObj.location])) &&
    ((_state == infoObj.state) ||
     ([_state isEqual:infoObj.state])) &&
    ((_country == infoObj.country) ||
     ([_country isEqual:infoObj.country])) &&
    ((_issuedOn == infoObj.issuedOn) ||
     ([_issuedOn isEqual:infoObj.issuedOn])) &&
    ((_expiresOn == infoObj.expiresOn) ||
     ([_expiresOn isEqual:infoObj.expiresOn])) &&
    ((_serialNumber == infoObj.serialNumber) ||
     ([_serialNumber isEqual:infoObj.serialNumber])) &&
    ((_issuer == infoObj.issuer) ||
     ([_issuer isEqual:infoObj.issuer]));
}

-(NSUInteger)hash
{
    NSUInteger prime = 31;
    NSUInteger result = 1;
    result = prime * result + [_commonName hash];
    result = prime * result + [_organizationalUnit hash];
    result = prime * result + [_organization hash];
    result = prime * result + [_location hash];
    result = prime * result + [_state hash];
    result = prime * result + [_country hash];
    result = prime * result + [_issuedOn hash];
    result = prime * result + [_expiresOn hash];
    result = prime * result + [_issuer hash];
    return result;
}

-(NSString *)description
{
    return [NSString stringWithFormat:@"CN=%@,OU=%@,O=%@,L=%@,ST=%@,C=%@,"
            "ISSUED=%@,EXPIRES=%@,SERIAL=%@,ISSUER=%@",self.commonName,
            self.organizationalUnit,self.organization,self.location,self.state,
            self.country,self.issuedOn,self.expiresOn,self.serialNumber,
            self.issuer];
}
@end
