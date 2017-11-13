/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMASN1Node.h"
#import "OMObject.h"

static NSArray *NAME;
static NSDictionary *OID;

@implementation OMASN1Node
@synthesize childList = _childList;
@synthesize tag = _tag;
@synthesize value = _value;


+(void)initialize
{
    if (self == [OMASN1Node class])
    {
        // ASN.1 data types
        NAME = [[NSArray alloc] initWithObjects:
                  @"",
                  @"BOOLEAN",           //0x01
                  @"INTEGER",           //0x02
                  @"BITSTRING",         //0x03
                  @"OCTETSTRING",       //0x04
                  @"NULL",              //0x05
                  @"OBJECTIDENTIFIER",  //0x06
                  @"ObjectDescripter",  //0x07
                  @"",                  //0x08
                  @"",                  //0x09
                  @"",                  //0x0A
                  @"",                  //0x0B
                  @"UTF8String",        //0x0c
                  @"",                  //0x0d
                  @"",                  //0x0e
                  @"",                  //0x0f
                  @"SEQUENCE",          //0x10
                  @"SET",               //0x11
                  @"NumericString",     //0x12
                  @"PrintableString",   //0x13
                  @"TeletexString",     //0x14
                  @"",                  //0x15
                  @"IA5String",         //0x16
                  @"UTCTime",           //0x17
                  @"GeneralizedTime",   //0x18
                  nil
                  ];
        
        //ASN.1 object identifiers
        OID = [[NSDictionary alloc] initWithObjectsAndKeys:
                @"extension",@"0.2.262.1.10.0",
                @"signature",@"0.2.262.1.10.1.1",
                @"pkcs-1",@"1.2.840.113549.1.1",
                @"rsaEncryption",@"1.2.840.113549.1.1.1",
                @"md5withRSAEncryption",@"1.2.840.113549.1.1.4",
                @"sha1withRSAEncryption",@"1.2.840.113549.1.1.5",
                @"rsaOAEPEncryptionSET",@"1.2.840.113549.1.1.6",
                @"pkcs-7",@"1.2.840.113549.1.7",
                @"data",@"1.2.840.113549.1.7.1",
                @"signedData",@"1.2.840.113549.1.7.2",
                @"envelopedData",@"1.2.840.113549.1.7.3",
                @"signedAndEnvelopedData",@"1.2.840.113549.1.7.4",
                @"digestedData",@"1.2.840.113549.1.7.5",
                @"encryptedData",@"1.2.840.113549.1.7.6",
                @"dataWithAttributes",@"1.2.840.113549.1.7.7",
                @"encryptedPrivateKeyInfo",@"1.2.840.113549.1.7.8",
                @"x509Certificate(for.PKCS.#12)",@"1.2.840.113549.1.9.22.1",
                @"x509Crl(for.PKCS.#12)",@"1.2.840.113549.1.9.23.1",
                @"contentType",@"1.2.840.113549.1.9.3",
                @"messageDigest",@"1.2.840.113549.1.9.4",
                @"signingTime",@"1.2.840.113549.1.9.5",
                @"cert-extension",@"2.16.840.1.113730.1",
                @"netscape-cert-type",@"2.16.840.1.113730.1.1",
                @"netscape-ssl-server-name",@"2.16.840.1.113730.1.12",
                @"netscape-comment",@"2.16.840.1.113730.1.13",
                @"netscape-base-url",@"2.16.840.1.113730.1.2",
                @"netscape-revocation-url",@"2.16.840.1.113730.1.3",
                @"netscape-ca-revocation-url",@"2.16.840.1.113730.1.4",
                @"netscape-cert-renewal-url",@"2.16.840.1.113730.1.7",
                @"netscape-ca-policy-url",@"2.16.840.1.113730.1.8",
                @"contentType",@"2.23.42.0",
                @"msgExt",@"2.23.42.1",
                @"national",@"2.23.42.10",
                @"field",@"2.23.42.2",
                @"fullName",@"2.23.42.2.0",
                @"givenName",@"2.23.42.2.1",
                @"amount",@"2.23.42.2.10",
                @"familyName",@"2.23.42.2.2",
                @"birthFamilyName",@"2.23.42.2.3",
                @"placeName",@"2.23.42.2.4",
                @"identificationNumber",@"2.23.42.2.5",
                @"month",@"2.23.42.2.6",
                @"date",@"2.23.42.2.7",
                @"accountNumber",@"2.23.42.2.7.11",
                @"passPhrase",@"2.23.42.2.7.12",
                @"address",@"2.23.42.2.8",
                @"attribute",@"2.23.42.3",
                @"cert",@"2.23.42.3.0",
                @"rootKeyThumb",@"2.23.42.3.0.0",
                @"additionalPolicy",@"2.23.42.3.0.1",
                @"algorithm",@"2.23.42.4",
                @"policy",@"2.23.42.5",
                @"root",@"2.23.42.5.0",
                @"module",@"2.23.42.6",
                @"certExt",@"2.23.42.7",
                @"hashedRootKey",@"2.23.42.7.0",
                @"certificateType",@"2.23.42.7.1",
                @"merchantData",@"2.23.42.7.2",
                @"cardCertRequired",@"2.23.42.7.3",
                @"setExtensions",@"2.23.42.7.5",
                @"setQualifier",@"2.23.42.7.6",
                @"brand",@"2.23.42.8",
                @"vendor",@"2.23.42.9",
                @"eLab",@"2.23.42.9.22",
                @"espace-net",@"2.23.42.9.31",
                @"e-COMM",@"2.23.42.9.37",
                @"authorityKeyIdentifier",@"2.5.29.1",
                @"basicConstraints",@"2.5.29.10",
                @"nameConstraints",@"2.5.29.11",
                @"policyConstraints",@"2.5.29.12",
                @"basicConstraints",@"2.5.29.13",
                @"subjectKeyIdentifier",@"2.5.29.14",
                @"keyUsage",@"2.5.29.15",
                @"privateKeyUsagePeriod",@"2.5.29.16",
                @"subjectAltName",@"2.5.29.17",
                @"issuerAltName",@"2.5.29.18",
                @"basicConstraints",@"2.5.29.19",
                @"keyAttributes",@"2.5.29.2",
                @"cRLNumber",@"2.5.29.20",
                @"cRLReason",@"2.5.29.21",
                @"expirationDate",@"2.5.29.22",
                @"instructionCode",@"2.5.29.23",
                @"invalidityDate",@"2.5.29.24",
                @"cRLDistributionPoints",@"2.5.29.25",
                @"issuingDistributionPoint",@"2.5.29.26",
                @"deltaCRLIndicator",@"2.5.29.27",
                @"issuingDistributionPoint",@"2.5.29.28",
                @"certificateIssuer",@"2.5.29.29",
                @"certificatePolicies",@"2.5.29.3",
                @"nameConstraints",@"2.5.29.30",
                @"cRLDistributionPoints",@"2.5.29.31",
                @"certificatePolicies",@"2.5.29.32",
                @"policyMappings",@"2.5.29.33",
                @"policyConstraints",@"2.5.29.34",
                @"authorityKeyIdentifier",@"2.5.29.35",
                @"policyConstraints",@"2.5.29.36",
                @"extKeyUsage",@"2.5.29.37",
                @"keyUsageRestriction",@"2.5.29.4",
                @"policyMapping",@"2.5.29.5",
                @"subtreesConstraint",@"2.5.29.6",
                @"subjectAltName",@"2.5.29.7",
                @"issuerAltName",@"2.5.29.8",
                @"subjectDirectoryAttributes",@"2.5.29.9",
                @"objectClass",@"2.5.4.0",
                @"aliasedEntryName",@"2.5.4.1",
                @"organizationName",@"2.5.4.10",
                @"collectiveOrganizationName",@"2.5.4.10.1",
                @"organizationalUnitName",@"2.5.4.11",
                @"collectiveOrganizationalUnitName",@"2.5.4.11.1",
                @"title",@"2.5.4.12",
                @"description",@"2.5.4.13",
                @"searchGuide",@"2.5.4.14",
                @"businessCategory",@"2.5.4.15",
                @"postalAddress",@"2.5.4.16",
                @"collectivePostalAddress",@"2.5.4.16.1",
                @"postalCode",@"2.5.4.17",
                @"collectivePostalCode",@"2.5.4.17.1",
                @"postOfficeBox",@"2.5.4.18",
                @"collectivePostOfficeBox",@"2.5.4.18.1",
                @"physicalDeliveryOfficeName",@"2.5.4.19",
                @"collectivePhysicalDeliveryOfficeName",@"2.5.4.19.1",
                @"knowledgeInformation",@"2.5.4.2",
                @"telephoneNumber",@"2.5.4.20",
                @"collectiveTelephoneNumber",@"2.5.4.20.1",
                @"telexNumber",@"2.5.4.21",
                @"collectiveTelexNumber",@"2.5.4.21.1",
                @"collectiveTeletexTerminalIdentifier",@"2.5.4.22.1",
                @"facsimileTelephoneNumber",@"2.5.4.23",
                @"collectiveFacsimileTelephoneNumber",@"2.5.4.23.1",
                @"internationalISDNNumber",@"2.5.4.25",
                @"collectiveInternationalISDNNumber",@"2.5.4.25.1",
                @"registeredAddress",@"2.5.4.26",
                @"destinationIndicator",@"2.5.4.27",
                @"preferredDeliveryMehtod",@"2.5.4.28",
                @"presentationAddress",@"2.5.4.29",
                @"commonName",@"2.5.4.3",
                @"member",@"2.5.4.31",
                @"owner",@"2.5.4.32",
                @"roleOccupant",@"2.5.4.33",
                @"seeAlso",@"2.5.4.34",
                @"userPassword",@"2.5.4.35",
                @"userCertificate",@"2.5.4.36",
                @"caCertificate",@"2.5.4.37",
                @"authorityRevocationList",@"2.5.4.38",
                @"certificateRevocationList",@"2.5.4.39",
                @"surname",@"2.5.4.4",
                @"crossCertificatePair",@"2.5.4.40",
                @"name",@"2.5.4.41",
                @"givenName",@"2.5.4.42",
                @"initials",@"2.5.4.43",
                @"generationQualifier",@"2.5.4.44",
                @"uniqueIdentifier",@"2.5.4.45",
                @"dnQualifier",@"2.5.4.46",
                @"enhancedSearchGuide",@"2.5.4.47",
                @"protocolInformation",@"2.5.4.48",
                @"distinguishedName",@"2.5.4.49",
                @"serialNumber",@"2.5.4.5",
                @"uniqueMember",@"2.5.4.50",
                @"houseIdentifier",@"2.5.4.51",
                @"supportedAlgorithms",@"2.5.4.52",
                @"deltaRevocationList",@"2.5.4.53",
                @"clearance",@"2.5.4.55",
                @"crossCertificatePair",@"2.5.4.58",
                @"countryName",@"2.5.4.6",
                @"localityName",@"2.5.4.7",
                @"collectiveLocalityName",@"2.5.4.7.1",
                @"stateOrProvinceName",@"2.5.4.8",
                @"collectiveStateOrProvinceName",@"2.5.4.8.1",
                @"streetAddress",@"2.5.4.9",
                @"collectiveStreetAddress",@"2.5.4.9.1",
                @"top",@"2.5.6.0",
                @"alias",@"2.5.6.1",
                @"residentialPerson",@"2.5.6.10",
                @"applicationProcess",@"2.5.6.11",
                @"applicationEntity",@"2.5.6.12",
                @"dSA",@"2.5.6.13",
                @"device",@"2.5.6.14",
                @"strongAuthenticationUser",@"2.5.6.15",
                @"certificateAuthority",@"2.5.6.16",
                @"groupOfUniqueNames",@"2.5.6.17",
                @"country",@"2.5.6.2",
                @"pkiUser",@"2.5.6.21",
                @"pkiCA",@"2.5.6.22",
                @"locality",@"2.5.6.3",
                @"organization",@"2.5.6.4",
                @"organizationalUnit",@"2.5.6.5",
                @"person",@"2.5.6.6",
                @"organizationalPerson",@"2.5.6.7",
                @"organizationalRole",@"2.5.6.8",
                @"groupOfNames",@"2.5.6.9",
                @"X.500-Algorithms",@"2.5.8",
                @"X.500-Alg-Encryption",@"2.5.8.1",
                @"rsa",@"2.5.8.1.1",
                @"hashedRootKey",@"2.54.1775.2",
                @"certificateType",@"2.54.1775.3",
                @"merchantData",@"2.54.1775.4",
                @"cardCertRequired",@"2.54.1775.5",
                @"setQualifier",@"2.54.1775.7",
                @"set-data",@"2.54.1775.99",
                nil];
    }
}

-(id)initWithHexString:(NSString *)data
{
    self = [self init];
    int point = 0;
    int iter = 0;
    const char *cString = data.UTF8String;
    if (self && data)
    {
        while (point < data.length)
        {
            iter++;
            int tag10 = [OMASN1Node intFromHexCString:cString+point end:2];
            BOOL isSeq = tag10 & 32;
            BOOL isContext = tag10 & 128;
            int tag = tag10 & 31;
            NSString *tagName = isContext?[NSString stringWithFormat:@"[%d]",tag]:
            [NAME objectAtIndex:tag];
            if (![tagName length])
            {
                tagName = @"UNSUPPORTED TAG";
            }
            point = point + 2;
            int len = 0;
            int lenLength = [OMASN1Node intFromHexCString:cString + point
                                                      end:2] & 127;
            if (tag != 5)
            {
                if ([OMASN1Node intFromHexCString:cString + point end:2] & 128)
                {
                    if (lenLength  > 2)
                    {
                        NSLog(@"Length field is too long");
                        return nil ;
                    }
                    len = [OMASN1Node intFromHexCString:cString + point + 2
                                                    end:lenLength * 2];
                    point  = point + lenLength * 2 + 2;
                }
                else if (lenLength != 0)
                {
                    len = [OMASN1Node intFromHexCString:cString + point end:2];
                    point = point + 2;
                }
                if (len > data.length - point)
                {
                    NSLog(@"Length field is longer than rest");
                    return nil;
                }
            }
            else
            {
                point = point + 2;
            }
            NSString *val = @"";
            if (len)
            {
                val = [data substringWithRange:NSMakeRange(point, len*2)];
                point = point + len*2;
            }
            NSString *tempString;
            OMASN1Node *tempNode;
            if (isSeq)
            {
                self.tag = tagName;
                tempNode = [[OMASN1Node alloc ] initWithHexString:val];
            }
            else
            {
                int tempTag = isContext?4:tag;
                tempString = [NSString stringWithFormat:@"%@",
                              [OMASN1Node getValueForTag:tempTag fromData:val]];
                tempNode = [[OMASN1Node alloc] init];
                tempNode.tag = tagName;
                tempNode.value = tempString;
            }
            [self.childList addObject:tempNode];
        }
    }
    else
    {
        self = nil;
    }
    return self;
}
-(id)init
{
    self = [super init];
    if (self)
    {
        self.childList = [[NSMutableArray alloc] init];
    }
    return self;
}

-(NSString *)description
{
    if ([self.value length])
    {
        return [NSString stringWithFormat:@"TAG = %@VALUE = %@",
                self.tag,self.value];
    }
    return [NSString stringWithFormat:@"CHILD = %@",self.childList];
}

+(NSString *)stringFromHex:(NSString *)hex
{
    NSMutableString * newString = [[NSMutableString alloc] init];
    int i = 0;
    while (i < [hex length])
    {
        NSString * hexChar = [hex substringWithRange: NSMakeRange(i, 2)];
        int value = 0;
        sscanf([hexChar cStringUsingEncoding:NSASCIIStringEncoding], "%x",
               &value);
        [newString appendFormat:@"%c", (char)value];
        i+=2;
    }
    return newString;
}

+(NSString *)getValueForTag:(int )tag fromData:(NSString *)data
{
    NSString *ret = @"";
    if (tag == 1)
    {
        ret = [NSString stringWithFormat:@"%@",data.length?@"TRUE":@"FALSE"];
    }
    else if (tag == 2)
    {
        ret = [NSString stringWithFormat:@"%d",
               (int)strtol([data UTF8String],NULL,16)];
    }
    else if (tag == 3)
    {
        int unUse = [OMASN1Node intFromHexCString:[data UTF8String] end:2];
        NSString *bits = [data substringToIndex:2];
        if (bits.length > 4)
        {
            ret = [NSString stringWithFormat:@"0x%@",bits];
        }
        else
        {
            ret = [NSString stringWithFormat:@"%d",
                   (int)strtol([data UTF8String],NULL,16)];
        }
        ret = [NSString stringWithFormat:@"%@ %d Unused bits",ret,unUse];
    }
    else if (tag == 5)
    {
        ret = @"";
    }
    else if (tag == 6)
    {
        NSMutableArray *res = [NSMutableArray array];
        const char *cString = data.UTF8String;
        int d0 = [OMASN1Node intFromHexCString:cString end:2];;
        int r1 = floor(d0/40);
        int r2 = d0 - r1 * 40;
        [res addObject:[NSNumber numberWithInt:r1]];
        [res addObject:[NSNumber numberWithInt:r2]];
        NSMutableArray *stack = [NSMutableArray array];
        int powNum = 0;
        int i ;
        for (i = 1; i < data.length - 2; i = i+2)
        {
            int token = [OMASN1Node intFromHexCString:cString+i+1 end:2];
            [stack addObject:[NSNumber numberWithInt:(token & 127)]];
            if (token & 128)
            {
                powNum ++;
            }
            else
            {
                int sum = 0;
                for (int j = 0; j < stack.count; j++)
                {
                    sum = sum + [[stack objectAtIndex:j]
                                 intValue] * pow(128, powNum --);
                }
                [res addObject:[NSNumber numberWithInt:sum]];
                powNum = 0;
                [stack removeAllObjects];
            }
        }
        ret = [res componentsJoinedByString:@"."];
        if ([OID valueForKey:ret])
        {
            ret = [NSString stringWithFormat:@"%@",[OID
                                                    valueForKey:ret]];
        }
    }
    
    else if ([[NAME objectAtIndex:tag]
              rangeOfString:@"STRING" options:NSCaseInsensitiveSearch].location
             != NSNotFound)
    {
        ret = [self stringFromHex:data];
    }
    else if ([[NAME objectAtIndex:tag]
              rangeOfString:@"TIME" options:NSCaseInsensitiveSearch].location
             != NSNotFound)
    {
        ret = [self stringFromHex:data];
    }
    else
    {
        ret = data;
    }
    return ret;
}

+(int)intFromHexCString:(const char *)string end:(int)length
{
    char dest[length+1];
    strncpy(dest, string, length);
    dest[length] = '\0';
    return (int)strtol(dest, NULL, 16);
}
@end
