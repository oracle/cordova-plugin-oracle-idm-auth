/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMToken.h"


@implementation OMToken

@synthesize tokenName = _tokenName;
@synthesize tokenScopes = _tokenScopes;
@synthesize sessionExpiryDate = _sessionExpiryDate;
@synthesize tokenIssueDate = _tokenIssueDate;
@synthesize tokenValue = _tokenValue;
@synthesize expiryTimeInSeconds = _expiryTimeInSeconds;
@synthesize refreshToken = _refreshToken;
@synthesize tokenType = _tokenType;

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    [aCoder encodeObject:self.tokenName forKey:@"TOKEN_NAME"];
    [aCoder encodeObject:self.tokenScopes forKey:@"TOKEN_SCOPES"];
    [aCoder encodeObject:self.sessionExpiryDate forKey:@"sessionExpiryDate"];
    [aCoder encodeObject:self.tokenIssueDate forKey:@"tokenIssueDate"];
    [aCoder encodeObject:self.tokenValue forKey:@"TOKEN_VALUE"];
    NSString *expStr = [NSString stringWithFormat:@"%d",
                        self.expiryTimeInSeconds];
    [aCoder encodeObject:expStr forKey:@"expiryTimeInSeconds"];
    [aCoder encodeObject:self.refreshToken forKey:@"refreshToken"];
    [aCoder encodeObject:self.tokenType forKey:@"tokenType"];
}

- (id)initWithCoder:(NSCoder *)aDecoder
{
    self = [super init];
    if(self)
    {
        self.tokenName = [aDecoder decodeObjectForKey:@"TOKEN_NAME"];
        self.tokenScopes = [aDecoder decodeObjectForKey:@"TOKEN_SCOPES"];
        self.sessionExpiryDate = [aDecoder
                                  decodeObjectForKey:@"sessionExpiryDate"];
        self.tokenIssueDate = [aDecoder decodeObjectForKey:@"tokenIssueDate"];
        self.tokenValue = [aDecoder decodeObjectForKey:@"TOKEN_VALUE"];
        self.expiryTimeInSeconds = [[aDecoder
                                     decodeObjectForKey:@"expiryTimeInSeconds"]
                                    intValue];
        self.refreshToken = [aDecoder decodeObjectForKey:@"refreshToken"];
        self.tokenType = [aDecoder decodeObjectForKey:@"tokenType"];
    }
    return self;
}

- (id)copyWithZone:(NSZone *)zone
{
    OMToken *token = [[[self class] allocWithZone:zone] init];
    token.tokenName = [_tokenName copy];
    token.tokenScopes = [_tokenScopes copy];
    token.tokenValue = [_tokenValue copy];
    token.sessionExpiryDate = [_sessionExpiryDate copy];
    token.tokenIssueDate = [_tokenIssueDate copy];
    token.expiryTimeInSeconds = _expiryTimeInSeconds;
    token.refreshToken = [_refreshToken copy];
    token.tokenType = [_tokenType copy];
    return token;
}

- (BOOL)isTokenValid
{
    NSDate *currentDate = [NSDate date];
    NSTimeInterval interval = [currentDate
                               timeIntervalSinceDate:self.tokenIssueDate];
    if(interval < self.expiryTimeInSeconds)
        return TRUE;
    return FALSE;
}

-(NSString *)description
{
    return [NSString stringWithFormat:@"Name : %@\nScope : %@\nValue : %@",
            _tokenName,_tokenScopes,_tokenValue];
}

@end
