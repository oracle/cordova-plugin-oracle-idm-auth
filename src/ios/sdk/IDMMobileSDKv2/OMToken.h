/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>

@interface OMToken : NSObject<NSCoding,NSCopying>
{
@protected
    NSString *_tokenName;
    NSSet *_tokenScopes;
    NSString *_tokenValue;
    NSDate *_sessionExpiryDate;
    NSDate *_tokenIssueDate;
    int _expiryTimeInSeconds;
    NSString *_refreshToken;
    NSString *_tokenType;
}

@property (nonatomic, strong) NSString *tokenName;
@property (nonatomic, strong) NSSet *tokenScopes;
@property (nonatomic, strong) NSDate *sessionExpiryDate;
@property (nonatomic, strong) NSDate *tokenIssueDate;
@property (nonatomic, strong) NSString *tokenValue;
@property (nonatomic) int expiryTimeInSeconds;
@property (nonatomic, strong) NSString *refreshToken;
@property (nonatomic, strong) NSString *tokenType;

- (BOOL)isTokenValid;

@end
