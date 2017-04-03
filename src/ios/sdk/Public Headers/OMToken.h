/* Copyright (c) 2011, 2014, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMToken.h - Stores Tokens returned by server
 
 DESCRIPTION
 Stores Tokens
 
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
 asashiss    04/11/16 - Creation
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
