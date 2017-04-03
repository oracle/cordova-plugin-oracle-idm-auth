/* Copyright (c) 2011, 2013, Oracle and/or its affiliates.
 All rights reserved.*/

/*
 NAME
 OMAuthenticationChallenge.h - Oracle Mobile Authentication Challenge class
 
 DESCRIPTION
 OMAuthenticationChallenge class contains the information about authentication 
 challenge and completion handler for responding to it
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 MODIFIED   (MM/DD/YY)
 asashiss    06/22/16 - OMSS-29823
 asashiss    02/04/16 - Creation
 */

#import <Foundation/Foundation.h>



enum
{
    OMChallengeUsernamePassword,
    OMChallengeClientCert,
    OMChallengeServerTrust,
    OMChallengeExternalBrowser,
    OMChallengeEmbeddedBrowser,
    OMChallengeInvalidRedirect
};
typedef NSUInteger OMChallengeType;

enum
{
    OMProceed,
    OMCancel
};
typedef NSUInteger OMChallengeResponse;
@interface OMAuthenticationChallenge : NSObject
@property (nonatomic, strong) NSDictionary *authData;
@property (nonatomic) OMChallengeType challengeType;
@property (nonatomic, copy) __block void(^authChallengeHandler)
                    (NSDictionary *authData,OMChallengeResponse response );
@end
