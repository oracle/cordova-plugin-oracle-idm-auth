/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>



enum
{
    OMChallengeUsernamePassword,
    OMChallengeClientCert,
    OMChallengeServerTrust,
    OMChallengeExternalBrowser,
    OMChallengeEmbeddedBrowser,
    OMChallengeEmbeddedSafari,
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
