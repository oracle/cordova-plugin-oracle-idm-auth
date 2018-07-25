/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import <Foundation/Foundation.h>
#import "OMOAuthAuthenticationService.h"

@interface OMAuthorizationGrant : NSObject
@property(nonatomic, weak) OMOAuthAuthenticationService *oauthService;
- (NSURL *)frontChannelRequestURL;
- (NSDictionary *)backChannelRequest:(NSDictionary *)authData;
- (void)processOAuthResponse:(NSDictionary *)urlQueryDict;
- (void)OAuthBackChannelResponse:(NSURLResponse *)urlResponse
                            data:(id)data
                        andError:(NSError *)error;
- (NSString *)queryParameters:(NSMutableString *)url;
- (NSString *)backChannelRequestBody:(NSMutableString *)url;
- (NSDictionary *)backChannelRequestHeader;
- (BOOL)doOfflineAuthentication:(NSURL *)offlineHost;
-(void)sendFrontChannelChallenge;
- (void)cancelAuthentication;
@end
