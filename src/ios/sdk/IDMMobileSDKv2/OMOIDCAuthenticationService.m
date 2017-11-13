/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMOIDCAuthenticationService.h"

@implementation OMOIDCAuthenticationService

-(void)setAuthContext
{
    [super setAuthContext];
    self.context.idToken = self.idToken;
    [self setUserInfoInContext];
}

-(void)setUserInfoInContext
{
    NSArray *segments = [self.context.idToken componentsSeparatedByString:@"."];
    NSString *base64String = [segments objectAtIndex: 1];
    int requiredLength = (int)(4 * ceil((float)[base64String length] / 4.0));
    int nbrPaddings = requiredLength - [base64String length];
    if (nbrPaddings > 0) {
        NSString *padding =
        [[NSString string] stringByPaddingToLength:nbrPaddings
                                        withString:@"=" startingAtIndex:0];
        base64String = [base64String stringByAppendingString:padding];
    }
    
    base64String = [base64String
                    stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    base64String = [base64String
                    stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    NSData *decodedData =
    [[NSData alloc] initWithBase64EncodedString:base64String options:0];
    NSDictionary *jsonDict = [NSJSONSerialization JSONObjectWithData:
                              decodedData
                                                             options:0
                                                               error:nil];
    self.context.userInfo = jsonDict;
}
@end
