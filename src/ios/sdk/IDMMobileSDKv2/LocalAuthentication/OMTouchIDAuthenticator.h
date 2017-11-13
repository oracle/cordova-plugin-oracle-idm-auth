/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMAuthenticator.h"

typedef void (^OMFallbackAuthenticationCompletionBlock)(BOOL authenticated);

@protocol OMTouchIDFallbackDelgate <NSObject>

@required

- (void)didSelectFallbackAuthentication:(NSError *)fallBackReason completionHandler:
    (OMFallbackAuthenticationCompletionBlock)handler;

@end

@interface OMTouchIDAuthenticator : OMAuthenticator

@property (nonatomic, weak) id<OMTouchIDFallbackDelgate> delegate;
@property (nonatomic, copy) NSString *localizedFallbackTitle;
@property (nonatomic, copy) NSString *localizedTouchIdUsingReason;

+ (BOOL)canEnableTouchID:(NSError *__autoreleasing*)error;

@end
