/**
 * Copyright (c) 2016, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import "IDMMobileSDKv2Library.h"
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>

/**
 * This is a webview used by the plugin to do webview based
 * authentications. e.g. WebSSO, OAUTH2 3-legged.
 * The webview has a back, forward, cancel and reload buttons
 * for the user to navigate, if they wander from the login page,
 * say, using a link on the login page.
 */
@interface AuthViewController : UIViewController

/**
 * Reference to the cancel button.
 */
@property (weak, nonatomic) IBOutlet UIBarButtonItem *cancelButton;

/**
 * Reference to the webview.
 */
@property (weak, nonatomic) IBOutlet UIWebView *authWebView;


@property (strong, nonatomic) WKWebView *wkWebView;

/**
 * Action handle for cancel button. This method implementation will
 * cancel the current login session.
 */
- (IBAction)cancel:(id)sender;

/**
 * This method is used to set the OMMSS instance to perform the cancel.
 */
- (void) setAuthenticationInstance: (OMMobileSecurityService*) ommss;

/**
 * Used to indicate if IDM is expecting a WkWebView.
 */
- (void) isWkWebViewEnabled: (BOOL) enabled;

@end

