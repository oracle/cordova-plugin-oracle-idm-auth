/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
#import "AuthViewController.h"
#import <WebKit/WebKit.h>

@interface AuthViewController ()
@property (weak, nonatomic) OMMobileSecurityService* ommssInstance;
@property (weak, nonatomic) NSMutableArray* availableButtonList;
@property (nonatomic) BOOL isLogin;
@property (strong, nonatomic) WKProcessPool *processPool;
@property (nonatomic) BOOL wkWebViewEnabled;
@end

#ifdef DEBUG
#   define IdmLog(...) NSLog(__VA_ARGS__)
#else
#   define IdmLog(...)
#endif

@implementation AuthViewController
@synthesize toolbar;

- (IBAction)cancel:(id)sender {
  IdmLog(@"Cancel invoked.");
  [self dismissViewControllerAnimated:YES completion:nil];
  if (self.isLogin) {
    [self.ommssInstance cancelAuthentication];
  }
}

- (void) setAuthenticationInstance: (OMMobileSecurityService*) ommss {
  self.ommssInstance = ommss;
}

- (void) setAvailableWebButtonList:(NSMutableArray*) availableButtons {
  self.availableButtonList = availableButtons;
}

- (void) setIsLoginChallenge:(BOOL) isLoginChallenge {
  self.isLogin = isLoginChallenge;
}

- (void) isWkWebViewEnabled: (BOOL) enabled {
  self.wkWebViewEnabled = enabled;
}

- (void) viewDidLoad {
  [super viewDidLoad];
  [self createToolbar];

  if (self.isLogin) {
    [self.backButton setEnabled:YES];
    [self.forwardButton setEnabled:YES];
    [self.refreshButton setEnabled:YES];
    [self.cancelButton setEnabled:YES];
  }

  if (self.wkWebViewEnabled && self.wkWebView == nil) {
    [self createWKWebview];
  }
}
- (void)createToolbar {
  NSMutableArray *buttonItems = [[NSMutableArray alloc] init];
  BOOL hasAllButtons = [self.availableButtonList containsObject:@"ALL"];

  if ([self.availableButtonList containsObject:@"NONE"]) {
    toolbar.hidden = true;
  } else {
    if (hasAllButtons || [self.availableButtonList containsObject:@"BACK"]) {
      [buttonItems addObject:self.backButton];
    }
    if (hasAllButtons || [self.availableButtonList containsObject:@"FORWARD"]) {
      [buttonItems addObject:self.forwardButton];
    }
    if (hasAllButtons || [self.availableButtonList containsObject:@"REFRESH"]) {
      [buttonItems addObject:self.refreshButton];
    }
    if (hasAllButtons || [self.availableButtonList containsObject:@"CANCEL"]) {
      [buttonItems addObject:self.cancelButton];
    }
    [toolbar setItems:buttonItems];
  }
}

- (WKProcessPool*) sharedProcessPool
{
  if (self.processPool == nil) {
    // Loading shared process pool from wkwebview plugin, if it exists.
    Class processPoolFactory = NSClassFromString(@"CDVWKProcessPoolFactory");
    if (processPoolFactory != nil) {
      #pragma clang diagnostic push
      #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
      self.processPool =  [[processPoolFactory performSelector:NSSelectorFromString(@"sharedFactory")]
                            performSelector:NSSelectorFromString(@"sharedPool")];
      #pragma clang diagnostic pop
    } else {
      self.processPool = [[WKProcessPool alloc] init];
    }
  }

  return self.processPool;
}

- (void)createWKWebview
{
  WKWebViewConfiguration *webconfig = [[WKWebViewConfiguration alloc] init];
  webconfig.websiteDataStore = [WKWebsiteDataStore defaultDataStore];
  webconfig.processPool = [self sharedProcessPool];

  self.wkWebView = [[WKWebView alloc] initWithFrame:self.authWebView.frame
                                      configuration:webconfig];
  self.wkWebView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
  [self.authWebView removeFromSuperview];
  [[self view] addSubview: self.wkWebView];
}

@end
