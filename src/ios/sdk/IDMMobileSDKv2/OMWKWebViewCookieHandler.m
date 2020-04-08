/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMWKWebViewCookieHandler.h"

@implementation OMWKWebViewCookieHandler

#pragma mark -
#pragma mark cookies related methds -

+ (void)cookiesForVisitedHosts:(NSArray*)visitedHosts completionHandler:
(void (^)(NSArray<WKWebsiteDataRecord *> *))completionHandler;

{
    NSSet *websiteDataTypes = [NSSet setWithArray:@[
                                                    WKWebsiteDataTypeMemoryCache,
                                                    WKWebsiteDataTypeLocalStorage,
                                                    WKWebsiteDataTypeCookies,
                                                    WKWebsiteDataTypeSessionStorage,
                                                    ]];
    
    [[WKWebsiteDataStore defaultDataStore] fetchDataRecordsOfTypes:websiteDataTypes
                                                 completionHandler:
     ^(NSArray<WKWebsiteDataRecord *> * _Nonnull dataRecords)
     {
         NSMutableSet *domainList = [self domainNamesfromVisitedHosts:
                                     visitedHosts];
         if ([domainList count])
         {
             NSCompoundPredicate* predicate = [self predicateForDomainNames:
                                               domainList];
             NSArray *filtredDataRecord = [dataRecords
                                           filteredArrayUsingPredicate:predicate];
             
             completionHandler(filtredDataRecord);
         }
         else
         {
             completionHandler(nil);
         }
         
     }];
}

//use sets to avoid duplicate domain name
+ (NSMutableSet*)domainNamesfromVisitedHosts:(NSArray*)visitedHosts
{
    NSMutableSet *domainList = [NSMutableSet set];
    
    for (NSURL *vistedURL in visitedHosts)
    {
        if ([vistedURL host])
        {
            NSString *domainName = [self domainNameFromHostName:[vistedURL host]];
            if (domainName) {
                [domainList addObject:domainName];
                
            }
            
        }
    }
    
    return domainList;
}

+ (NSString*)domainNameFromHostName:(NSString*)hostname
{
    
    NSString *domainName = nil;
    
    NSArray*components = [hostname componentsSeparatedByString:@"."];
    
    if ([components count] > 2)
    {
        NSArray *domainComponents = [components
                                     subarrayWithRange:NSMakeRange([components count]-2, 2)];
        
        for (NSString *component in domainComponents)
        {
            if (domainName == nil)
            {
                domainName = component;
            }
            else
            {
                domainName = [domainName stringByAppendingString:@"."];
                domainName = [domainName stringByAppendingString:component];
            }
        }
    }
    else
    {
        domainName = hostname;
    }
    
    return domainName;
}

+ (NSCompoundPredicate*)predicateForDomainNames:(NSSet*)domainNames
{
    NSMutableArray *predicatesList = [NSMutableArray array];
    
    for (NSString *domainName in domainNames)
    {
        NSPredicate *domainCookiePredicate = [NSPredicate
                                              predicateWithFormat:
                                              @"displayName = %@",domainName];
        [predicatesList addObject:domainCookiePredicate];
        
    }
    
    NSCompoundPredicate *compoundPredicate = [NSCompoundPredicate
                                              orPredicateWithSubpredicates:
                                              predicatesList];
    
    return compoundPredicate;
}


#pragma mark -
#pragma Cookie deleting methods -

+ (void)clearWkWebViewDataOfTypes:(NSSet*)websiteDataTypes forUrls:(NSArray*)visitedUrls completionHandler:(void (^) (void))completionBlock
{
    
    [OMWKWebViewCookieHandler cookiesForVisitedHosts:visitedUrls
                             completionHandler:^(NSArray<WKWebsiteDataRecord *> * records)
     {
         if ([records count])
         {
             [[WKWebsiteDataStore defaultDataStore] removeDataOfTypes:websiteDataTypes
                                                       forDataRecords:records
                                                    completionHandler:^{
                                                        
                                                        NSLog(@"cleared");
                                                        if (completionBlock) {
                                                            completionBlock();
                                                        }
                                                    }];
         }
         else
         {
             if (completionBlock) {
                 completionBlock();
             }
             
         }
         
     }];
    
}

+ (void)clearWkWebViewCookiesForUrls:(NSArray*)visitedUrls completionHandler:(void (^) (void))completionBlock
{
    NSSet *websiteDataTypes = [NSSet setWithArray:@[
                                                    WKWebsiteDataTypeMemoryCache,
                                                    WKWebsiteDataTypeLocalStorage,
                                                    WKWebsiteDataTypeCookies,
                                                    WKWebsiteDataTypeSessionStorage,
                                                    ]];
    
    [self clearWkWebViewDataOfTypes:websiteDataTypes forUrls:visitedUrls completionHandler:completionBlock];
    
    
}

+ (void)clearWkWebViewCashForUrls:(NSArray*)visitedUrls completionHandler:(void (^) (void))completionBlock
{
    NSSet *websiteDataTypes = [NSSet setWithArray:@[
                                                    WKWebsiteDataTypeMemoryCache,
                                                    WKWebsiteDataTypeLocalStorage,
                                                    WKWebsiteDataTypeSessionStorage,
                                                    ]];
    
    
    [self clearWkWebViewDataOfTypes:websiteDataTypes forUrls:visitedUrls completionHandler:completionBlock];

}

+ (void)deleteCookieFromWKHTTPStore:(NSHTTPCookie*)cookie
{
    if(@available(iOS 11.0,*))
    {
        [[[WKWebsiteDataStore defaultDataStore] httpCookieStore] deleteCookie:cookie completionHandler:^{
            NSLog(@"deleteCookieFromWKHTTPStore");
        }];
        
    }
}

@end
