/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


#import "OMUtilities.h"
#import "OMErrorCodes.h"
#import "OMObject.h"

static  NSString *omaDir = @"OMAStorage";
static  NSString *keyStoreDir = @"OMAKeystore";
static  NSString *localAuthDir = @"OMALocalAuth";
static  NSString *secDir = @"OMASecurestore";

@implementation OMUtilities

+ (NSString *)omaDirectoryPath
{
    @synchronized ([NSFileManager class])
    {
        static NSString *secDirectory = nil;

        if (!secDirectory)
        {
            NSArray *paths = NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES);
            NSString *appLibraryDirectory = [paths firstObject];
            NSString *omaDirectory = [appLibraryDirectory stringByAppendingPathComponent:omaDir];
            
            BOOL directoryCreated = NO;
            
            BOOL isExist =  [[NSFileManager defaultManager] fileExistsAtPath:omaDirectory
                                                                 isDirectory:&directoryCreated];
            
            if (!isExist)
            {
                [[NSFileManager defaultManager] createDirectoryAtPath:omaDirectory withIntermediateDirectories:YES attributes:nil error:nil];
            }
            
            secDirectory = omaDirectory;
        }
        return secDirectory;

    }
    
}


+ (NSString *)filePathForfile:(NSString*)fileName inDirectory:(NSString*)directory
                                                        error:(NSError **)error
{
    NSString *baseDirectoryPath = [self omaDirectoryPath];
    NSString *filePath = nil;
    
    if (directory)
    {
       NSString *relativeDirectory = [baseDirectoryPath stringByAppendingPathComponent:directory];
        
        BOOL isDirectory = NO;
        [[NSFileManager defaultManager] fileExistsAtPath:relativeDirectory isDirectory:&isDirectory];
        
        if (!isDirectory)
        {
            baseDirectoryPath = nil;
            
            if (error)
            {
                *error = [OMObject createErrorWithCode:OMERR_FILE_NOT_FOUND];
            }
        }
        else
        {
            baseDirectoryPath = relativeDirectory;
        }
    }
   
    if (baseDirectoryPath)
    {
        filePath = [baseDirectoryPath stringByAppendingPathComponent:fileName];
    }
    
    return filePath;
}

+ (NSString *)keystoreDirectoryName;
{
    return keyStoreDir;
}

+ (NSString *)localAuthDirectoryName;
{
    return localAuthDir;
}

+ (NSString *)secureDirectoryName;
{
    return secDir;
}

+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request
    returningResponse:(__autoreleasing NSURLResponse **)responsePtr
    error:(__autoreleasing NSError **)errorPtr {
    dispatch_semaphore_t    sem;
    __block NSData *        result;

    result = nil;

    sem = dispatch_semaphore_create(0);

    [[[NSURLSession sharedSession] dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (errorPtr != NULL) {
            *errorPtr = error;
        }
        if (responsePtr != NULL) {
            *responsePtr = response;
        }
        if (error == nil) {
            result = data;
        }
        dispatch_semaphore_signal(sem);
    }] resume];

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

   return result;
}

@end
