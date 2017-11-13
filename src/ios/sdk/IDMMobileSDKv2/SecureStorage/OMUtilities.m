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

@end
