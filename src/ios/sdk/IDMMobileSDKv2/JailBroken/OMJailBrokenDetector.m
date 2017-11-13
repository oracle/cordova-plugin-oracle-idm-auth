/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */



#import "OMJailBrokenDetector.h"
#import <UIKit/UIKit.h>
#include <sys/stat.h>

@implementation OMJailBrokenDetector

+ (BOOL)isDeviceJailBroken
{
    
    if ([self isRunningOnSimulator])
    {
        
        return NO;
    }
    
    @try {
        BOOL isAppTampered = NO;
        isAppTampered = [self checkUserIdentifier];
        if (isAppTampered)
        {
            return YES;
        }
        
        BOOL maliciousApps = [self checkForJailBrokenApps];
        if (maliciousApps)
        {
            return YES;
        }
        
        BOOL accessToPrivateFiles = [self accessToPrivateFiles];
        if (accessToPrivateFiles)
        {
            return YES;
        }
        
        BOOL isBroken = [self checkSymbolicLink];
        if (isBroken)
        {
            return YES;
        }
        
         isBroken = [self checkSandBoxIntegrity];
        if (isBroken)
        {
            return YES;
        }
        
        isBroken = [self writeToPrivate];
        if (isBroken)
        {
            return YES;
        }


    }
    @catch (NSException *exception)
    {
        return NO;
    }
    return NO;
}

+ (BOOL)checkUserIdentifier
{
    if ([[[NSBundle mainBundle] infoDictionary]
            objectForKey:@"SignerIdentity"] != nil)
    {
        // Jailbroken
        return YES;
    }
    return NO;
}

+ (BOOL)accessToPrivateFiles;
{
    NSArray *jailbrokenPath = [NSArray arrayWithObjects:
                               @"/usr/sbin/sshd",
                               @"/usr/bin/sshd",
                               @"/usr/libexec/sftp-server",
                               @"/private/var/lib/apt",
                               @"/private/var/stash",
                               @"/System/Library/LaunchDaemons/com.ikey.bbot.plist",
                               nil];
    
    BOOL isPrivateFileAccessible = NO;
    for(NSString *string in jailbrokenPath)
    {
        if ([[NSFileManager defaultManager] fileExistsAtPath:string])
        {
            isPrivateFileAccessible = YES;
            break;
        }
    }
    
    return isPrivateFileAccessible;
}

+ (BOOL)checkForJailBrokenApps
{
    BOOL isJailBroken = NO;
    NSArray *jailbrokenPath;
    
    jailbrokenPath = [NSArray arrayWithObjects:
                   @"/Applications/Cydia.app",
                   @"/Applications/xCon.app",
                   @"/Applications/RockApp.app",
                   @"/Applications/Icy.app",
                   @"/Applications/WinterBoard.app",
                   @"/Applications/SBSettings.app",
                   @"/Applications/MxTube.app",
                   @"/Applications/IntelliScreen.app",
                   @"/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
                   @"/Applications/FakeCarrier.app",
                   @"/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
                   @"/Applications/blackra1n.app",
                   @"/private/var/mobile/Library/SBSettings/Themes", nil];
    
    for(NSString *string in jailbrokenPath)
    {
        if ([[NSFileManager defaultManager] fileExistsAtPath:string])
        {
            isJailBroken = YES;
            break;
        }
    }
    return isJailBroken;
}

+ (BOOL)writeToPrivate
{
    BOOL isBroken = NO;
    
    //Try to write file in private
    NSError *error;
    
    [[NSString stringWithFormat:@"Jailbreak test string"]
     writeToFile:@"/private/test_jb.txt"
     atomically:YES
     encoding:NSUTF8StringEncoding error:&error];
    
    if(nil==error)
    {
        //Wrote?: JB device
        //cleanup what you wrote
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/test_jb.txt"
                                                   error:nil];
        isBroken = YES;
    }
    
    return isBroken;
}

+ (BOOL)checkSymbolicLink
{
    BOOL isBroken = NO;

    struct stat s;
    
    if(lstat("/Applications", &s) ||
       lstat("/var/stash/Library/Ringtones", &s) ||
       lstat("/var/stash/Library/Wallpaper", &s)||
       lstat("/var/stash/usr/include", &s)||
       lstat("/var/stash/usr/libexec", &s)  ||
       lstat("/var/stash/usr/share", &s) ||
       lstat("/var/stash/usr/arm-apple-darwin9", &s))
    {
        if(s.st_mode & S_IFLNK)
        {
            isBroken = YES;
        }
    }
    return isBroken;

}

+ (BOOL)checkSandBoxIntegrity
{
    BOOL isBroken = NO;

    int pid = fork();
    if(!pid){
        exit(0);
    }
    if(pid>=0)
    {
        isBroken = YES;
    }
    return isBroken;

}

+ (BOOL)isRunningOnSimulator
{
    NSString *deviceModel = [[UIDevice currentDevice] model];
    NSRange strRange = [deviceModel rangeOfString:@"Simulator"];

    if (strRange.location != NSNotFound)
    {
        return YES;
    }
    return NO;
}

@end
