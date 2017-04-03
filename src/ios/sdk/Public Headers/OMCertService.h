/* Copyright (c) 2011, 2014, Oracle and/or its affiliates. 
All rights reserved.*/

/*
 NAME
 OMCertService.h - Oracle Mobile Certificate Service
 
 DESCRIPTION
 Takes care of certificate operations
 
 RELATED DOCUMENTS
 None
 
 PROTOCOLS DEFINED
 None
 
 PROTOCOLS IMPLEMENTED
 
 CATEGORIES/EXTENSIONS
 None
 
 EXAMPLES
 None
 
 NOTES
 None
 
 msadasiv    01/24/13 - Creation
 */

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "OMCertInfo.h"
@protocol OMCertServiceDelegate;

@interface OMCertService : NSObject

/**
 * Evaluate Server Trust challenge, throw alert to user if required
 * and add certs to keychain.
 *
 * @param challenge         Reference to challenge object got from
 *                          NSURLConnection delegate
 *                          connection:didReceiveAuthenticationChallege
 */
+ (void) evaluateTrustAndRespondToChallenge:
(NSURLAuthenticationChallenge *) challenge;

/**
 * Returns OMAsyncConnectionHandler object initialized with operation handler
 *
 * @param trustRef          Reference to trust object that contains certificate
 *                          chain.
 * @return                  status of adding certs to keychain
 */
+(BOOL) addToKeyChainAllCertsInTrust:(SecTrustRef) trustRef;

/**
 * Returns a summary of the leaf certificate for showing to user
 *
 * @param trustRef          Reference to trust object that contains certificate
 *                          chain.
 * @return                  Returns summary of certificate or nil on error.
 */
+(NSString *) certSummaryInTrust:(SecTrustRef) trustRef;

/* Returns all the certificates stored by the app in keychain.
 * @return An array containing all the certificates stored in keychain by the
 *         app.
 */
+(NSArray *) allServerCertificates;

/**
 * Reads a DER encoded certficate available at file path and adds it to
 * keychain. If a server is using self signed certificates then adding 
 * certificates will suppress the trust warning shown by SDK.
 * @param filePath  A string containing location of certificate file
 * @param error     NSError object if any error was encountered while importing
 *                  certificate from file to keychain
 * @return          Returns true if certificate is successfully read and added 
 *                  to keychain. Returns false if there was any error either in
 *                  reading certificate or adding it to keychain.
 */
+(BOOL) importServerCertificateFromFilePath:(NSURL *)filePath
                                      error:(NSError **)error;

/*
 * Adds a certficate object to keychain. If a server is using self signed
 * certificates then adding certificates will suppress the trust warning shown 
 * by SDK.
 * @param certRef Certificate reference to be added to keychain
 * @param error   NSError object if any error was encountered while importing
 *                certificate to keychain
 * @return        Returns true if certificate is added successfully else false.
 */
+(BOOL) importServerCertificateFromRef:(SecCertificateRef)certificate
                                    error:(NSError **)error;

/*
 * Adds leaf certficate from server trust to keychain
 * @param trustRef Reference to trust object that contains certificate
 *                 chain.
 * @return Returns true if certificate is added successfully else false.
 */
+(BOOL) addLeafCertificateFromTrust:(SecTrustRef) trustRef;

/*
 * Extracts client identity from a file, imports it to the keychain and deletes 
 * the client certifiacte file.
 * @param fileURL Local file URL of client certificate file
 * @param password String to decrypt the file
 * @param error NSError object if any error was encountered while importing
 *              certificate to keychain
 * @return Returns a dictionary containing information of imported 
 *         client identity
 */
+(NSArray *) importClientCertificateFromFile:(NSURL *)fileURL
                               password:(NSString *)password
                                  error:(NSError **)error;

/*
 * Extract all the identities from a p12 file and return an arry of identities.
 * @param fileURL Local file URL of client certificate file
 * @param password String to decrypt the file
 * @param error NSError object if any error was encountered while extracting
 *              identitites from file
 * @return Returns an array of SecIdentityRef
 */

+(NSArray *) identitiesFromFile:(NSURL *)fileURL
                        withPassword:(NSString *)password
                               error:(NSError **)error;
/*
 * Adds a SecIdentityRef to keychain
 * @param identityRef The identity to be added to keychain
 * @param error NSError object if any error was encountered while importing
 *              certificate to keychain
 * @return Returns true if import is successful
 */
+(BOOL) importClientCertificate:(SecIdentityRef)identityRef
                          error:(NSError **)error;

/*
 * All client identities availabel in keychain
 * @return Returns an array of SecIdentityRef that were found in keychain
 */
+(NSArray *)allClientIdentities;

/*
 * All OMCertInfo objects for  client identities availabel in keychain
 * @param Array of identityRef 
 * @return Returns an array of OMCertInfo
 */

+ (NSMutableArray *)getCertInfoForIdentities:(NSArray *)clientIdenties;

/*
 * Removes all client identities from the keychain.
 * @param error A NSError reference that will be populated if any error happens 
 *              while removing the identities from keychain
 * @return Number of identities removed
 */
+(int) clearAllClientCertificates:(NSError **)error;

/*
 * Removes all server certificates from the keychain.
 * @param error A NSError reference that will be populated if any error happens
 *              while removing the identities from keychain
 * @return Number of certificates removed
 */
+(int) clearAllServerCertificates:(NSError **)error;

/*
 * If any client identity is installed in keychain
 * @return true if a client identity is available
 */
+(BOOL)isClientIdentityInstalled;

/*
 * Information of a client identity.
 * @param identity SecIdentityRef for which the information is required
 * return A dictionary of the extracted information.
 */
+(OMCertInfo *)infoForClientCertificate:(SecIdentityRef)identity;

+(void)persistClientCertChallengeReceivedForHost:(NSString *)host
                                            port:(NSInteger)port;

+(BOOL)wasClientCertChallengeReceivedPreviouslyForHost:(NSString *)host
                                                  port:(NSInteger)port;

/*
 * Information about all client certificates installed by the app
 * @return Returns a NSArray of OMCertInfo objects
 */
+(NSArray *)infoForAllClientCertificates;

/*
 * Deletes a client certificate from keychain corresponding to OMCertInfo object
 * @param certInfo An OMCertInfo object that is the client identity to be
 *                 removed from keychain
 * @param error A NSError reference that will be populated if any error happens
 *              while removing the identity from keychain
 */
+(BOOL)deleteClientCertificate:(OMCertInfo *)certInfo error:(NSError **)error;

/*
 * Finds the issuuers of the provided certificate
 * @param cert A SecCertificateRef object whose issuer chain is to be found
 * return Array of issuer certifiactes
 */
+(NSArray *)listOfConnectedCertsFor:(SecCertificateRef)cert;


+ (NSURLCredential *)getCretCredentialForIdentity:(SecIdentityRef)identityRef;

+ (SecTrustResultType ) evaluateTrustResultForChallenge:
(NSURLAuthenticationChallenge *) challenge withError:(OSStatus*)err;

@end

@protocol OMCertServiceDelegate <NSObject>

@required
-(void)didImportClientCertificate:(NSArray *)certInfo
                            error:(NSError *)error;
@end
