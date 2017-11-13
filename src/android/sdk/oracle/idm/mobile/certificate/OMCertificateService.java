/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.certificate;

import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

import oracle.idm.mobile.crypto.CryptoScheme;
import oracle.idm.mobile.logging.OMLog;

/**
 * This class provides access to SDK's keystore. The keystore is intended to
 * store the untrusted server certificates accepted by the application. It can
 * also store the client certificates having private keys. Usage: pass the
 * application context in the {@link OMCertificateService} constructor. The SDK uses a
 * default password to protect the integrity of the keystore.
 *
 * @since 11.1.2.3.1
 */
public class OMCertificateService {

    private static final String TAG = OMCertificateService.class.getSimpleName();
    private static final String OM_TRUSTSTORE_NAME = "omTrustStore.bks";
    private static final String OM_KEYSTORE_NAME = "omKeyStore.bks";
    private static final String KEYSTORE_TYPE_PKCS12 = "pkcs12";
    private final char[] OM_TRUSTSTORE_PWD = OM_TRUSTSTORE_NAME.toCharArray(); //change to secure // TODO: 2/23/2016
    private final char[] OM_KEYSTORE_PWD = OM_KEYSTORE_NAME.toCharArray();//change to secure // TODO: 2/23/2016
    private static final char[] HEX_CHARS =
            {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
                    'E', 'F'};

//    NOTE: Copied from android.net.http.SslCertificate. This needs to be checked for any change when Android update is made.
    // Begin : android.net.http.SslCertificate constants
    /**
     * Bundle key names
     */
    private static final String X509_CERTIFICATE = "x509-certificate";
    // End : android.net.http.SslCertificate constants

    private Context mContext;

    private KeyStore mTrustStore;//SDK's trust store - for storing self signed root certificates/server trust certificates.
    private KeyStore mKeyStore;//SDK's key store - for storing private key certificates.
    private KeyStore mAndroidKeyStore;
    private boolean isAndroidKeyStore;

    enum KeyStoreType {
        TRUSTSTORE, KEYSTORE
    }

    /*FIXME Should consider pros and cons of convering this to Singleton:
    Singelton:
    Pros:
    Mutliple instances being created across SDK code will be comutationally intensive as keystores are being read from file

    */

    /**
     * This initializes the app level KeyStore and TrustStore maintained by the SDK. This
     * is equivalent to calling {@link OMCertificateService#OMCertificateService(Context, ClientCertificatePreference.Storage)}
     * with {@link ClientCertificatePreference.Storage#APP_LEVEL_KEYSTORE}.
     * So, client certificate operations (import, delete) on objects created using this constructor
     * will be performed only on app level Java KeyStore.
     * <p/>
     * To perform these operations on AndroidKeyStore, use {@link OMCertificateService#OMCertificateService(Context, ClientCertificatePreference.Storage)}
     * with {@link oracle.idm.mobile.certificate.ClientCertificatePreference.Storage#APP_LEVEL_ANDROID_KEYSTORE}.
     *
     * @param context Application context
     */
    public OMCertificateService(Context context) throws CertificateException {
        this(context, ClientCertificatePreference.Storage.APP_LEVEL_KEYSTORE);
    }

    /**
     * This initializes keystore based on clientCertificateStorage and the app level
     * TrustStore.
     *
     * @param context                  Application context
     * @param clientCertificateStorage used to specify the client certificate storage type
     */
    public OMCertificateService(Context context,
                                ClientCertificatePreference.Storage clientCertificateStorage) throws CertificateException {
        if (context == null || clientCertificateStorage == null) {
            throw new IllegalArgumentException("Arguments can not be null!");
        }

        mContext = context;
        initTrustStore();
        initKeyStore(clientCertificateStorage);
    }

    /**
     * This will return the trust store maintained by the SDK , used by the
     * SDKSocketFactory which internally is used by the DefaultHTTPClient. This
     * is the only trust store maintained and referred by any network call by
     * the SDK.
     *
     * @return {@link KeyStore}
     * @hide Internal API
     */
    public KeyStore getTrustStore() {
        return mTrustStore;
    }


    /**
     * Imports the given certificate file in the SDK's trust store.If there is
     * any issue in importing the certificate, the SDK throws
     * {@link CertificateException}.
     *
     * @param certFile certificate file .
     * @throws CertificateException
     */
    public void importServerCertificate(File certFile)
            throws CertificateException {
        if (certFile == null) {
            throw new IllegalArgumentException(
                    "Certificate file can not be null.");
        }
        X509Certificate x509Certificate = getX509CertificateFromFile(certFile);
        if (x509Certificate != null) {
            importServerCertificate(x509Certificate);
        } else
            throw new CertificateException();//TODO
    }

    /**
     * Imports the {@link X509Certificate} Object in the SDK's trust Store.
     *
     * @param certificate The {@link X509Certificate} object.
     * @throws CertificateException
     */
    public void importServerCertificate(X509Certificate certificate)
            throws CertificateException {
        if (certificate == null) {
            throw new IllegalArgumentException(
                    "Server Certificate can not be null.");
        }
        String alias = certificate.getSubjectDN() + " ("
                + certificate.getSerialNumber().toString() + ")";
        try {
            // since we are forming an alias internally so its specific to a
            // certificate, let us check if this alias already exists if no then
            // install other wise avoid import.
            boolean matchFound = false;
            Enumeration<String> aliases = mTrustStore.aliases();
            while (aliases.hasMoreElements()) {
                String aliasFromKeystore = aliases.nextElement();
                if (aliasFromKeystore.equals(alias)) {
                    matchFound = true;
                    break;
                }
            }
            if (!matchFound) {
                mTrustStore.setCertificateEntry(alias, certificate);

                saveTrustStore();
            } else {
                OMLog.debug(TAG, "Server Certificate already exists in the TrustStore.");
            }
            refresh(KeyStoreType.TRUSTSTORE);
        } catch (GeneralSecurityException gse) {
            if (gse instanceof CertificateException) {
                throw (CertificateException) gse;
            }
            throw new CertificateException(gse.getMessage(), gse);
        }
    }

    /**
     * Gets server aliases available in the application trust store..
     *
     * @return {@link Enumeration} with all aliases available in trust store.
     */
    public Enumeration<String> getInstalledServerAliases() throws CertificateException {
        try {
            if (mTrustStore != null) {
                return mTrustStore.aliases();
            }
        } catch (Exception e) {
            throw new CertificateException(e.getMessage());
        }
        return null;
    }

    /**
     * Returns the {@link List} of {@link OMCertificateInfo} of all the server
     * certificates stored in the application trust store.
     *
     * @return
     * @throws CertificateException
     */
    public List<OMCertificateInfo> getAllInstalledServerCertificateInfo()
            throws CertificateException {
        List<OMCertificateInfo> certInfoList = null;
        if (mTrustStore != null) {
            certInfoList = new ArrayList<>();
            Enumeration<String> aliases = getInstalledServerAliases();
            while (aliases != null && aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                OMCertificateInfo certificateInfo = getServerCertificateInfo(alias);
                if (certificateInfo != null) {
                    certificateInfo.setAlias(alias);
                    certInfoList.add(certificateInfo);
                }
            }
        }
        return certInfoList;
    }


    /**
     * Returns the {@link X509Certificate} associated with the given alias.
     * <p/>
     *
     * @param alias
     * @return
     * @throws CertificateException
     * @hide Internal API
     */
    public X509Certificate getServerCertificate(String alias)
            throws CertificateException {
        X509Certificate certificate = null;
        if (mTrustStore != null) {
            try {
                certificate = (X509Certificate) mTrustStore
                        .getCertificate(alias);
            } catch (Exception e) {
                throw new CertificateException(e.getMessage());
            }
        }
        return certificate;
    }

    /**
     * This method deletes the specified server certificate installed in the
     * TrustStore.
     *
     * @throws CertificateException
     */

    public void deleteServerCertificate(OMCertificateInfo certificateInfo)
            throws CertificateException {
        if (mTrustStore != null && certificateInfo != null) {
            OMLog.info(TAG, "Deleting Server certificate for : " + certificateInfo.getAlias());
            deleteCertificateEntryInternal(mTrustStore, certificateInfo);
            saveTrustStore();
        }
    }

    /**
     * This method removes all the server certificates installed in the local
     * TrustStore.
     *
     * @throws CertificateException
     */
    public void deleteAllServerCertificates() throws CertificateException {
        if (mTrustStore != null) {
            List<OMCertificateInfo> certificateInfoList = getAllInstalledServerCertificateInfo();
            for (OMCertificateInfo certificateInfo : certificateInfoList) {
                deleteCertificateEntryInternal(mTrustStore, certificateInfo);
            }
            saveTrustStore();
        }
    }


    /**
     * Returns the certificate finger print based on the passed hash based {@link CryptoScheme}.
     *
     * @param certificate
     * @param scheme
     * @return
     * @throws CertificateException
     */
    public static String getFingerPrint(X509Certificate certificate, CryptoScheme scheme) throws CertificateException {

        if (certificate == null) {
            throw new IllegalArgumentException("Invalid or null certificate.");
        }
        if (scheme == null || !CryptoScheme.isHashAlgorithm(scheme)) {
            throw new IllegalArgumentException("Invalid hash algorithm.");
        }
        MessageDigest shaMd = null;
        try {
            shaMd = MessageDigest.getInstance(scheme.getValue());
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }

        return convertByteToHex(shaMd.digest(certificate.getPublicKey()
                .getEncoded()));
    }

    private static String convertByteToHex(byte[] data) {
        int n = data.length;
        StringBuffer sb = new StringBuffer(n * 3 - 1);
        for (int i = 0; i < n; i++) {
            if (i > 0)
                sb.append(':');
            sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
            sb.append(HEX_CHARS[data[i] & 0x0F]);
        }
        return sb.toString();
    }

    /**
     * Imports the client certificates(.p12,.pfx) into app level android keystore or
     * bouncy castle keystore, depending on the storage option used in
     * {@link OMCertificateService#OMCertificateService(Context, ClientCertificatePreference.Storage)}.
     * NOTE: This SHOULD be called from a background thread as this method does File I/O.
     *
     * @param file A valid local file URL of the certificate file.
     * @param pwd  Password for the Client Certificate.
     * @throws CertificateException
     */
    public void importClientCertificate(File file, char[] pwd)
            throws CertificateException {
        if (file == null) {
            throw new IllegalArgumentException(
                    "Client Certificate File can not be null.");
        }
        if (pwd == null) {
            throw new IllegalArgumentException(
                    "Client Certificate Password can not be null.");
        }
        try {
            importClientCertificateLocalInternal(file, pwd);
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    /**
     * API to return the {@link X509KeyManager} associated with the default
     * keystore maintained by the cert service.
     * internal API
     *
     * @hide
     */
    public X509KeyManager getDefaultKeyManager() throws GeneralSecurityException {
        if (mKeyStore != null) {
            KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            if (isAndroidKeyStore) {
                kmf.init(mKeyStore, null);
            } else {
                kmf.init(mKeyStore, OM_KEYSTORE_PWD);
            }
            return (X509KeyManager) kmf.getKeyManagers()[0];
        }
        return null;
    }

    /**
     * API to return the {@link KeyStore.PrivateKeyEntry} corresponding to the alias
     * passed and the storage preference passed.
     *
     * @param alias   certificate alias
     * @param storage the storage from where the client certificate should be retrieved
     * @return PrivateKeyEntry
     * @throws GeneralSecurityException
     * @throws KeyChainException
     * @throws InterruptedException
     * @hide
     */
    public KeyStore.PrivateKeyEntry getPrivateEntry(String alias, ClientCertificatePreference.Storage storage)
            throws GeneralSecurityException, KeyChainException, InterruptedException {

        if (storage == ClientCertificatePreference.Storage.SYSTEM_LEVEL_KEYSTORE) {
            //handle system alias
            OMLog.debug(TAG, "Getting PrivateKeyEntry from SYSTEM_LEVEL_KEYSTORE credentialStorage for : " + alias);
            return new KeyStore.PrivateKeyEntry(KeyChain.getPrivateKey(mContext,
                    alias), KeyChain.getCertificateChain(mContext, alias));
        } else {
            KeyStore.PrivateKeyEntry entry = null;
            if (alias != null && mKeyStore != null) {
                if (storage == ClientCertificatePreference.Storage.APP_LEVEL_ANDROID_KEYSTORE
                        && getAndroidKeyStore() != null) {
                    entry = (KeyStore.PrivateKeyEntry) getAndroidKeyStore().getEntry(alias, null);
                } else {
                    entry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(alias,
                            new KeyStore.PasswordProtection(OM_KEYSTORE_PWD));
                }
            }
            return entry;
        }
    }

    /**
     * Returns all the client aliases stored in the application KeyStore.
     *
     * @return
     */
    public Enumeration<String> getInstalledClientAliases() throws CertificateException {
        if (mKeyStore != null) {
            try {
                return mKeyStore.aliases();
            } catch (KeyStoreException e) {
                throw new CertificateException(e);
            }
        }
        return null;
    }

    /**
     * Returns the {@link List} of {@link OMCertificateInfo} of all the client
     * certificates stored in the application KeyStore.
     *
     * @return
     * @throws CertificateException
     */
    public List<OMCertificateInfo> getAllInstalledClientCertificateInfo()
            throws CertificateException {
        List<OMCertificateInfo> certInfoList = null;
        if (mKeyStore != null) {
            certInfoList = new ArrayList<>();
            Enumeration<String> aliases = getInstalledClientAliases();
            while (aliases != null && aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                OMCertificateInfo certificateInfo = getClientCertificateInfo(alias);
                certificateInfo.setAlias(alias);
                certInfoList.add(certificateInfo);
            }
        }
        return certInfoList;
    }

    /**
     * API to delete specified client certificate stored in the KeyStore.
     *
     * @throws CertificateException
     */

    public void deleteClientCertificate(final OMCertificateInfo certificateInfo)
            throws CertificateException {
        if (mKeyStore != null && certificateInfo != null) {
            OMLog.info(TAG, "Deleting Client Certificate");
            deleteCertificateEntryInternal(mKeyStore, certificateInfo);
            saveKeyStore();
        }
    }

    /**
     * This method deletes all the client certificates installed in the
     * KeyStore.
     *
     * @throws CertificateException
     */
    public void deleteAllClientCertificates() throws CertificateException {

        if (mKeyStore != null) {
            OMLog.info(TAG, "Deleting All Client certificates!");
            List<OMCertificateInfo> certInfoList = getAllInstalledClientCertificateInfo();
            for (OMCertificateInfo certificateInfo : certInfoList) {
                deleteCertificateEntryInternal(mKeyStore, certificateInfo);
            }
            saveKeyStore();
        }
    }

    /**
     * This method parses the byte array contained in the bundle into X509Certificate object.
     * Note: This is NOT supposed to be used by developers. It is meant only for internal use.
     *
     * @param bundle
     * @return
     * @hide
     */
    public static X509Certificate convertToX509Certificate(Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        X509Certificate x509Certificate;
        byte[] bytes = bundle.getByteArray(X509_CERTIFICATE);
        if (bytes == null) {
            x509Certificate = null;
        } else {
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(bytes));
                x509Certificate = (X509Certificate) cert;
            } catch (CertificateException e) {
                x509Certificate = null;
            }
        }
        return x509Certificate;
    }


    /*
     * This is a utility method to convert a certificate file to a
     * {@link X509Certificate} object.
     *
     * @param certFile
     * @return
     * @throws CertificateException
     */
    private X509Certificate getX509CertificateFromFile(File certFile)
            throws CertificateException {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(certFile);
            CertificateFactory certFactory = CertificateFactory
                    .getInstance("X.509");
            DataInputStream dis = new DataInputStream(fis);
            byte[] certBytes;
            try {
                certBytes = new byte[dis.available()];
                dis.readFully(certBytes);
                Certificate cert = certFactory
                        .generateCertificate(new ByteArrayInputStream(certBytes));
                if (cert instanceof X509Certificate) {
                    return (X509Certificate) cert;
                }
            } catch (IOException e) {
                throw new CertificateException(e);
            } finally {
                try {
                    dis.close();
                } catch (IOException ioe) {
                    // do nothing
                }
            }

        } catch (FileNotFoundException e) {
            throw new CertificateException(e);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException ioe) {
                    // do nothing
                }
            }
        }
        return null;
    }

    /**
     * Returns the {@link OMCertificateInfo} for the specified server alias stored in
     * the KeyStore.
     *
     * @param alias
     * @return
     * @throws CertificateException
     */
    private OMCertificateInfo getServerCertificateInfo(String alias)
            throws CertificateException {
        if (mTrustStore != null) {
            try {
                return new OMCertificateInfo(
                        (X509Certificate) mTrustStore.getCertificate(alias));
            } catch (KeyStoreException e) {
                throw new CertificateException(e);
            }
        }
        return null;
    }

    /**
     * Internal API to initialize the SDK trustStore.
     */
    private void initTrustStore() throws CertificateException {
        try {
            mTrustStore = KeyStore.getInstance(KeyStore.getDefaultType());// BKS
        } catch (KeyStoreException e) {
            OMLog.error(TAG,
                    "Error Initializing TrustStore : "
                            + e.getLocalizedMessage());
            Log.i(TAG, e.getMessage(), e);
            throw new CertificateException(e);
        }

        FileInputStream is = null;
        try {
            is = mContext.openFileInput(OM_TRUSTSTORE_NAME);
            mTrustStore.load(is, OM_TRUSTSTORE_PWD);
            Log.v(TAG, "Initialized app-level BKS TrustStore");
        } catch (Exception e) {
            if (mTrustStore != null) {
                try {
                    mTrustStore.load(null, OM_TRUSTSTORE_PWD);
                } catch (Exception e1) {
                    OMLog.error(TAG, " " + e1.getLocalizedMessage());
                }
            }
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    // Do nothing.
                }
            }

        }
    }

    /**
     * Internal API to save the truststore in the file system.
     *
     * @throws CertificateException
     */
    private void saveTrustStore() throws CertificateException {
        FileOutputStream fos = null;
        try {
            fos = mContext.openFileOutput(OM_TRUSTSTORE_NAME,
                    Context.MODE_PRIVATE);
            mTrustStore.store(fos, OM_TRUSTSTORE_PWD);
            OMLog.debug(TAG, "TrustStore Saved!");
        } catch (Exception e) {
            throw new CertificateException(e.getMessage());
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (Exception e) {
                // do nothing.
            }
        }
    }


    /**
     * Internal API to initialize the SDK KeyStore.
     */
    private void initKeyStore(ClientCertificatePreference.Storage clientCertificateStorage) {
        if (clientCertificateStorage == ClientCertificatePreference.Storage.APP_LEVEL_ANDROID_KEYSTORE) {
            mKeyStore = getAndroidKeyStore();
            return;
        }

        try {
            mKeyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
        } catch (KeyStoreException e) {
            OMLog.error(TAG,
                    "Error while Initializing KeyStore : " + e.getLocalizedMessage());
        }

        FileInputStream is = null;
        try {
            is = mContext.openFileInput(OM_KEYSTORE_NAME);
            mKeyStore.load(is, OM_KEYSTORE_PWD);
            Log.v(TAG, "Initialized app-level Java KeyStore");
        } catch (Exception e) {
            if (mKeyStore != null) {
                try {
                    mKeyStore.load(null, OM_KEYSTORE_PWD);
                } catch (Exception e1) {
                    // Do nothing
                }
            }
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e) {
                    // Do nothing
                }
            }
        }
    }

    private KeyStore getAndroidKeyStore() {
        if (mAndroidKeyStore == null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                try {
                    mAndroidKeyStore = KeyStore.getInstance("AndroidKeyStore");
                    mAndroidKeyStore.load(null);
                    isAndroidKeyStore = true;
                    Log.v(TAG, "Initialized AndroidKeyStore");
                } catch (Exception e) {
                    Log.e(TAG, e.getMessage());
                }
            }
        }
        return mAndroidKeyStore;
    }

    /**
     * Internal API for importing the client certificate.
     *
     * @param file
     * @param pwd
     * @return
     * @throws CertificateException
     * @throws IOException
     */
    private String importClientCertificateLocalInternal(File file, char[] pwd)
            throws CertificateException, IOException {
        String alias = null;
        boolean privateKeyFound = false;
        FileInputStream is = null;
        try {
            is = new FileInputStream(file);
            KeyStore tmpKeyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
            tmpKeyStore.load(is, pwd);
            Enumeration<String> aliases = tmpKeyStore.aliases();
            if (mKeyStore != null) {
                if (aliases != null) {
                    while (aliases.hasMoreElements() && !privateKeyFound) {
                        alias = aliases.nextElement();
                        Certificate[] chain = tmpKeyStore
                                .getCertificateChain(alias);
                        Key key = tmpKeyStore.getKey(alias, pwd);
                        if ((key instanceof PrivateKey)) {
                            privateKeyFound = true;
                            if (isAndroidKeyStore) {
                                // entries cannot be protected with passwords in
                                // AndroidKeyStore
                                mKeyStore.setKeyEntry(alias, key, null, chain);
                            } else {
                                mKeyStore.setKeyEntry(alias, key, OM_KEYSTORE_PWD,
                                        chain);
                            }
                        }
                    }
                    if (privateKeyFound) {
                        saveKeyStore();
                    } else {
                        throw new CertificateException(
                                "Private Key not found in the certificate file!");
                    }
                } else {
                    throw new CertificateException(
                            "No Aliases found in the certificate file!");
                }
            } else {
                // just log.
                OMLog.error(TAG, "Keystore is null, import operation failed!");
            }
        } catch (GeneralSecurityException e) {
            Log.i(TAG, e.getMessage(), e);
            if (e instanceof CertificateException) {
                throw (CertificateException) e;
            } else
                throw new CertificateException(e);
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (Exception e) {
                // nothing
            }
        }
        OMLog.debug(TAG, "Imported Client Certificate CN = "
                + getClientCertificateInfo(alias).getCommonName());
        return alias;
    }

    /**
     * Returns the {@link OMCertificateInfo} for the specified client alias stored in
     * the KeyStore.
     *
     * @param alias
     * @return
     * @throws CertificateException
     */
    private OMCertificateInfo getClientCertificateInfo(String alias)
            throws CertificateException {
        if (mKeyStore != null) {
            try {
                OMCertificateInfo certInfo = new OMCertificateInfo(
                        (X509Certificate) mKeyStore.getCertificate(alias));
                certInfo.setAlias(alias);
                return certInfo;
            } catch (KeyStoreException e) {
                throw new CertificateException(e);
            }
        }
        return null;
    }


    /**
     * Internal API to save the keystore to the file system.
     *
     * @throws CertificateException
     */
    private void saveKeyStore() throws CertificateException {
        if (isAndroidKeyStore) {
            /*
             * store() results in UnSupportedOperationException for
             * AndroidKeyStore. It cannot be serialized to OutputStream.
             * Verified that client certificates stored once are available after
             * app restart. So, doing nothing here.
             */
            return;
        }
        FileOutputStream fos = null;
        try {
            fos = mContext.openFileOutput(OM_KEYSTORE_NAME,
                    Context.MODE_PRIVATE);
            mKeyStore.store(fos, OM_KEYSTORE_PWD);
            OMLog.debug(TAG, "KeyStore Saved!");
        } catch (Exception e) {
            throw new CertificateException(e.getMessage());
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (Exception e) {
                // do nothing.
            }
        }
    }

    /**
     * Deleted client certificate from the application keystore.
     *
     * @param keystore
     * @param certificateInfo
     * @throws CertificateException
     */
    private void deleteCertificateEntryInternal(KeyStore keystore,
                                                final OMCertificateInfo certificateInfo) throws CertificateException {
        if (keystore != null && certificateInfo != null) {
            try {
                keystore.deleteEntry(certificateInfo.getAlias());
                OMLog.debug(TAG,
                        "Deleted Certificate CN = "
                                + certificateInfo.getCommonName());

            } catch (KeyStoreException e) {
                throw new CertificateException(e);
            }
        }
    }

    /**
     * Internal API which refreshes the given {@link KeyStore} object based on
     * the {@link KeyStoreType} provided. So that any connection which has a
     * dependency on this {@link KeyStore} will get an updated reference.
     *
     * @throws CertificateException
     */
    private void refresh(KeyStoreType type) throws CertificateException {
        FileInputStream is = null;
        try {
            switch (type) {
                case TRUSTSTORE:
                    is = mContext.openFileInput(OM_TRUSTSTORE_NAME);
                    mTrustStore.load(is, OM_TRUSTSTORE_PWD);
                    iterate(mTrustStore);
                    break;
                case KEYSTORE:
                    if (isAndroidKeyStore) {
                        // In-memory instance is already up-to-date.
                        return;
                    }
                    is = mContext.openFileInput(OM_KEYSTORE_NAME);
                    mKeyStore.load(is, OM_KEYSTORE_PWD);
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            OMLog.info(TAG, "Error Refreshing : " + type.name() + " " + e.getLocalizedMessage());
            Log.i(TAG, e.getMessage(), e);//logging the entire stack
            throw new CertificateException(e);
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (Exception e) {
                // do nothing
            }
        }
        OMLog.debug(TAG, "Done Refreshing : " + type.name());
    }

    /*
     * Internal API to iterate over the KeyStore.
     *
     */
    private void iterate(KeyStore keystore) {
        try {
            Enumeration<String> e = keystore.aliases();

            if (!e.hasMoreElements()) {
                OMLog.debug(TAG, "Empty Keystore");
            }
            while (e.hasMoreElements()) {
                // good to have for debugging purpose.
                OMLog.debug(TAG, "Available alias : " + e.nextElement());
            }
        } catch (Exception ignored) {
            //eat the exception if any, as this is just for logging.
        }
    }
}
