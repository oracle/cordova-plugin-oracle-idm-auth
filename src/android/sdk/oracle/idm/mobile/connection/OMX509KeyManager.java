/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import android.content.Context;
import android.security.KeyChainException;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

import oracle.idm.mobile.certificate.ClientCertificatePreference;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.logging.OMLog;

/**
 * SDK's X509KeyManager impl for its connections.
 */
class OMX509KeyManager extends X509ExtendedKeyManager {
    private static final String TAG = OMX509KeyManager.class.getSimpleName();
    private Context mContext;
    private String mCertificateAlias;
    private X509KeyManager mX509KeyManager;
    private OMCertificateService mCertificateService;
    private KeyStore.PrivateKeyEntry mPrivateKeyEntry;
    private ClientCertificatePreference mClientCertificatePreference;
    private String[] mClientAuthKeyTypes;
    private Principal[] mClientAuthIssuers;
    private boolean mClientCertRequired, mDefaultImplProvided;
    private Principal mPeerPrincipal;
    private String mPeerHost;
    private int mPeerPort = -1;

    OMX509KeyManager(OMCertificateService certificateService, final X509KeyManager x509KeyManager) {
        mCertificateService = certificateService;
        mX509KeyManager = x509KeyManager;
        if (mX509KeyManager != null) {
            mDefaultImplProvided = true;
        }
    }

    OMX509KeyManager(OMCertificateService certificateService, final X509KeyManager x509KeyManager, ClientCertificatePreference preference) {
        this(certificateService, x509KeyManager);
        mClientCertificatePreference = preference;
        //can be default preference
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        OMLog.info(TAG, "Client Certificate Required!!");

        if (!mClientCertRequired) {
            SSLSocket session = ((SSLSocket) socket);
            mPeerHost = session.getInetAddress().getHostName();
            mPeerPort = session.getPort();
            OMLog.info(TAG, "For host: "+mPeerHost +" port: "+mPeerPort);
        }

        //lets see if we already have the keys in the default keymanager we have already provided.
        mClientCertRequired = true;
        mClientAuthKeyTypes = keyType;
        mClientAuthIssuers = issuers;

        if (mDefaultImplProvided) {//means we already have default impl
            return mX509KeyManager.chooseClientAlias(keyType, issuers, socket);
        } else {
            //check if already have client cert pref in place?
            if (mClientCertificatePreference != null) {
                mCertificateAlias = mClientCertificatePreference.getAlias();
                try {
                    mPrivateKeyEntry = mCertificateService.getPrivateEntry(mCertificateAlias, mClientCertificatePreference.getStorage());
                } catch (GeneralSecurityException e) {
                    //internal error
                    OMLog.error(TAG, e.getMessage(), e);
                } catch (KeyChainException e) {
                    //android system keychain error
                    OMLog.error(TAG, "System Keychain error", e);
                } catch (InterruptedException e) {
                    OMLog.error(TAG, "System Keychain error", e);
                }
                return mCertificateAlias;
            }
        }
        return null;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        if (mDefaultImplProvided) {
            return mX509KeyManager.chooseServerAlias(keyType, issuers, socket);
        }
        return null;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (mDefaultImplProvided) {
            mX509KeyManager.getCertificateChain(alias);

        } else {
            if (mPrivateKeyEntry != null) {
                OMLog.info(TAG, "Returning X509CertificateChain for alias " + mCertificateAlias + " From " + mClientCertificatePreference.getStorage());
                return (X509Certificate[]) mPrivateKeyEntry.getCertificateChain();
            }
        }
        return new X509Certificate[0];
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        if (mDefaultImplProvided) {
            return mX509KeyManager.getClientAliases(keyType, issuers);
        }
        return new String[0];
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        if (mDefaultImplProvided) {
            return mX509KeyManager.getServerAliases(keyType, issuers);
        }
        return new String[0];
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {

        if (mDefaultImplProvided) {
            return mX509KeyManager.getPrivateKey(alias);
        } else {
            if (mPrivateKeyEntry != null) {
                OMLog.info(TAG, "Returning PrivateKey for alias " + mCertificateAlias + " From " + mClientCertificatePreference.getStorage());
                return mPrivateKeyEntry.getPrivateKey();
            }
        }
        return null;
    }

    String[] getClientAuthKeyTypes() {
        return mClientAuthKeyTypes;
    }

    Principal[] getClientAuthIssuers() {
        return mClientAuthIssuers;
    }

    Principal getPeerPrincipal() {
        return mPeerPrincipal;
    }

    void setClientCertificatePreference(ClientCertificatePreference preference) {
        mClientCertificatePreference = preference;
    }

    boolean isClientCertRequired() {
        return mClientCertRequired;
    }

    String getPeerHost() {
        return mPeerHost;
    }

    int getPeerPort() {
        return mPeerPort;
    }

    private OMCertificateService getCertificateService() throws CertificateException {
        return mCertificateService;
    }


}
