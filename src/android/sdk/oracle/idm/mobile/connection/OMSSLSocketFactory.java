/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import oracle.idm.mobile.certificate.ClientCertificatePreference;
import oracle.idm.mobile.certificate.OMCertificateService;
import oracle.idm.mobile.logging.OMLog;
import oracle.idm.mobile.logging.OMLogger;

/**
 * @hide
 * @since 11.1.2.3.1
 */
public class OMSSLSocketFactory extends SSLSocketFactory {

    private static final OMLogger mLogger = new OMLogger(OMSSLSocketFactory.class);

    private String[] mCorrectedProtocols = null;
    private String[] mEnabledCipherSuites;

    private OMTrustManager mTM;
    private OMX509KeyManager mKM;
    private SSLContext mSSLContext;

    private OMCertificateService mCertificateService;

    private boolean mHandleClientCertificate;
    private boolean mClientCertificatePreference;

    /**
     * Should be called as per the platform specifications.
     * <p/>
     * For eg:
     * TLS and TLSv1 is supported for in platform APIs
     * TLSv1.1 and TLS1.2 is supported in API 16+
     *
     * @param protocol
     * @throws NoSuchAlgorithmException
     */
    OMSSLSocketFactory(OMCertificateService certificateService, boolean handleClientCertificates, String protocol) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        OMLog.debug("OMSSLSocketFactory", "Creating SSLSocketFactory for protocol: " + protocol + " Client Certificate support : " + handleClientCertificates);
        mSSLContext = SSLContext.getInstance(protocol);
        mHandleClientCertificate = handleClientCertificates;
        mTM = new OMTrustManager(certificateService.getTrustStore());
        if (mHandleClientCertificate) {
            //initialize the key manager only if application has enabled support for client certificate.
            mKM = new OMX509KeyManager(certificateService, null);
        }
        mSSLContext.init((mHandleClientCertificate) ? (new KeyManager[]
                {mKM}) : null, new TrustManager[]{mTM}, null);
        mCertificateService = certificateService;
    }

    OMSSLSocketFactory(OMCertificateService certificateService, boolean handleClientCertificates, String protocol,
                       String[] correctedProtocols, String[] enabledCipherSuites)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        this(certificateService, handleClientCertificates, protocol);
        mCorrectedProtocols = correctedProtocols;
        mEnabledCipherSuites = enabledCipherSuites;
    }


    boolean isServerCertUntrusted() {
        return mTM.isServerCertUntrusted();
    }


    boolean isClientCertRequired() {
        return mKM != null && mKM.isClientCertRequired();
    }

    Principal[] getIssuers() {
        if (mKM != null) {
            return mKM.getClientAuthIssuers();
        }
        return null;
    }

    String[] getKeyTypes() {
        if (mKM != null) {
            return mKM.getClientAuthKeyTypes();
        }
        return null;
    }

    int getPeerPort() {
        if (mKM != null) {
            return mKM.getPeerPort();
        }
        return -1;
    }

    String getPeerHost() {
        if (mKM != null) {
            return mKM.getPeerHost();
        }
        return null;
    }

    Principal getPrincipal() {
        if (mKM != null) {
            return mKM.getPeerPrincipal();
        }
        return null;
    }

    void setServerCertAllowed(boolean flag) {
        mTM.setServerCertAllowed(flag);
    }

    X509Certificate[] getUntrustedServerCertChain() {
        return mTM.getUntrustedServerCertChain();
    }

    String getAuthType() {
        return mTM.getAuthType();
    }

    void setClientCertificatePreference(ClientCertificatePreference preference) {
        if (mKM != null) {
            mKM.setClientCertificatePreference(preference);
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return new String[0];
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return new String[0];
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        SSLSocket sslSocket = (SSLSocket) mSSLContext.getSocketFactory()
                .createSocket(s, host, port, autoClose);
        sslSocket.setEnabledProtocols(protocolCorrection(sslSocket
                .getEnabledProtocols()));
        sslSocket.setEnabledCipherSuites(updateCipherSuites(sslSocket
                .getEnabledCipherSuites()));
        return sslSocket;
    }

    /*
    Corrects/Sets the protocols which application wants to set.
    Weblogic still supports TLS but by default on Android5.0 onwards TLSv1.1/1.2 is used
     */
    protected String[] protocolCorrection(String[] supportedProtocols) {
        if (mCorrectedProtocols != null) {
            /**
             * Initially this support was added because of the following
             * reason only for Build.VERSION.SDK_INT >=
             * Build.VERSION_CODES.LOLLIPOP:
             * <p>
             * By default from Android5.0 onwards TLSv1.1 and TLSv1.2 is
             * enabled, but the weblogic server is not compatible with
             * v1.2/v1.1 hence setting the protocol as v1 by default. TODO
             * this should be reverted back when weblogic adds this support.
             *
             * But, later for fixing 25179521 and 25453853, the version
             * check [Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP]
             * is removed. It is mainly to enable TLSv1.1,TLSv1.2 in Android
             * APIs 16-19, where it is supported but not enabled by default.
             */
            return mCorrectedProtocols;
        }
        return supportedProtocols;
    }

    private String[] updateCipherSuites(String[] enabledCipherSuites) {
        if (mEnabledCipherSuites != null) {
            return mEnabledCipherSuites;
        }
        return enabledCipherSuites;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return null;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return null;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return null;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return null;
    }

    public OMTrustManager getTrustManager() {
        return mTM;
    }

    /**
     * SDK TrustManager Impl
     *
     * @hide
     */
    public static class OMTrustManager implements X509TrustManager {
        private X509TrustManager localTM = null;
        private X509TrustManager androidTM = null;
        private KeyStore trustStore;
        private boolean isServerCertAllowed = false;
        private boolean isServerCertUntrusted;
        private boolean isClientCertRequired;
        private X509Certificate[] chain;
        private String authType;

        public OMTrustManager(KeyStore store) throws KeyStoreException, NoSuchAlgorithmException {
            if (store == null) {
                mLogger.error("[OMTrustManager] TrustStore provided for X509trustManager is null");
                throw new IllegalArgumentException("TrustStore for custom TrustManager can not be null!");
            }
            androidTM = getTrustManager(null);
            trustStore = store;
            localTM = getTrustManager(trustStore);
            isClientCertRequired = false;
            isServerCertUntrusted = false;
        }

        private X509TrustManager getTrustManager(KeyStore keyStore)
                throws NoSuchAlgorithmException, KeyStoreException {
            TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());

            tmf.init(keyStore);

            return (X509TrustManager) tmf.getTrustManagers()[0];
        }

        void setServerCertAllowed(boolean flag) {
            isServerCertAllowed = flag;
        }

        boolean isServerCertUntrusted() {
            return isServerCertUntrusted;
        }

        X509Certificate[] getUntrustedServerCertChain() {
            return this.chain;
        }

        String getAuthType() {
            return authType;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            //first lets check the certificate trust in the System Trust Store.

            try {
                androidTM.checkServerTrusted(chain, authType);
            } catch (CertificateException e) {
                mLogger.trace("[OMTrustManager] Cert not trusted by android store");
                //not trusted by system
                //lets check in local store.
                checkServerTrustedLocally(chain, authType, e);
            }
        }

        public void checkServerTrustedLocally(X509Certificate[] chain, String authType, CertificateException systemStoreException) throws CertificateException {
            try {
                if (trustStore.size() > 0) {
                    //certs installed.
                    try {
                        localTM.checkServerTrusted(chain, authType);
                        mLogger.trace("[OMTrustManager] Cert trusted by local store");
                    } catch (CertificateException e1) {
                        mLogger.trace("[OMTrustManager] Cert not trusted in local store");
                        isServerCertUntrusted = true;
                        this.chain = chain;
                        this.authType = authType;
                        throw e1;
                    }
                } else {
                    mLogger.trace("[OMTrustStore] No certs available in local store");
                    isServerCertUntrusted = true;
                    this.chain = chain;
                    this.authType = authType;
                    if (systemStoreException != null) {
                        throw systemStoreException;
                    } else {
                        throw new CertificateException("No certs available in local store. Hence it is untrusted.");
                    }
                }
            } catch (KeyStoreException e1) {
                isServerCertUntrusted = true;
                this.chain = chain;
                this.authType = authType;
                throw new CertificateException(e1);
            }

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
