/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.net.URL;
import java.security.cert.X509Certificate;

import oracle.idm.mobile.OMExceptionEvent;

/**
 * used to represent the exception caused during SSL handshake, when server certificate is not trusted.
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class SSLExceptionEvent implements OMExceptionEvent {

    private static final long serialVersionUID = -327329255478561342L;
    private X509Certificate[] mChain;
    private String mAuthType;
    private URL mURL;

    public SSLExceptionEvent(X509Certificate[] chain, String authType, URL url) {
        mChain = chain;
        mAuthType = authType;
        mURL = url;
    }

    @Override
    public OMExceptionEventType getExceptionEventType() {
        return OMExceptionEventType.SERVER_CERT_NOT_TRUSTED;
    }

    public X509Certificate[] getCertificateChain() {
        return mChain;
    }

    public String getAuthType() {
        return mAuthType;
    }

    public URL getURL() {
        return mURL;
    }
}
