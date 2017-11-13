/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.connection;

import java.security.Principal;

import oracle.idm.mobile.OMExceptionEvent;

/**
 * Internal class used to represent exception event caused due to CertificateBased Authentication
 *
 * @hide
 * @since 11.1.2.3.1
 */
public class CBAExceptionEvent implements OMExceptionEvent {

    private static final long serialVersionUID = -7069280923554610043L;
    private String[] mKeys;
    private Principal[] mIssuers;
    private Principal mPeer;//connecting host.
    private String mPeerHost;//connection host
    private int mPeerPort = -1;

    CBAExceptionEvent(Principal[] issuers, String host, int port, String[] keys) {
        mKeys = keys;
        mIssuers = issuers;
        mPeerPort = port;
        mPeerHost = host;
    }

    //TODO
    @Override
    public OMExceptionEventType getExceptionEventType() {
        return OMExceptionEventType.CLIENT_CERT_REQUIRED;
    }

    public Principal[] getIssuers() {
        return mIssuers;
    }

    public String[] getKeys() {
        return mKeys;
    }


    public String getPeerHost() {
        return mPeerHost;
    }

    public int getPeerPort() {
        return mPeerPort;
    }
}
