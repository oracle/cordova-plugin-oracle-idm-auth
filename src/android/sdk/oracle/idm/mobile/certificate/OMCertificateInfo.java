/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.certificate;

import java.security.cert.X509Certificate;
import java.util.StringTokenizer;

/**
 * Class to represent certificate information.
 *
 */
public class OMCertificateInfo {

    private X509Certificate mCertificate;
    private String mCN;
    private String mO;
    private String mOU;
    private String mAlias;// to track the alias name against which we are
    // storing this
    // certificate in the SDK's keystore.

    private OMCertificateInfo(String dn) {
        StringTokenizer st = new StringTokenizer(dn, ",");

        while (st.hasMoreTokens()) {
            String token = st.nextToken().trim();
            String tokenVal = token.substring(token.indexOf('=') + 1);

            if (token.startsWith("CN")) {
                mCN = tokenVal;
            } else if (token.startsWith("OU")) {
                mOU = tokenVal;
            } else if (token.startsWith("O")) {
                mO = tokenVal;
            }
        }
    }

    OMCertificateInfo(X509Certificate certificate) {
        this(certificate.getSubjectDN().getName());
        mCertificate = certificate;
    }

    /**
     * Helper Utility to tie a certificate info object with the alias
     * corresponding to which is stored in the Keystore/trustore.
     */
    void setAlias(String alias) {
        mAlias = alias;
    }

    public String getAlias() {
        return mAlias;
    }

    public String getCommonName() {
        return mCN;
    }

    public String getOrganization() {
        return mO;
    }

    public String getOrganizationUnit() {
        return mOU;
    }

    public OMCertificateInfo issuedBy() {
        if (mCertificate != null && mCertificate.getIssuerDN() != null) {
            return new OMCertificateInfo(mCertificate.getIssuerDN().getName());
        }
        return null;
    }

    public OMCertificateInfo issuedTo() {
        return this;
    }

    @Override
    public String toString() {
        return mCertificate.getSubjectDN().getName();
    }
}
