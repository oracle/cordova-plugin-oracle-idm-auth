/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile;

import java.io.Serializable;

/**
 * @hide
 */
public interface OMExceptionEvent extends Serializable {

    OMExceptionEventType getExceptionEventType();

    enum OMExceptionEventType {

        SERVER_CERT_NOT_TRUSTED("ServerCertNotTrusted"),
        CLIENT_CERT_REQUIRED("ClientCertificateRequired"),
        INVALID_LOGIN_CREDENTIALS("InvalidLoginCredentials"),
        INVALID_REDIRECT("InvalidRedirect");

        private String mValue;

        OMExceptionEventType(String value) {
            mValue = value;
        }

        public String getValue() {
            return mValue;
        }
    }
}
