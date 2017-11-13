/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

/**
 * This represents the type of authentication challenge. Refer the
 * values for more information.
 *
 */
public enum OMAuthenticationChallengeType {

    /**
     * Username and password are required to complete the authentication process.
     * Please note: If identity domain is also required the challenge MAP will contain
     * a key for Identity Domain.
     */
    USERNAME_PWD_REQUIRED,
    EMBEDDED_WEBVIEW_REQUIRED,
    UNTRUSTED_SERVER_CERTIFICATE,
    EXTERNAL_BROWSER_INVOCATION_REQUIRED,
    CLIENT_IDENTITY_CERTIFICATE_REQUIRED,
    INVALID_REDIRECT_ENCOUNTERED;
}
