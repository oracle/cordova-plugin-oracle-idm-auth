/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

/**
 * Enum that stores the supported grant types.
 *
 * @since 11.1.2.3.1
 */
public enum OAuthAuthorizationGrantType {
    /**
     * Implicit Grant type
     */
    IMPLICIT("OAuthImplicit"),

    /**
     * Resource Owner grant type
     */
    RESOURCE_OWNER("OAuthResourceOwner"),
    /**
     * Authorization Code grant type
     */
    AUTHORIZATION_CODE("OAuthAuthorizationCode"),
    /**
     * Client Credentials grant type
     */
    CLIENT_CREDENTIALS("OAuthClientCredentials"),
    ASSERTION("OAuthUserAssertion");

    private String value;

    OAuthAuthorizationGrantType(String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    public static OAuthAuthorizationGrantType valueOfGrantType(
            String grantType) {
        for (OAuthAuthorizationGrantType grantTypeEnum : values()) {
            if (grantTypeEnum.value.equalsIgnoreCase(grantType)) {
                return grantTypeEnum;
            }
        }
        return null;
    }
}
