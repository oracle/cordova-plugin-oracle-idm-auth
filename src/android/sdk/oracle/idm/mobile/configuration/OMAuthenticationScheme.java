/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

/**
 * OMAuthenticationScheme is an enum which should be used to represent the
 * authentication scheme for a given request.
 *
 * @since 11.1.2.3.1
 */
public enum OMAuthenticationScheme {
    BASIC("HttpBasicAuthentication"),
    OAUTH20("OAuth2.0"),
    FEDERATED("FederatedAuthentication"),
    OFFLINE("OfflineAuthentication"),
    CBA("ClientCertificateBasedAuthentication"),
    OPENIDCONNECT10("OpenIDConnect10"),
    REFRESH_TOKEN("RefreshToken");

    private String mValue;

    OMAuthenticationScheme(String value) {
        mValue = value;
    }

    public String getValue() {
        return mValue;
    }

    public static OMAuthenticationScheme valueOfAuthScheme(String authScheme) {
        for (OMAuthenticationScheme authSchemeEnum : values()) {
            if (authSchemeEnum.getValue().equalsIgnoreCase(authScheme)) {
                return authSchemeEnum;
            }
        }
        return null;
    }
}
