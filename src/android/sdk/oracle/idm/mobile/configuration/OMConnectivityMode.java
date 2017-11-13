/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

/**
 * OMConnectivityMode  Enum represents the various connectivity mode that can be
 * used in a authentication request. If ONLINE is used, then the current
 * authentication request can perform only online mode of authentication. If
 * OFFLINE is used, the current authentication request can perform only offline
 * mode of authentication. If AUTO is used, then the SDK will determine based on
 * the network availability to perform either online or offline authentication.
 *
 * @since 11.1.2.3.1
 */
public enum OMConnectivityMode {

    ONLINE("Online"), OFFLINE("Offline"), AUTO("Auto");

    private String mConnMode;

    OMConnectivityMode(String connectivityMode) {
        this.mConnMode = connectivityMode;
    }

    public static OMConnectivityMode valueOfOMConnectivityMode(String connectivityMode) {
        for (OMConnectivityMode connectivityModeEnum : values()) {
            if (connectivityModeEnum.mConnMode.equalsIgnoreCase(connectivityMode)) {
                return connectivityModeEnum;
            }
        }
        return null;
    }
}
