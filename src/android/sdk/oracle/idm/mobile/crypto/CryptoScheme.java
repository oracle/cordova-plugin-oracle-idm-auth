/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;
 
/**
 * CryptoScheme enum represents the supported hashing algorithms that are used
 * for hashing the credentials to store in the credential store.
 *
 */
public enum CryptoScheme {
    // as per https://gps.oracle.com/ossa/farm/standards/doku.php?id=ats:start
    PLAINTEXT("PlainText"),
    SHA1("SHA1"),
    SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512"),
    SSHA256("SaltedSHA-256"), SSHA384("SaltedSHA-384"), SSHA512(
            "SaltedSHA-512"),
    AES("AES"),
    PBKDF2HmacSHA1("PBKDF2WithHmacSHA1");
 
    private String value;
 
    CryptoScheme(String value) {
        this.value = value;
    }
 
    public String getValue() {
        return this.value;
    }
 
    public static CryptoScheme getCryptoScheme(String value) {
        if (value == null)
            return null;
 
        CryptoScheme[] values = CryptoScheme.values();
        for (CryptoScheme scheme : values) {
            if (value.equalsIgnoreCase(scheme.value)) {
                return scheme;
            }
        }
        return null;
    }
 
    public static boolean isHashAlgorithm(CryptoScheme scheme) {
        if (scheme == CryptoScheme.AES || scheme == CryptoScheme.PLAINTEXT) {
            return false;
        }
        return true;
    }
 
    public static boolean isSaltedHashAlgorithm(CryptoScheme scheme) {
        if (scheme == CryptoScheme.SSHA256
                || scheme == CryptoScheme.SSHA384
                || scheme == CryptoScheme.SSHA512) {
            return true;
        }
        return false;
    }
}
