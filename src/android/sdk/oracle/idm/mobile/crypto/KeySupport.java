/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.crypto;

import java.nio.charset.Charset;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import oracle.idm.mobile.OMErrorCode;

/**
 * Key conversion related methods. An example would be converting a byte array or a String to
 * {@link Key}. Also, given a {@link Key}, returning it in byte array encoded format.
 *
 */

public class KeySupport {

    private static final String UTF8 = "UTF-8";
    private static final Charset UTF8_CHARSET = Charset.forName(UTF8);

    /**
     * Validate and converts the passed bytes to {@link Key} object.
     * @param key
     * @return
     */
    /* package */ Key getKeyFromBytes(byte[] key) throws OMKeyManagerException {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }

        int keySize = key.length * 8;

        switch (keySize) {
            case 128:
            case 192:
            case 256:
                break;
            default:
                String message = "Invalid key size for AES: " + keySize + ". Valid lengths are: 16, 24 or 32 bytes.";
                throw new OMKeyManagerException(OMErrorCode.KEY_SIZE_NOT_SUPPORTED_BY_ALGORITHM, message);
        }

        return new SecretKeySpec(key, "AES");
    }

    /**
     * PBKDF2 based key derivation function with default salt and iterations.
     * @param password
     * @return newly generated key.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    /* package */ Key getKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {

        int iterations = 1000;
        int keyLengthInBits = 512;
        char[] chars = password.toCharArray();
        byte[] salt = getSalt(password);

        KeySpec spec = new PBEKeySpec(chars, salt, iterations, keyLengthInBits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey key = skf.generateSecret(spec);
        return key;
    }

    /**
     * Salt derived from password.
     * @param password
     * @return
     */
    /* package */ byte[] getSalt(String password) {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(password.getBytes(UTF8_CHARSET));
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

}
