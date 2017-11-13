/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// from https://android.googlesource.com/platform/development/+/master/samples/Vault/src/com/example/android/vault/SecretKeyWrapper.java

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import oracle.idm.mobile.logging.OMLog;

/**
 * Wraps {@link SecretKey} instances using a public/private key pair stored in
 * the platform {@link KeyStore}. This allows us to protect symmetric keys with
 * hardware-backed crypto, if provided by the device.
 * <p>
 * See <a href="http://en.wikipedia.org/wiki/Key_Wrap">key wrapping</a> for more
 * details.
 * <p>
 * Not inherently thread safe.
 */
public class SecretKeyWrapper {
    private static final String TAG = SecretKeyWrapper.class.getSimpleName();
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private Cipher cipher;
    private final KeyPair keyPair;
    private boolean userAuthenticationRequired;

    /**
     * Create a wrapper using the public/private key pair with the given alias.
     * If no pair with that alias exists, it will be generated.
     */
    public SecretKeyWrapper(Context context, String alias, boolean userAuthenticationRequired)
            throws GeneralSecurityException, IOException {
        cipher = Cipher.getInstance(TRANSFORMATION);
        this.userAuthenticationRequired = userAuthenticationRequired;
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (!keyStore.containsAlias(alias)) {
            long start = System.currentTimeMillis();
            generateKeyPair(context, alias, userAuthenticationRequired);
            OMLog.trace(TAG, "generateKeyPair took " + (System.currentTimeMillis() - start) + " ms");
        }

        // Even if we just generated the key, always read it back to ensure we
        // can read it successfully.
        final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
        keyPair = new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
    }

    /**
     * Generate key pair.
     * @param context
     * @param alias
     * @throws GeneralSecurityException
     */
    @TargetApi(Build.VERSION_CODES.M)
    private static void generateKeyPair(Context context, String alias, boolean userAuthenticationRequired)
            throws GeneralSecurityException {
        if (userAuthenticationRequired) {
            final KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setUserAuthenticationRequired(true)
                    .build();
            //TODO Update studio and build to Android N, then set jdk location in File->Project structure
//            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
//                builder.setInvalidatedByBiometricEnrollment(false);
//            }
            final KeyPairGenerator gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            gen.initialize(spec);
            gen.generateKeyPair();
        } else {
            final Calendar start = new GregorianCalendar();
            final Calendar end = new GregorianCalendar();
            end.add(Calendar.YEAR, 100);
            final KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(new X500Principal("CN=OMAuthenticator User, O=" + alias))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
            gen.initialize(spec);
            gen.generateKeyPair();
        }
    }

    /**
     * Wrap a {@link SecretKey} using the public key assigned to this wrapper.
     * Use {@link #unwrap(byte[])} to later recover the original {@link SecretKey}.
     *
     * @return a wrapped version of the given {@link SecretKey} that can be
     * safely stored on untrusted storage.
     */
    public byte[] wrap(SecretKey key) throws GeneralSecurityException {
        if (userAuthenticationRequired) {
            Key publicKey = keyPair.getPublic();
            /* Ref: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html
            A known bug in Android 6.0 (API Level 23) causes user authentication-related authorizations to
            be enforced even for public keys. To work around this issue, extract the public key material to use
            outside of Android Keystore.*/
            PublicKey unrestrictedPublicKey =
                    KeyFactory.getInstance(publicKey.getAlgorithm()).generatePublic(
                            new X509EncodedKeySpec(publicKey.getEncoded()));
            cipher.init(Cipher.WRAP_MODE, unrestrictedPublicKey);
        } else {
            cipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
        }
        return cipher.wrap(key);
    }

    /**
     * Unwrap a {@link SecretKey} using the private key assigned to this wrapper.
     *
     * @param blob a wrapped {@link SecretKey} as previously returned by {@link #wrap(SecretKey)}.
     */
    public SecretKey unwrap(byte[] blob) throws GeneralSecurityException {
        cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
        return (SecretKey) cipher.unwrap(blob, "AES", Cipher.SECRET_KEY);
    }

    Cipher getUnwrapCipher() throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
        return cipher;
    }
}
