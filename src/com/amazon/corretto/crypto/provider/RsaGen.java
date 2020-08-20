// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Loader.ARRAY_CACHE;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

class RsaGen extends KeyPairGeneratorSpi {
    private final KeyFactory keyFactory;
    private final AmazonCorrettoCryptoProvider provider_;
    private RSAKeyGenParameterSpec kgSpec;

    static {
        Loader.load();
    }

    RsaGen(AmazonCorrettoCryptoProvider provider) {
        Loader.checkNativeLibraryAvailability();
        provider_ = provider;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            kgSpec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
        } catch (final NoSuchAlgorithmException ex) {
            throw new AssertionError(ex);
        }
    }

    native private static void generate(
            int keySize,
            boolean checkConsistency,
            byte[] pubExp,
            byte[] modOut,
            byte[] privExpOut,
            byte[] primePOut,
            byte[] primeQOut,
            byte[] dmPOut,
            byte[] dmQOut,
            byte[] coefOut
            );

    @Override
    public KeyPair generateKeyPair() {
        final int keySize = kgSpec.getKeysize();

        final byte[] pubExp = kgSpec.getPublicExponent().toByteArray();
        // The modulus has a length equal to the keysize. An extra byte is allocated
        // to ensure that there are never any problems with sign-bits.
        // The private exponent may also be the key length.
        final int keySizeBytes = (keySize / 8) + 1;
        byte[] modOut = ARRAY_CACHE.getArray(keySizeBytes);
        byte[] privExpOut = ARRAY_CACHE.getArray(keySizeBytes);

        // All subsequent parts are the lengths of the primes which are
        // each half as long as the modulus (which is their product).
        // Once again, an extra byte is allocated to avoid there are
        // never problems with sign-bits.
        final int partLen = (keySize / 16) + 1;
        byte[] primePOut = ARRAY_CACHE.getArray(partLen);
        byte[] primeQOut = ARRAY_CACHE.getArray(partLen);
        byte[] dmPOut = ARRAY_CACHE.getArray(partLen);
        byte[] dmQOut = ARRAY_CACHE.getArray(partLen);
        byte[] coefOut = ARRAY_CACHE.getArray(partLen);
        generate(keySize, provider_.hasExtraCheck(ExtraCheck.KEY_PAIR_GENERATION_CONSISTENCY),
            pubExp, modOut, privExpOut, primePOut, primeQOut, dmPOut, dmQOut, coefOut);

        final BigInteger modulus = new BigInteger(modOut);
        try {
            final PublicKey publicKey = keyFactory.generatePublic(
                    new RSAPublicKeySpec(modulus, kgSpec.getPublicExponent()));
            final PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateCrtKeySpec(
                    modulus,
                    kgSpec.getPublicExponent(),
                    new BigInteger(privExpOut),
                    new BigInteger(primePOut),
                    new BigInteger(primeQOut),
                    new BigInteger(dmPOut),
                    new BigInteger(dmQOut),
                    new BigInteger(coefOut)));

            ARRAY_CACHE.offerArray(modOut); modOut = null;
            ARRAY_CACHE.offerArray(privExpOut); privExpOut = null;
            ARRAY_CACHE.offerArray(primePOut); primePOut = null;
            ARRAY_CACHE.offerArray(primeQOut); primeQOut = null;
            ARRAY_CACHE.offerArray(dmPOut); dmPOut = null;
            ARRAY_CACHE.offerArray(dmQOut); dmQOut = null;
            ARRAY_CACHE.offerArray(coefOut); coefOut = null;

            return new KeyPair(publicKey, privateKey);
        } catch (InvalidKeySpecException ex) {
            throw new AssertionError(ex);
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec spec, SecureRandom rnd) throws InvalidAlgorithmParameterException {
        if (spec instanceof RSAKeyGenParameterSpec) {
            kgSpec = validateParameter((RSAKeyGenParameterSpec) spec);
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + spec);
        }
    }

    @Override
    public void initialize(int keysize, SecureRandom rnd) throws InvalidParameterException {
        try {
            kgSpec = validateParameter(new RSAKeyGenParameterSpec(keysize, RSAKeyGenParameterSpec.F4));
        } catch (final InvalidAlgorithmParameterException ex) {
            throw new InvalidParameterException(ex.getMessage());
        }
    }

    private static RSAKeyGenParameterSpec validateParameter(RSAKeyGenParameterSpec spec) throws InvalidAlgorithmParameterException {
        if (spec.getKeysize() < 512) {
            throw new InvalidAlgorithmParameterException("Unsupported key size: " + spec.getKeysize());
        }
        return spec;
    }
}
