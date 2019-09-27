package com.eawf.deriver.util;

import com.eawf.deriver.bitcoin.Base58Check;
import com.eawf.deriver.ecc.CurveParams;
import com.eawf.deriver.ecc.ScalarMultiply;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public final class Keys {

    public static final byte[] XPUB = {(byte) 0x04, (byte) 0x88, (byte) 0xB2, (byte) 0x1E};
    public static final byte[] YPUB = {(byte) 0x04, (byte) 0x9D, (byte) 0x7C, (byte) 0xB2};
    public static final byte[] ZPUB = {(byte) 0x04, (byte) 0xB2, (byte) 0x47, (byte) 0x46};

    private Keys() {
    } // Non-instantiable

    /**
     * Performs Scalar Multiplication about a specified point and returns the
     * public key's bytes.
     *
     * @param prvKey the private key used in scalar multiplication.
     * @param genPoint the generator point used in scalar multiplication.
     * @return the public key created by multiplying {@code prvKey} by
     * {@code genPoint}.
     */
    public static byte[] createPubKey(byte[] prvKey, ECPoint genPoint) {
        BigInteger masterS = new BigInteger(1, prvKey);
        ECPoint point = ScalarMultiply.scalmult(genPoint, masterS);
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        byte[] x_bytes = new byte[32];
        byte[] x_raw = x.toByteArray();
        if (x_raw.length > 32) {
            x_bytes = Arrays.copyOfRange(x_raw, x_raw.length - 32, x_raw.length);
        } else if (x_raw.length < 32) {
            System.arraycopy(x_raw, 0, x_bytes, 32 - x_raw.length, x_raw.length);
        } else {
            x_bytes = x_raw;
        }
        byte parity = (byte) (y.testBit(0) ? 0x03 : 0x02);
        return Bytes.concat(new byte[]{parity}, x_bytes);
    }

    /**
     * Converts the given public key bytes (in compressed or uncompressed form)
     * into a PublicKey object.
     *
     * @param pubKeyBytes the bytes to convert (if compressed, first
     * decompresses the key).
     * @return the PublicKey object whose X and Y values match the given bytes.
     */
    public static ECPublicKey toPubKey(byte[] pubKeyBytes) {
        try {
            if (pubKeyBytes[0] == 0x02 || pubKeyBytes[0] == 0x03) {
                pubKeyBytes = decompressPubKey(pubKeyBytes);
            }
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubKeyBytes, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(pubKeyBytes, 33, 65));
            ECPoint W = new ECPoint(x, y);
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(W, CurveParams.ecSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            return (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Decompresses the given public key bytes.
     *
     * @param pubKeyBytes the bytes of a public key in compressed form (0x02 or
     * 0x03 || X value).
     * @return the bytes of a public key in uncompressed form (0x04 || X value
     * || Y value).
     */
    public static byte[] decompressPubKey(byte[] pubKeyBytes) {
        byte[] K_x_bytes = new byte[32];
        System.arraycopy(pubKeyBytes, 1, K_x_bytes, 0, K_x_bytes.length);
        byte parity = pubKeyBytes[0];
        BigInteger K_x = new BigInteger(1, K_x_bytes);
        BigInteger y_square = K_x.modPow(
                BigInteger.valueOf(3), CurveParams.p).add(CurveParams.b)
                .mod(CurveParams.p);
        BigInteger y_root = y_square.modPow(
                CurveParams.p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)),
                CurveParams.p);
        BigInteger K_y;
        if (parity == 0x02 && y_root.testBit(0)
                || parity == 0x03 && !y_root.testBit(0)) {
            K_y = y_root.negate().mod(CurveParams.p);
        } else {
            K_y = y_root;
        }
        byte[] K_y_bytes = Strings.toBytes(String.format("%064X", K_y));
        byte[] K_uncomp = Bytes.concat(new byte[]{0x04},
                Bytes.concat(K_x_bytes, K_y_bytes));
        return K_uncomp;
    }

    /**
     * Validates a given Account-Level Extended Public Key and returns the raw
     * bytes without checksum.
     *
     * @param xkey_ser the extended public key to verify
     * @return the raw bytes of the extended public key
     * @throws ExtendedKeyFormatException if the extended public key does not
     * match the expected format for an account-level extended public key
     */
    public static byte[] validateExtendedKey(String xkey_ser) throws ExtendedKeyFormatException {
        try {
            // If given xkey_ser isn't a Base58 encoded string or the checksum doesn't validate, throw exception
            byte[] xkey_bytes = Base58Check.base58ToBytes(xkey_ser);
            // If length of extended key is not 78 bytes (without checksum), throw exception
            if (xkey_bytes.length != 78) {
                throw new Exception();
            }
            // If version bytes are not equal to xpub, ypub, or zpub, throw exception
            byte[] version = Arrays.copyOfRange(xkey_bytes, 0, 4);
            if (!Arrays.equals(version, XPUB)
                    && !Arrays.equals(version, YPUB)
                    && !Arrays.equals(version, ZPUB)) {
                throw new Exception();
            }
            // If depth byte is not 0x03, throw exception
            byte depth = xkey_bytes[4];
            if (depth != (byte) 0x03) {
                throw new Exception();
            }
            return xkey_bytes;
        } catch (Exception ex) {
            throw new ExtendedKeyFormatException("extended key is not a valid account-level extended public key.");
        }
    }

}
