package com.eawf.deriver.util;

import com.eawf.deriver.bitcoin.Base58Check;
import com.eawf.deriver.bitcoin.Bech32;

/**
 * Utility class for {@code byte} operations.
 *
 * @author Carson Mullins
 */
public class Bytes {

    private final static char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    private Bytes() {

    } // Non-instantiable

    /**
     * Concatenates two byte arrays into a single byte array.
     *
     * @param b1 the first byte array.
     * @param b2 the second byte array.
     * @return the byte array equal to b1 || b2.
     */
    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] output = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, output, 0, b1.length);
        System.arraycopy(b2, 0, output, b1.length, b2.length);
        return output;
    }

    /**
     * Converts a byte array into its hexadecimal string representation.
     *
     * @param bytes the byte array to convert.
     * @return a hexadecimal string representation of bytes.
     */
    public static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Encodes the given public key hash as a P2PKH address.
     *
     * @param pubKeyHash the public key hash to encode
     * @return a P2PKH address (begins with "1")
     */
    public static String getAddressP2PKH(byte[] pubKeyHash) {
        byte[] address_bytes = concat(new byte[]{0x00}, pubKeyHash);
        return Base58Check.bytesToBase58(address_bytes);
    }

    /**
     * Encodes the given public key hash as a P2SH-P2WPKH address.
     *
     * @param pubKeyHash the public key hash to encode
     * @return a P2SH-P2WPKH address (begins with "3")
     */
    public static String getAddressP2SHP2WPKH(byte[] pubKeyHash) {
        byte[] witnessProgram = concat(new byte[]{0x00, 0x14}, pubKeyHash);
        byte[] scriptHash = Hashes.hash160(witnessProgram);
        byte[] address_bytes = concat(new byte[]{0x05}, scriptHash);
        return Base58Check.bytesToBase58(address_bytes);
    }

    /**
     * Encodes the given public key hash as a P2WPKH address.
     *
     * @param pubKeyHash the public key hash to encode
     * @return a P2WPKH address (begins with "bc1")
     */
    public static String getAddressP2WPKH(byte[] pubKeyHash) {
        return Bech32.segwitToBech32("bc", 0, pubKeyHash);
    }
}
