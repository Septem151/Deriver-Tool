package com.eawf.deriver.util;

/**
 *
 * @author Carson Mullins
 */
public final class Strings {

    private Strings() {
    } // Non-instantiable

    /**
     * Converts a hexadecimal string representation of bytes into a byte array.
     *
     * @param hex the hexadecimal string (not checked for length correctness).
     * @return the byte array representation of hex value.
     */
    public static byte[] toBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

}
