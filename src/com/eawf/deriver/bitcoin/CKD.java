package com.eawf.deriver.bitcoin;

import com.eawf.deriver.ecc.CurveParams;
import com.eawf.deriver.ecc.ScalarMultiply;
import com.eawf.deriver.util.Bytes;
import com.eawf.deriver.util.Hashes;
import com.eawf.deriver.util.Keys;
import com.eawf.deriver.util.Strings;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * Helper class with Key Derivation functions.
 *
 * @author Carson Mullins
 */
public class CKD {

    private CKD() {
    } // Non-instantiable

    /**
     * Derives a child extended private key from a parent extended private key.
     * An extended private key has 64 bytes, the left-hand 32-bytes is treated
     * as the master secret key, and the right-hand 32-bytes is treated as the
     * master chain code. Specifications defined in
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>
     *
     * @param xkey_par the parent extended private key.
     * @param i the child index to derive.
     * @param hardened whether the derived child extended key will be hardened
     * (note: hardened means i = i + (2^31 - 1), or i = 0x80000000 | i).
     * @return the child extended private key derived at child index i.
     */
    public static byte[] CKDpriv(byte[] xkey_par, int i, boolean hardened) {
        // Split xkey_par into two 32-byte sequences, I_L and I_R.
        // Use parse256(I_L) as master secret key (k_par), and I_R as
        // master chain code (c_par).
        byte[] k_par = Arrays.copyOfRange(xkey_par, 0, xkey_par.length / 2);
        byte[] c_par = Arrays.copyOfRange(xkey_par, xkey_par.length / 2, xkey_par.length);
        BigInteger k_par_bigInt = new BigInteger(1, k_par);
        // If Non-Hardened derivation: Public Key is needed in compressed form. 
        // Calculate K_par as Public Key where K_par = k_par * G
        // Note: Scalar Point Multiplication
        // If Hardened: let I = HMAC-SHA512(Key = c_par, Data = 0x00 || 
        // ser256(k_par) || ser32(i)). (Note: The 0x00 pads the private key
        // to make it 33 bytes long.)
        // If not (normal child): let I = HMAC-SHA512(Key = c_par, Data = serP
        // (K_par) || ser32(i)).
        i = (hardened) ? 0x80000000 | i : i;
        byte[] data;
        byte[] i_bytes = ByteBuffer.allocate(4).putInt(i).array();
        if (hardened) {
            data = Bytes.concat(
                    new byte[]{0x00}, Bytes.concat(k_par, i_bytes));
        } else {
            byte[] compressed_K_par = Keys.createPubKey(k_par, CurveParams.G);
            data = Bytes.concat(compressed_K_par, i_bytes);
        }
        byte[] I = Hashes.hmac(c_par, data);

        // Split I into two 32-byte sequences, I_L and I_R.
        // The returned child key k_i is parse256(I_L) + k_par (mod n).
        // The returned chain code c_i is I_R.
        byte[] I_L = Arrays.copyOfRange(I, 0, I.length / 2);
        byte[] I_R = Arrays.copyOfRange(I, I.length / 2, I.length);

        BigInteger I_L_bigInt = new BigInteger(1, I_L);
        BigInteger res = I_L_bigInt.add(k_par_bigInt);
        res = res.mod(CurveParams.n);

        byte[] k_i = Strings.toBytes(String.format("%064X", res));
        byte[] c_i = I_R;

        byte[] xkey_i = Bytes.concat(k_i, c_i);
        return xkey_i;
    }

    /**
     * Derives a child extended public key from a parent extended public key. An
     * extended public key has 65 bytes, the left-hand 33-bytes is treated as
     * the public key, and the right-hand 32-bytes is treated as the master
     * chain code. Specifications defined in
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>
     *
     * @param xkey_par the parent extended public key.
     * @param i the child index to derive.
     * @return the child extended public key derived at child index i.
     */
    public static byte[] CKDpub(byte[] xkey_par, int i) {
        byte[] chain_code = Arrays.copyOfRange(xkey_par, 33, xkey_par.length);
        byte[] data = Bytes.concat(Arrays.copyOfRange(xkey_par, 0, 33), ByteBuffer.allocate(4).putInt(i).array());
        byte[] I = Hashes.hmac(chain_code, data);
        byte[] I_L = Arrays.copyOfRange(I, 0, 32);
        byte[] I_R = Arrays.copyOfRange(I, 32, 64);
        // I_L is treated as a private key
        byte[] pubAdd = Keys.createPubKey(I_L, CurveParams.G);
        ECPoint pubAddPoint = Keys.toPubKey(pubAdd).getW();
        byte[] pubPar = Arrays.copyOfRange(xkey_par, 0, 33);
        ECPoint pubParPoint = Keys.toPubKey(pubPar).getW();
        ECPoint childPoint = ScalarMultiply.addPoint(pubAddPoint, pubParPoint);
        byte[] x_bytes = new byte[32];
        byte[] x_raw = childPoint.getAffineX().toByteArray();
        if (x_raw.length > 32) {
            x_bytes = Arrays.copyOfRange(x_raw, x_raw.length - 32, x_raw.length);
        } else if (x_raw.length < 32) {
            System.arraycopy(x_raw, 0, x_bytes, 32 - x_raw.length, x_raw.length);
        } else {
            x_bytes = x_raw;
        }
        byte parity = (byte) (childPoint.getAffineY().testBit(0) ? 0x03 : 0x02);
        byte[] childPubKey = Bytes.concat(new byte[]{parity}, x_bytes);
        return Bytes.concat(childPubKey, I_R);
    }

    /**
     * Derives a child extended public key from a parent extended private key.
     * An extended public key has 65 bytes, the left-hand 33-bytes is treated as
     * the public key, and the right-hand 32-bytes is treated as the master
     * chain code. Specifications defined in
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>
     *
     * @param xkey_par the parent extended private key.
     * @param i the child index to derive.
     * @param hardened whether the derived child extended key will be hardened
     * (note: hardened means i = i + (2^31 - 1), or i = 0x80000000 | i).
     * @return the child extended public key derived at child index i.
     */
    public static byte[] NCKDpriv(byte[] xkey_par, int i, boolean hardened) {
        byte[] xKey = CKDpriv(xkey_par, i, hardened);
        byte[] pubKey = Keys.createPubKey(Arrays.copyOfRange(xKey, 0, 32), CurveParams.G);
        return Bytes.concat(pubKey, Arrays.copyOfRange(xKey, 32, 64));
    }
}
