package com.eawf.deriver.bitcoin;

import com.eawf.deriver.ecc.CurveParams;
import com.eawf.deriver.ecc.ScalarMultiply;
import com.eawf.deriver.util.Bytes;
import com.eawf.deriver.util.Hashes;
import com.eawf.deriver.util.Keys;
import java.nio.ByteBuffer;
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
}
