package com.eawf.deriver.util;

/**
 * Exception thrown when a given input does not match the proper format of a
 * bitcoin account-level extended public key.
 *
 * @author Carson Mullins
 */
public class ExtendedKeyFormatException extends Exception {

    public ExtendedKeyFormatException(String message) {
        super(message);
    }

}
