package com.eawf.deriver;

import com.eawf.deriver.bitcoin.CKD;
import com.eawf.deriver.util.Bytes;
import com.eawf.deriver.util.ExtendedKeyFormatException;
import com.eawf.deriver.util.Hashes;
import com.eawf.deriver.util.Keys;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

/**
 *
 * @author Carson Mullins
 */
public class Main {

    private static final Scanner scan = new Scanner(System.in);

    /**
     * @param args the command line arguments, of which there should be none.
     */
    public static void main(String[] args) {
        // Start the command line application, prompting for input until terminated.
        String input;
        while (true) {
            clearScreen();
            // Ask user for the extended public key.
            System.out.println("Enter the Account-Level Extended Public Key (Q to exit).");
            input = scan.nextLine();
            if (input.equalsIgnoreCase("Q")) {
                break;
            }
            try {
                byte[] xkey_bytes = Keys.validateExtendedKey(input);
                // Separate deserialize the extended key into version, chain code, and public key.
                byte[] version = Arrays.copyOfRange(xkey_bytes, 0, 4);
                byte[] chainCodeParent = Arrays.copyOfRange(xkey_bytes, 13, 45);
                byte[] publicKeyParent = Arrays.copyOfRange(xkey_bytes, xkey_bytes.length - 33, xkey_bytes.length);
                // Concatenate the public key with the chain code to get the account-level extended key
                // used for derivation.
                byte[] xkeyAccount = Bytes.concat(publicKeyParent, chainCodeParent);
                // Derive External Extended Public Key m/XX/0'/X'/0
                byte[] xkeyExternal = CKD.CKDpub(xkeyAccount, 0);
                // Repeatedly ask user for indexes until prompted to quit.
                do {
                    // Derive an address at a given index (looping if invalid input)
                    int indexAddress = -1;
                    boolean validIndex = false;
                    while (!validIndex) {
                        clearScreen();
                        System.out.print("Enter an Address index (Q to change extended key): ");
                        input = scan.nextLine();
                        if (input.equalsIgnoreCase("Q")) {
                            break;
                        }
                        try {
                            double doubleIndex = Double.parseDouble(input);
                            if (doubleIndex > Integer.MAX_VALUE) {
                                System.out.println("Index must be less than 2,147,483,648.");
                                pause(1500);
                            } else if (doubleIndex < 0) {
                                System.out.println("Index cannot be negative.");
                                pause(1500);
                            } else if (Math.floor(doubleIndex) != (int) doubleIndex) {
                                System.out.println("Index must be a whole number.");
                                pause(1500);
                            } else {
                                indexAddress = (int) doubleIndex;
                                validIndex = true;
                            }
                        } catch (NumberFormatException ex) {
                            System.out.println("Only numbers are allowed.");
                            pause(1500);
                        }
                    }
                    if (indexAddress == -1) {
                        break;
                    }
                    clearScreen();
                    // Derive and display information about the Address at the given index.
                    byte[] xkeyAddress = CKD.CKDpub(xkeyExternal, indexAddress);
                    byte[] publicKey = Arrays.copyOfRange(xkeyAddress, 0, 33);
                    byte[] pubKeyHash = Hashes.hash160(publicKey);
                    String address;
                    String addressType;
                    if (Arrays.equals(version, Keys.XPUB)) {
                        // If xpub, derive as P2PKH
                        addressType = "P2PKH";
                        address = Bytes.getAddressP2PKH(pubKeyHash);
                    } else if (Arrays.equals(version, Keys.YPUB)) {
                        // If ypub, derive as P2SH-P2WPKH
                        addressType = "P2SH-P2WPKH";
                        address = Bytes.getAddressP2SHP2WPKH(pubKeyHash);
                    } else {
                        // If zpub, derive as P2WPKH
                        addressType = "P2WPKH";
                        address = Bytes.getAddressP2WPKH(pubKeyHash);
                    }
                    System.out.println(addressType + " Address at index " + indexAddress + ":");
                    System.out.println(address + System.lineSeparator());
                    // Wait for user input before repeating.
                    System.out.println("Enter to continue...");
                    scan.nextLine();
                } while (true);
            } catch (ExtendedKeyFormatException ex) {
                System.out.println(ex.getMessage());
                pause(1500);
            }
        }
        scan.close();
    }

    public static void pause(int milliseconds) {
        try {
            Thread.sleep(milliseconds);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Clears the console screen. Works on Linux and Windows, but has not been
     * tested with macOS.
     */
    public static void clearScreen() {
        String system = System.getProperty("os.name");
        if (system.startsWith("Linux")) {
            System.out.print("\033[H\033[2J");
            System.out.flush();
        } else if (system.startsWith("Windows")) {
            try {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } catch (IOException | InterruptedException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

}
