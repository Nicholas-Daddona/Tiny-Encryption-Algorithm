package edu.ccsu.cs492;

/**
 * @author Nicholas Daddona
 * <p>
 * A demonstration of the Tiny Encryption Algorithm
 */
public class Main {

    public static void main(String[] args) {
        long plaintext = 0x01CA456789ABCDEFL; // 64 bit plaintext block
        int[] key = {0xAF6BABCD, 0xEF00F000, 0xFEAFFFFF, 0xABCDEF01}; // 128 bit key split into 4 integers

        System.out.println("Original Plaintext " + String.format("0x%016X", plaintext));
        System.out.println("Key used for encryption " + String.format("0x%08X%X%X%X", key[0], key[1], key[2], key[3]));
        long ciphertext = TEA.encrypt(plaintext, key); // encrypt the block
        System.out.println("Ciphertext resulting from encryption " + String.format("0x%016X", ciphertext));
        long decryptedblock = TEA.decrypt(ciphertext, key); // decrypt the ciphertext using the same key
        System.out.println("Plaintext resulting from decryption of Ciphertext " + String.format("0x%016X", decryptedblock));
    }
}
