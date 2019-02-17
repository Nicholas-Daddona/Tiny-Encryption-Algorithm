package edu.ccsu.cs492;

/**
 * An implementation of the Tiny Encryption Algorithm
 * <p>
 * Encryption and Decryption portions operate on a single long value. When the right and left halves are recombined, a
 * mask is used to prevent any errors
 *
 * @author Nicholas Daddona
 */
public class TEA {

    private static final int DELTA = 0x9e3779b9; // 2^32/golden ratio
    private static final long BITMASK32 = 0xffffffffL; // (1L << 32) - 1

    /**
     * TEA encryption portion, performs 32 runs on a single 64 bit block
     *
     * @param block the block to be encrypted
     * @param key   128 bit key as an array of 4 integers
     * @return 64 bit ciphertext of the block encrypted with the given key
     */
    public static long encrypt(long block, int[] key) {
        checkKey(key); // ensure the key can be used
        int rBlock = (int) block; // right half of the block
        int lBlock = (int) (block >>> 32); // left half of the block

        long sum = 0;
        for (int i = 0; i < 32; i++) {
            sum += DELTA;
            lBlock += ((rBlock << 4) + key[0]) ^ (rBlock + sum) ^ ((rBlock >>> 5) + key[1]);
            rBlock += ((lBlock << 4) + key[2]) ^ (lBlock + sum) ^ ((lBlock >>> 5) + key[3]);
        }
        return (lBlock & BITMASK32) << 32 | (rBlock & BITMASK32);
    }

    /**
     * TEA decryption portion, performs 32 runs on a single 64 bit block
     *
     * @param block the block of ciphertext being decrypted
     * @param key   the key used for decryption
     * @return the plaintext obtained from decryption
     */
    public static long decrypt(long block, int[] key) {
        checkKey(key); // ensure the key can be used
        int rBlock = (int) block; // right half of the block
        int lBlock = (int) (block >>> 32); // left half of the block

        long sum = DELTA << 5;
        for (int i = 0; i < 32; i++) {
            rBlock -= ((lBlock << 4) + key[2]) ^ (lBlock + sum) ^ ((lBlock >>> 5) + key[3]);
            lBlock -= ((rBlock << 4) + key[0]) ^ (rBlock + sum) ^ ((rBlock >>> 5) + key[1]);
            sum -= DELTA;
        }
        return (lBlock & BITMASK32) << 32 | (rBlock & BITMASK32);
    }

    /**
     * Used to check if a key is valid for encryption/decryption
     *
     * @param key the key being checked
     */
    private static void checkKey(int[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }
        if (key.length != 4) {
            throw new IllegalArgumentException("Key must be an array of 4 integers");
        }
    }
}
