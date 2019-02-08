package edu.ccsu.cs492;

public class TEA {

    private static final int DELTA = 0x9e3779b9; // 2^32/golden ratio
    private static long MASK32 = (1L << 32) - 1;

    /**
     * TEA encryption portion, performs 32 runs on a single 64 bit block
     *
     * @param block the block to be encrypted
     * @param key   128 bit key as an array of 4 integers
     * @return 64 bit ciphertext of the block encrypted with the given key
     */
    public static long encrypt(long block, int[] key) {
        checkKey(key); // ensure the key can be used
        System.out.println(String.format("0x%08X", MASK32));
        int rBlock = (int) block; // right half of the block
        int lBlock = (int) (block >>> 32); // left half of the block
        int k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];

        long sum = 0;
        for (int i = 0; i < 32; i++) {
            sum += DELTA;
            lBlock += ((rBlock << 4) + k0) ^ (rBlock + sum) ^ ((rBlock >>> 5) + k1);
            rBlock += ((lBlock << 4) + k2) ^ (lBlock + sum) ^ ((lBlock >>> 5) + k3);
        }
        return (lBlock & MASK32) << 32 | (rBlock & MASK32);
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
