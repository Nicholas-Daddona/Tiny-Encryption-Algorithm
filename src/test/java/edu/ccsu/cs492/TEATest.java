package edu.ccsu.cs492;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

/**
 * Used to test TEA implementation with set inputs
 * <p>
 * Plaintext and Ciphertext blocks are stored as longs
 */
@RunWith(Parameterized.class)
public class TEATest {

    /**
     * Expected Plaintext from decryption
     */
    private long plainText;

    /**
     * Ciphertext that corresponds to plaintext
     */
    private long expectedCipher;

    /**
     * 128-bit key stored as an array of 4 integers
     */
    private int[] key;

    /**
     * Default Constructor:
     * <p>
     * Used to run tests with multiple parameters
     *
     * @param plainText      the plaintext being used
     * @param expectedCipher the ciphertext corresponding to the provided plaintext
     * @param key            the key used to obtain the ciphertext
     */
    public TEATest(long plainText, long expectedCipher, int[] key) {
        this.plainText = plainText;
        this.expectedCipher = expectedCipher;
        this.key = key;
    }

    /**
     * Tests the Encryption portion of the TEA implementation
     */
    @Test
    public void encryptTest() {
        long result = TEA.encrypt(plainText, key);
        Assert.assertEquals(expectedCipher, result);
    }

    /**
     * Returns a collection of the parameters needed to run the tests
     *
     * @return a collection of the parameters used to run the tests
     */
    @Parameterized.Parameters
    public static Collection input() {
        return Arrays.asList(new Object[][]{
                {0x0123456789abcdefL, 0x7556391b2315d9f8L, new int[]{0xa56babcd, 0xf000ffff, 0xffffffff, 0xabcdef01}},
                {0x0123456789abcdefL, 0xfe18f8f3fcb8dcd3L, new int[]{0xa56babcd, 0xffffffff, 0xffffffff, 0xabcdef01}},
                {0x0123456789abcdefL, 0x97f78dcf1dba72baL, new int[]{0xa56babcd, 0xffabffff, 0xffffffff, 0xabcdef01}}
        });
    }
}
