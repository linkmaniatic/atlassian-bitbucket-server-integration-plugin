package com.atlassian.bitbucket.jenkins.internal.applink.oauth;

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang3.StringUtils;

import java.security.SecureRandom;

/**
 * Implementation of {@link Randomizer} that uses the Java {@link SecureRandom} to generate random strings
 */
public class RandomizerImpl implements Randomizer {

    /**
     * Alphanumeric ASCII chars: [0-9], [A-Z], and [a-z]
     */
    @VisibleForTesting
    static final char[] ALPHA_NUM_CODEC =
            "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();

    /**
     * A URL-safe set of characters.
     * <br>
     * ASCII characters [0-9], [A-Z], and [a-z], plus the URL-safe characters '-' and '_', used to generate random
     * strings that are safe to be passed in as URL query params.
     */
    @VisibleForTesting
    static final char[] URL_SAFE_CODEC =
            "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_".toCharArray();

    private final SecureRandom random = new SecureRandom();

    /**
     * Convert randomly generated bytes to an alphanumeric string.
     * <br>
     * The length of the resultant string (in chars) will be the same as the length of the given bytes. Each byte will
     * be converted to a char as follows:
     * <br>
     * 1. The value of the byte is converted to a number between zero and 255 via a bitwise operation:
     * <br>
     * {@code nonNegativeValue = byteValue & 0xFF }
     * <br>
     * 2. The non-negative result is used to select a random char from the {@link #ALPHA_NUM_CODEC alphanumeric chars}:
     * <br>
     * {@code alphaNumChar = ALPHA_NUM_CODEC[nonNegativeValue % ALPHA_NUM_CODEC.length] }
     * <br>
     * Alphanumerical chars are the ASCII letters [0-9], [A-Z], and [a-z].
     *
     * @param bytes        the randomly generated bytes to convert to an alphanumeric String
     * @param allowedChars the characters to choose from to generate the string
     * @return an alphanumeric String generated from the given bytes
     */
    private static String generateString(byte[] bytes, char[] allowedChars) {
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            chars[i] = allowedChars[(bytes[i] & 0xFF) % allowedChars.length];
        }
        return new String(chars);
    }

    public String randomAlphanumericString(int length) {
        if (length == 0) {
            return StringUtils.EMPTY;
        }
        if (length < 0) {
            throw new IllegalArgumentException("Requested random string length " + length + " is less than 0.");
        }
        return generateString(randomBytes(length), ALPHA_NUM_CODEC);
    }

    public String randomUrlSafeString(int length) {
        if (length == 0) {
            return StringUtils.EMPTY;
        }
        if (length < 0) {
            throw new IllegalArgumentException("Requested random string length " + length + " is less than 0.");
        }
        return generateString(randomBytes(length), URL_SAFE_CODEC);
    }

    private byte[] randomBytes(int length) {
        byte[] randomBytes = new byte[length];
        random.nextBytes(randomBytes);
        return randomBytes;
    }
}
