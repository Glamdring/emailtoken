package bg.bozho.logintoken;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class DigestUtils {

    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final char[] DIGITS_LOWER = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    /**
     * Calculates a HmacSHA256 value
     *
     * @param data
     * @param key
     * @return HmacSHA1
     */
    public static String hmac(String data, String key) {
        try {
            // get an hmac_sha1 key from the raw key bytes
            SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA256_ALGORITHM);
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data.getBytes("UTF-8"));

            return new String(encodeHex(rawHmac));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeyException ex) {
            throw new RuntimeException("Problem with calculating hmac", ex);
        }
    }

    public static String hash(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");

            md.update(data.getBytes("UTF-8"));
            byte[] digest = md.digest();
            return new String(encodeHex(digest));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            throw new RuntimeException("Problem generating hash", ex);
        }
    }

    // copied from commons-codec
    private static char[] encodeHex(byte[] data) {
        int l = data.length;
        char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS_LOWER[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS_LOWER[0x0F & data[i]];
        }
        return out;
    }
}
