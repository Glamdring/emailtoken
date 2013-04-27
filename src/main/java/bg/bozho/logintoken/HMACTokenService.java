package bg.bozho.logintoken;

public class HMACTokenService implements TokenService {

    private String hmacKey;
    private long tokenExpirationTime;

    public HMACTokenService(String hmacKey) {
        this.hmacKey = hmacKey;
    }
    public HMACTokenService(String hmacKey, long tokenExpirationTime) {
        this.hmacKey = hmacKey;
        this.tokenExpirationTime = tokenExpirationTime;
    }

    public String generateQueryString(String id, long timestamp) {
        return "id=" + id + "&timestamp=" + timestamp + "&token=" + generateToken(id, timestamp);
    }

    public String generateToken(String id, long timestamp) {
        String data = id + timestamp;
        return DigestUtils.hmac(data, hmacKey);
    }

    public boolean verify(String token, String id, long timestamp) {
        // check if the token has expired
        if (tokenExpirationTime > 0 &&
                timestamp + tokenExpirationTime < System.currentTimeMillis()) {
            return false;
        }

        String expected = generateToken(id, timestamp);
        return expected.equals(token);
    }
}
