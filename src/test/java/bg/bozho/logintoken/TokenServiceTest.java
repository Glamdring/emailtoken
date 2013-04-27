package bg.bozho.logintoken;

import org.junit.Assert;
import org.junit.Test;

public class TokenServiceTest {

    @Test
    public void tokenVerificationTest() {
        HMACTokenService service = new HMACTokenService("foo");
        long timestamp = System.currentTimeMillis();
        String id = "1234";
        String token = service.generateToken(id, timestamp);
        boolean result = service.verify(token, id, timestamp);
        Assert.assertTrue(result);
    }

    @Test
    public void expiredTokenVerificationTest() throws InterruptedException{
        HMACTokenService service = new HMACTokenService("foo", 1000);
        long timestamp = System.currentTimeMillis();
        String id = "1234";
        String token = service.generateToken(id, timestamp);
        Thread.sleep(1100);
        boolean result = service.verify(token, id, timestamp);
        Assert.assertFalse(result);
    }
}
