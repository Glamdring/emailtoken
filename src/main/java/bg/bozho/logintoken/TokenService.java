package bg.bozho.logintoken;

public interface TokenService {

    String generateQueryString(String id, long timestamp);

    String generateToken(String id, long timestamp);

}