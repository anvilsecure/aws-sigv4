package burp;

import java.time.Instant;

public class AWSCredentials
{
    private String accessKeyId = "";
    private String secretKey = "";
    private String sessionToken = null;
    private long expireTimeEpochSeconds = 0;

    public String getSecretKey() { return this.secretKey; }
    public String getSessionToken() { return this.sessionToken; }
    public String getAccessKeyId() {return this.accessKeyId; }

    public AWSCredentials(String accessKeyId, String secretKey)
    {
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
    }

    public AWSCredentials(String accessKeyId, String secretKey, String sessionToken, long expireTimeEpochSeconds)
    {
        this(accessKeyId, secretKey);
        this.sessionToken = sessionToken;
        this.expireTimeEpochSeconds = expireTimeEpochSeconds;
    }


    public long secondsToExpire()
    {
        return this.expireTimeEpochSeconds - Instant.now().getEpochSecond();
    }

    public String toString()
    {
        return String.format("accessKeyId = %s, secretKey = %s, sessionToken = %s", this.accessKeyId, this.secretKey, this.sessionToken);
    }
}
