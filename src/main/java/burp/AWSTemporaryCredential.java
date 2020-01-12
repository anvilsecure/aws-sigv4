package burp;

import java.time.Instant;

/*
This class represents temporary credentials that utilize a session token in addition to a secret key.
 */
public class AWSTemporaryCredential implements AWSCredential
{
    protected long expireTimeEpochSeconds = 0;
    protected String accessKeyId;
    protected String secretKey;
    protected String sessionToken;

    public AWSTemporaryCredential(String accessKeyId, String secretKey, String sessionToken, long expireTimeEpochSeconds)
    {
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
        this.sessionToken = sessionToken;
        this.expireTimeEpochSeconds = expireTimeEpochSeconds;
    }

    @Override
    public String getAccessKeyId()
    {
        return accessKeyId;
    }

    @Override
    public String getSecretKey()
    {
        return secretKey;
    }

    @Override
    public String getSessionToken()
    {
        return sessionToken;
    }

    @Override
    public boolean isTemporary()
    {
        return true;
    }

    // return the number of seconds until the temporary credentials expire
    public long secondsToExpire()
    {
        return expireTimeEpochSeconds - Instant.now().getEpochSecond();
    }

    public String toString()
    {
        return String.format("accessKeyId = %s, secretKey = %s, sessionToken = %s", getAccessKeyId(), getSecretKey(), getSessionToken());
    }
}
