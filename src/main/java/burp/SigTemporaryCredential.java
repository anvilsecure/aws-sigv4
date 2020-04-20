package burp;

import java.time.Instant;

/*
This class represents temporary credentials that utilize a session token in addition to a secret key.
 */
public class SigTemporaryCredential extends SigCredential
{
    private static final long CREDENTIAL_RENEWAL_AGE = 30; // seconds before expiration

    private long expireTimeEpochSeconds;
    private String sessionToken;

    private SigTemporaryCredential() {};

    public static boolean shouldRenewCredential(final SigTemporaryCredential credential) {
        return ((credential == null) || (credential.secondsToExpire() < CREDENTIAL_RENEWAL_AGE));
    }

    public SigTemporaryCredential(String accessKeyId, String secretKey, String sessionToken, long expireTimeEpochSeconds)
    {
        setAccessKeyId(accessKeyId);
        setSecretKey(secretKey);
        setSessionToken(sessionToken);
        this.expireTimeEpochSeconds = expireTimeEpochSeconds;
    }


    public String getSessionToken()
    {
        return sessionToken;
    }

    @Override
    public boolean isTemporary()
    {
        return true;
    }

    @Override
    public String getClassName()
    {
        return getClass().getName();
    }

    protected void setSessionToken(final String sessionToken) {
        this.sessionToken = sessionToken;
    }

    // return the number of seconds until the temporary credentials expire
    public long secondsToExpire()
    {
        return expireTimeEpochSeconds - Instant.now().getEpochSecond();
    }

    @Override
    public String getExportString() {
        String export = super.getExportString();
        export += String.format("aws_session_token = %s\n", getSessionToken());
        return export;
    }

    public String toString()
    {
        return String.format("accessKeyId = %s, secretKey = %s, sessionToken = %s", getAccessKeyId(), getSecretKey(), getSessionToken());
    }
}
