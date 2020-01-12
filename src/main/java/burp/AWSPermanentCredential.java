package burp;

/*
This class represents a permanent AWS credential generated with IAM
 */
public class AWSPermanentCredential implements AWSCredential
{
    private String accessKeyId;
    private String secretKey;

    public AWSPermanentCredential(String accessKeyId, String secretKey)
    {
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
    }

    @Override
    public boolean isTemporary() { return false; }

    @Override
    public String getAccessKeyId() { return this.accessKeyId; }

    @Override
    public String getSecretKey() { return this.secretKey; }

    @Override
    public String getSessionToken() { return null; }

    public String toString()
    {
        return String.format("accessKeyId = %s, secretKey = %s", this.accessKeyId, this.secretKey);
    }
}
