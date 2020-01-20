package burp;

/*
This class represents a permanent AWS credential generated with IAM
 */
public class AWSPermanentCredential extends AWSCredential
{
    private AWSPermanentCredential() {};

    public AWSPermanentCredential(String accessKeyId, String secretKey)
    {
        setAccessKeyId(accessKeyId);
        setSecretKey(secretKey);
    }

    @Override
    public boolean isTemporary() { return false; }

    @Override
    public String getClassName()
    {
        return getClass().getName();
    }

}
