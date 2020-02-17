package burp;

/*
This class represents a permanent AWS credential generated with IAM
 */
public class SigStaticCredential extends SigCredential
{
    private SigStaticCredential() {};

    public SigStaticCredential(String accessKeyId, String secretKey)
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
