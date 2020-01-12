package burp;

public interface AWSCredential
{
    public boolean isTemporary();
    public String getAccessKeyId();
    public String getSecretKey();
    public String getSessionToken(); // temporary credentials use this
}
