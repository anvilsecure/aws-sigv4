package burp;

public class AWSStaticCredentialProvider implements AWSCredentialProvider {

    public static final String PROVIDER_NAME = "Static";

    private AWSCredential credential;

    private AWSStaticCredentialProvider() {};

    public AWSStaticCredentialProvider(AWSCredential credential)
    {
        this.credential = credential;
    }

    @Override
    public AWSCredential getCredential() {
        return credential;
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public String getClassName() { return getClass().getName();}

}
