package burp;

public class SigStaticCredentialProvider implements SigCredentialProvider
{

    public static final String PROVIDER_NAME = "Static";

    private SigCredential credential;

    private SigStaticCredentialProvider() {};

    public SigStaticCredentialProvider(SigCredential credential)
    {
        this.credential = credential;
    }

    @Override
    public SigCredential getCredential() {
        return credential;
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public String getClassName() { return getClass().getName();}

}
