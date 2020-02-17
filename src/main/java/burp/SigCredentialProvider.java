package burp;

import burp.error.SigCredentialProviderException;

public interface SigCredentialProvider
{
    SigCredential getCredential() throws SigCredentialProviderException;
    String getName();
    String getClassName();
}
