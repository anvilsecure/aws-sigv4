package burp;

import burp.error.AWSCredentialProviderException;

public interface AWSCredentialProvider {
    AWSCredential getCredential() throws AWSCredentialProviderException;
    String getName();
    String getClassName();
}
