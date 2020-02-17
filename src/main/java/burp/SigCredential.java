package burp;

import java.util.regex.Pattern;

public abstract class SigCredential
{
    protected static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{16,128}$");
    protected static final Pattern secretKeyPattern = Pattern.compile("^[a-zA-Z0-9/+]{40,128}$"); // base64 characters. not sure on length

    private String accessKeyId;
    private String secretKey;

    abstract boolean isTemporary();

    abstract String getClassName();

    public String getAccessKeyId()
    {
        return accessKeyId;
    }

    public String getSecretKey()
    {
        return secretKey;
    }

    protected void setAccessKeyId(final String accessKeyId) {
        if (accessKeyIdPattern.matcher(accessKeyId).matches())
            this.accessKeyId = accessKeyId;
        else
            throw new IllegalArgumentException("Credential accessKeyId must match pattern "+accessKeyIdPattern.pattern());
    }

    protected void setSecretKey(final String secretKey) {
        if (secretKeyPattern.matcher(secretKey).matches())
            this.secretKey = secretKey;
        else
            throw new IllegalArgumentException("Credential secretKey must match pattern "+secretKeyPattern.pattern());
    }

    public String getExportString()
    {
        String export = "";
        export += String.format("aws_access_key_id = %s\n", getAccessKeyId());
        export += String.format("aws_secret_access_key = %s\n", getSecretKey());
        return export;
    }

    public String toString()
    {
        return String.format("accessKeyId = %s, secretKey = %s", this.accessKeyId, this.secretKey);
    }
}
