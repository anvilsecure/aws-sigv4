package burp;

import burp.error.SigCredentialProviderException;
import org.apache.commons.lang3.StringUtils;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.services.sts.model.StsException;

import java.util.regex.Pattern;

public class SigAssumeRoleCredentialProvider implements SigCredentialProvider, Cloneable
{
    public static final Pattern externalIdPattern = Pattern.compile("^[a-zA-Z0-9=@:/,._-]{2,1024}$");
    public static final Pattern roleArnPattern = Pattern.compile("^arn:aws:iam::[0-9]{12}:role(?:/|/[\u0021-\u007E]{1,510}/)[0-9a-zA-Z+=,.@_-]{1,64}$"); // regionless
    public static final Pattern roleSessionNamePattern = Pattern.compile("^[a-zA-Z0-9+=@,._-]{2,64}$");
    public static final String PROVIDER_NAME = "STSAssumeRole";

    private String roleArn;
    private String sessionName;
    private int durationSeconds;
    private String externalId;

    private transient SigTemporaryCredential temporaryCredential;
    private SigCredential staticCredential;
    private final transient BurpExtender burp = BurpExtender.getBurp();

    public static final int CREDENTIAL_LIFETIME_MIN = 900;
    public static final int CREDENTIAL_LIFETIME_MAX = 43200;
    public static final String ROLE_SESSION_NAME_DEFAULT_PREFIX = "BurpSigV4";

    public String getRoleArn()
    {
        return this.roleArn;
    }
    public String getExternalId() { return this.externalId; }
    public String getSessionName()
    {
        return this.sessionName;
    }
    public int getDurationSeconds()
    {
        return this.durationSeconds;
    }

    public SigCredential getStaticCredential()
    {
        return this.staticCredential;
    }

    private SigAssumeRoleCredentialProvider() {};

    private SigAssumeRoleCredentialProvider(final String roleArn, final SigCredential credential)
    {
        setRoleArn(roleArn);
        this.staticCredential = credential;
        this.sessionName = createDefaultRoleSessionName();
        this.durationSeconds = CREDENTIAL_LIFETIME_MIN;
        this.externalId = "";
    }

    private void setExternalId(final String externalId) {
        if (externalIdPattern.matcher(externalId).matches())
            this.externalId = externalId;
        else
            throw new IllegalArgumentException("AssumeRole externalId must match pattern "+externalIdPattern.pattern());
    }

    private void setDurationSeconds(int durationSeconds)
    {
        // duration must be in range [900, 43200]
        if (durationSeconds < CREDENTIAL_LIFETIME_MIN) {
            durationSeconds = CREDENTIAL_LIFETIME_MIN;
        }
        else if (durationSeconds > CREDENTIAL_LIFETIME_MAX) {
            durationSeconds = CREDENTIAL_LIFETIME_MAX;
        }
        this.durationSeconds = durationSeconds;
    }

    private void setRoleArn(final String roleArn)
    {
        if (roleArnPattern.matcher(roleArn).matches())
            this.roleArn = roleArn;
        else
            throw new IllegalArgumentException("AssumeRole roleArn must match pattern "+roleArnPattern.pattern());
    }

    private void setRoleSessionName(final String roleSessionName)
    {
        if (roleSessionNamePattern.matcher(roleSessionName).matches())
            this.sessionName = roleSessionName;
        else
            throw new IllegalArgumentException("AssumeRole roleSessionName must match pattern "+roleSessionNamePattern.pattern());
    }

    protected SigAssumeRoleCredentialProvider clone()
    {
        return new SigAssumeRoleCredentialProvider.Builder(this.roleArn, this.staticCredential)
                .withDurationSeconds(this.durationSeconds)
                .withRoleSessionName(this.sessionName)
                .tryExternalId(this.externalId)
                .build();
    }

    public static class Builder {
        private SigAssumeRoleCredentialProvider assumeRole;
        public Builder(final String roleArn, final SigCredential credential) {
            this.assumeRole = new SigAssumeRoleCredentialProvider(roleArn, credential);
        }
        public Builder(final SigAssumeRoleCredentialProvider assumeRole) {
            this.assumeRole = assumeRole.clone();
        }
        // with -> strict, try -> lax
        public Builder withRoleArn(final String roleArn) {
            this.assumeRole.setRoleArn(roleArn);
            return this;
        }
        public Builder withRoleSessionName(final String sessionName) {
            this.assumeRole.setRoleSessionName(sessionName);
            return this;
        }
        public Builder tryRoleSessionName(final String sessionName) {
            if (StringUtils.isNotEmpty(sessionName))
                withRoleSessionName(sessionName);
            else
                this.assumeRole.sessionName = createDefaultRoleSessionName();
            return this;
        }
        public Builder withDurationSeconds(final int durationSeconds) {
            this.assumeRole.setDurationSeconds(durationSeconds);
            return this;
        }
        public Builder withCredential(SigCredential credential) {
            if (credential == null) {
                throw new IllegalArgumentException("AssumeRole permanent credential cannot be null");
            }
            this.assumeRole.staticCredential = credential;
            return this;
        }
        public Builder withExternalId(final String externalId) {
            this.assumeRole.setExternalId(externalId);
            return this;
        }
        public Builder tryExternalId(final String externalId) {
            if (StringUtils.isNotEmpty(externalId))
                withExternalId(externalId);
            else
                this.assumeRole.externalId = "";
            return this;
        }
        public SigAssumeRoleCredentialProvider build() {
            return this.assumeRole;
        }
    }

    private static String createDefaultRoleSessionName()
    {
        return String.format("%s_%d", ROLE_SESSION_NAME_DEFAULT_PREFIX, System.currentTimeMillis());
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public String getClassName() { return getClass().getName(); }

    @Override
    public SigCredential getCredential() throws SigCredentialProviderException
    {
        SigTemporaryCredential credentialCopy = this.temporaryCredential;
        if (SigTemporaryCredential.shouldRenewCredential(credentialCopy)) {
            // signature is expired or about to expire. get new credentials
            credentialCopy = renewCredential();
        }
        if (credentialCopy == null) {
            throw new SigCredentialProviderException("Failed to retrieve temp credentials for: "+this.roleArn);
        }
        return credentialCopy;
    }

    /*
    Fetch new temporary credentials. This is synchronized so multiple threads don't try to refresh creds
    at the same time. The result would be additional, unnecessary calls to STS but is otherwise harmless.
     */
    private synchronized SigTemporaryCredential renewCredential() throws SigCredentialProviderException
    {
        // ensure creds weren't just renewed by another thread
        SigTemporaryCredential credentialCopy = this.temporaryCredential;
        if (!SigTemporaryCredential.shouldRenewCredential(credentialCopy)) {
            return credentialCopy;
        }

        burp.logger.info("Fetching temporary credentials for role "+this.roleArn);
        this.temporaryCredential = null;
        AwsCredentials credentials;
        if (staticCredential.isTemporary()) {
            credentials = AwsSessionCredentials.create(staticCredential.getAccessKeyId(), staticCredential.getSecretKey(), ((SigTemporaryCredential) staticCredential).getSessionToken());
        } else {
            credentials = AwsBasicCredentials.create(staticCredential.getAccessKeyId(), staticCredential.getSecretKey());
        }
        StsClient stsClient = StsClient.builder()
                .httpClient(new SdkHttpClientForBurp())
                .region(Region.US_EAST_1)
                .credentialsProvider(() -> credentials)
                .build();

        AssumeRoleRequest.Builder requestBuilder = AssumeRoleRequest.builder()
                .roleArn(this.roleArn)
                .roleSessionName(this.sessionName)
                .durationSeconds(this.durationSeconds);
        if (StringUtils.isNotEmpty(this.externalId)) {
            requestBuilder.externalId(this.externalId);
        }

        try {
            AssumeRoleResponse roleResponse = stsClient.assumeRole(requestBuilder.build());
            Credentials creds = roleResponse.credentials();
            credentialCopy = new SigTemporaryCredential(
                    creds.accessKeyId(),
                    creds.secretAccessKey(),
                    creds.sessionToken(),
                    creds.expiration().getEpochSecond());
        } catch (StsException exc) {
            throw new SigCredentialProviderException("Failed to get role credentials: "+exc.getMessage());
        }
        this.temporaryCredential = credentialCopy;
        return credentialCopy;
    }

}
