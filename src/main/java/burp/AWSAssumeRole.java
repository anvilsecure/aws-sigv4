package burp;

import burp.error.AWSCredentialProviderException;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class AWSAssumeRole implements AWSCredentialProvider, Cloneable
{
    public static final Pattern externalIdPattern = Pattern.compile("^[a-zA-Z0-9=@:/,._-]{2,1024}$");
    public static final Pattern roleArnPattern = Pattern.compile("^arn:aws:iam::[0-9]{12}:role/[0-9a-zA-Z+=,.@_-]{1,64}$"); // regionless
    public static final Pattern roleSessionNamePattern = Pattern.compile("^[a-zA-Z0-9+=@,._-]{2,64}$");
    public static final String PROVIDER_NAME = "STSAssumeRole";

    private String roleArn;
    private String sessionName;
    private int durationSeconds;
    private String externalId;

    private AWSTemporaryCredential temporaryCredential;
    private AWSPermanentCredential permanentCredential;
    private final transient BurpExtender burp = BurpExtender.getBurp();

    private static final String AWS_STS_HOSTNAME = "sts.amazonaws.com";
    private static final String AWS_STS_REGION = "us-east-1";
    private static final String AWS_STS_SIGNAME = "sts";
    private static long CREDENTIAL_RENEWAL_AGE = 30; // seconds before expiration
    public static final int CREDENTIAL_LIFETIME_MIN = 900;
    public static final int CREDENTIAL_LIFETIME_MAX = 43200;
    public static final String ROLE_SESSION_NAME_DEFAULT_PREFIX = "BurpAwsig";

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

    public AWSPermanentCredential getPermanentCredential()
    {
        return this.permanentCredential;
    }

    private AWSAssumeRole() {};

    private AWSAssumeRole(final String roleArn, final AWSPermanentCredential credential)
    {
        setRoleArn(roleArn);
        this.permanentCredential = credential;
        this.sessionName = createDefaultRoleSessionName();
        this.durationSeconds = CREDENTIAL_LIFETIME_MIN;
        this.externalId = "";
    }

    private void setExternalId(final String externalId) {
        if (externalIdPattern.matcher(externalId).matches())
            this.externalId = externalId;
        else
            throw new IllegalArgumentException("AWSAssumeRole externalId must match pattern "+externalIdPattern.pattern());
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
            throw new IllegalArgumentException("AWSAssumeRole roleArn must match pattern "+roleArnPattern.pattern());
    }

    private void setRoleSessionName(final String roleSessionName)
    {
        if (roleSessionNamePattern.matcher(roleSessionName).matches())
            this.sessionName = roleSessionName;
        else
            throw new IllegalArgumentException("AWSAssumeRole roleSessionName must match pattern "+roleSessionNamePattern.pattern());
    }

    protected AWSAssumeRole clone()
    {
        return new AWSAssumeRole.Builder(this.roleArn, this.permanentCredential)
                .withDurationSeconds(this.durationSeconds)
                .withRoleSessionName(this.sessionName)
                .tryExternalId(this.externalId)
                .build();
    }

    public static class Builder {
        private AWSAssumeRole assumeRole;
        public Builder(final String roleArn, final AWSPermanentCredential credential) {
            this.assumeRole = new AWSAssumeRole(roleArn, credential);
        }
        public Builder(final AWSAssumeRole assumeRole) {
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
            if (sessionName != null && !sessionName.equals(""))
                withRoleSessionName(sessionName);
            else
                this.assumeRole.sessionName = createDefaultRoleSessionName();
            return this;
        }
        public Builder withDurationSeconds(final int durationSeconds) {
            this.assumeRole.setDurationSeconds(durationSeconds);
            return this;
        }
        public Builder withCredential(AWSPermanentCredential credential) {
            if (credential == null) {
                throw new IllegalArgumentException("AssumeRole permanent credential cannot be null");
            }
            this.assumeRole.permanentCredential = credential;
            return this;
        }
        public Builder withExternalId(final String externalId) {
            this.assumeRole.setExternalId(externalId);
            return this;
        }
        public Builder tryExternalId(final String externalId) {
            if (externalId != null && !externalId.equals(""))
                withExternalId(externalId);
            else
                this.assumeRole.externalId = "";
            return this;
        }
        public AWSAssumeRole build() {
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
    public AWSCredential getCredential() throws AWSCredentialProviderException
    {
        if ((this.temporaryCredential == null) || (this.temporaryCredential.secondsToExpire() < CREDENTIAL_RENEWAL_AGE)) {
            // signature is expired or about to expire. get new credentials
            renewCredential();
        }
        if (this.temporaryCredential == null) {
            throw new AWSCredentialProviderException("Failed to retrieve temp credentials for: "+this.roleArn);
        }
        return temporaryCredential;
    }

    /*
    fetch new temporary credentials.
     */
    private void renewCredential() throws AWSCredentialProviderException
    {
        burp.logger.info("Fetching temporary credentials for role "+this.roleArn);
        this.temporaryCredential = null;

        List<String> headers = new ArrayList<>();
        headers.add("POST / HTTP/1.1");
        headers.add("Accept: application/json");
        headers.add("Content-Type: application/x-www-form-urlencoded; charset=utf-8");

        List<String> parameters = new ArrayList<>();
        parameters.add("Action=AssumeRole");
        parameters.add("Version=2011-06-15");
        parameters.add("RoleArn=" + burp.helpers.urlEncode(this.roleArn));
        parameters.add("RoleSessionName=" + burp.helpers.urlEncode(this.sessionName));
        parameters.add("DurationSeconds=" + this.durationSeconds);
        if (this.externalId != null && !this.externalId.equals("")) {
            parameters.add("ExternalId=" + burp.helpers.urlEncode(this.externalId));
        }
        byte[] body = burp.helpers.stringToBytes(String.join("&", parameters));

        // build the SigV4 signed request
        AWSSignedRequest signedRequest = new AWSSignedRequest(
                burp.helpers.buildHttpService(AWS_STS_HOSTNAME, 443, true),
                burp.helpers.buildHttpMessage(headers, body),
                burp);
        AWSProfile stsProfile = new AWSProfile.Builder("sts-temp", "STS_ASSUME_ROLE_KEYID")
                .withCredentialProvider(new AWSStaticCredentialProvider(permanentCredential), 0)
                .withService(AWS_STS_SIGNAME)
                .withRegion(AWS_STS_REGION)
                .build();
        signedRequest.applyProfile(stsProfile);
        byte[] signedBytes = signedRequest.getSignedRequestBytes(permanentCredential);

        // create http client. get final headers for request.
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        IRequestInfo requestInfo = burp.helpers.analyzeRequest(signedBytes);
        headers = requestInfo.getHeaders();
        headers.remove(0); // POST / HTTP/1.1

        // send the signed AssumeRole request
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .uri(URI.create("https://"+ AWS_STS_HOSTNAME +"/"));
        for (String header : headers) {
            String[] value = header.split(": ", 2);
            // remove headers that the builder must set itself
            if (value[0].toLowerCase().equals("content-length")) {
                continue;
            }
            else if (value[0].toLowerCase().equals("host")) {
                continue;
            }
            requestBuilder.header(value[0], value[1]);
        }
        HttpResponse<String> response = null;
        try {
            response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException exc) {
            burp.logger.error(String.format("Failed to send AssumeRole request to %s: %s", AWS_STS_HOSTNAME, exc.toString()));
            throw new AWSCredentialProviderException(String.format("Failed to send AssumeRole request to %s: %s", AWS_STS_HOSTNAME, exc.toString()));
        }

        // process the response and get the temporary credentials
        if (response.statusCode() != 200) {
            burp.logger.error("Failed to retrieve temporary credentials for profile: "+permanentCredential.getAccessKeyId());
            throw new AWSCredentialProviderException(String.format("Failed to retrieve temporary credentials for profile: "+permanentCredential.getAccessKeyId()));
        }

        final String responseBody = response.body();
        burp.logger.debug(String.format("HTTP Response %d %s", response.statusCode(), responseBody));
        try {
            JsonObject sessionObject = new Gson().fromJson(responseBody, JsonObject.class);
            JsonObject credentialsObj = sessionObject.get("AssumeRoleResponse").getAsJsonObject()
                    .get("AssumeRoleResult").getAsJsonObject()
                    .get("Credentials").getAsJsonObject();
            this.temporaryCredential = new AWSTemporaryCredential(
                    credentialsObj.get("AccessKeyId").getAsString(),
                    credentialsObj.get("SecretAccessKey").getAsString(),
                    credentialsObj.get("SessionToken").getAsString(),
                    credentialsObj.get("Expiration").getAsLong());
            burp.logger.info("Received temporary credentials with accessKeyId " + this.temporaryCredential.getAccessKeyId());
        } catch (NullPointerException exc) {
            throw new AWSCredentialProviderException("Unexpected AssumeRole response");
        }
    }

}
