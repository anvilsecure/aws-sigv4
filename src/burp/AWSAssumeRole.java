package burp;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

public class AWSAssumeRole implements Cloneable
{
    private String roleArn;
    private String sessionName;
    private int durationSeconds;
    private String externalId;

    private AWSCredentials credentials;
    private BurpExtender burp;

    private static final String AWS_STS_HOSTNAME = "sts.amazonaws.com";
    private static int CREDENTIAL_RENEWAL_AGE = 60; // seconds before expiration
    public static final int CREDENTIAL_LIFETIME_MIN = 900;
    public static final int CREDENTIAL_LIFETIME_MAX = 43200;
    public static final String ROLE_SESSION_NAME_DEFAULT = "burp-awsig";

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

    private void setExternalId(final String externalId) {
        if (AWSProfile.externalIdPattern.matcher(externalId).matches())
            this.externalId = externalId;
        else
            throw new IllegalArgumentException("AWSAssumeRole roleArn must match pattern "+AWSProfile.roleArnPattern.pattern());
    }

    private void setDurationSeconds(int durationSeconds)
    {
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
        if (AWSProfile.roleArnPattern.matcher(roleArn).matches())
            this.roleArn = roleArn;
        else
            throw new IllegalArgumentException("AWSAssumeRole roleArn must match pattern "+AWSProfile.roleArnPattern.pattern());
    }

    protected AWSAssumeRole clone()
    {
        return new AWSAssumeRole.Builder(this.roleArn, this.burp)
                .withDurationSeconds(this.durationSeconds)
                .withRoleSessionName(this.sessionName)
                .withExternalId(this.externalId)
                .build();
    }

    public static class Builder {
        private AWSAssumeRole assumeRole;
        public Builder(final String roleArn, BurpExtender burp) {
            this.assumeRole = new AWSAssumeRole(roleArn, burp);
        }
        public Builder(final AWSAssumeRole assumeRole) {
            this.assumeRole = assumeRole.clone();
        }
        public Builder withRoleArn(final String roleArn) {
            this.assumeRole.setRoleArn(roleArn);
            return this;
        }
        public Builder withRoleSessionName(final String sessionName) {
            this.assumeRole.sessionName = sessionName;
            return this;
        }
        public Builder withDurationSeconds(final int durationSeconds) {
            this.assumeRole.setDurationSeconds(durationSeconds);
            return this;
        }
        public Builder withExternalId(final String externalId) {
            this.assumeRole.setExternalId(externalId);
            return this;
        }
        public AWSAssumeRole build() {
            return this.assumeRole;
        }
    }

    private AWSAssumeRole(final String roleArn, BurpExtender burp)
    {
        setRoleArn(roleArn);
        this.sessionName = ROLE_SESSION_NAME_DEFAULT;
        this.durationSeconds = CREDENTIAL_LIFETIME_MIN;
        this.externalId = null;
        this.burp = burp;
    }

    public AWSCredentials getTemporaryCredentials(final AWSCredentials permanentCredentials)
    {
        if ((this.credentials == null) || (this.credentials.secondsToExpire() < CREDENTIAL_RENEWAL_AGE)) {
            // signature is expired or about to expire. get new credentials
            renewCredentials(permanentCredentials);
        }
        return credentials;
    }

    /*
    fetch new temporary credentials.
     */
    private boolean renewCredentials(final AWSCredentials permanentCredentials)
    {
        burp.logger.info("Fetching temporary credentials for role "+this.roleArn);

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
        AWSProfile stsProfile = new AWSProfile.Builder(
                "sts-temp",
                permanentCredentials.getAccessKeyId(),
                permanentCredentials.getSecretKey())
                .withService("sts")
                .build();
        signedRequest.applyProfile(stsProfile);
        byte[] signedBytes = signedRequest.getSignedRequestBytes(permanentCredentials);

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
            return false;
        }

        // process the response and get the temporary credentials
        String responseBody = response.body();
        burp.logger.debug(String.format("HTTP Response %d %s", response.statusCode(), responseBody));
        JsonObject sessionObj = Json.createReader(new StringReader(responseBody)).readObject();
        if (response.statusCode() != 200) {
            burp.logger.error("Failed to retrieve temporary credentials for profile: "+permanentCredentials.getAccessKeyId());
            return false;
        }
        JsonObject credentialsObj = sessionObj.getJsonObject("AssumeRoleResponse").getJsonObject("AssumeRoleResult").getJsonObject("Credentials");
        this.credentials = new AWSCredentials(
                credentialsObj.getString("AccessKeyId"),
                credentialsObj.getString("SecretAccessKey"),
                credentialsObj.getString("SessionToken"),
                credentialsObj.getInt("Expiration"));
        burp.logger.info("Received temporary credentials with accessKeyId "+this.credentials.getAccessKeyId());
        return true;
    }

    public JsonObject toJsonObject() {
        return Json.createObjectBuilder()
                .add("roleArn", this.roleArn)
                .add("roleSessionName", this.sessionName)
                .add("durationSeconds", this.durationSeconds)
                .add("externalId", this.externalId)
                .build();
    }

    public static AWSAssumeRole fromJsonObject(final JsonObject obj, BurpExtender burp) {
        return new AWSAssumeRole.Builder(obj.getString("roleArn"), burp)
                .withRoleSessionName(obj.getString("roleSessionName", ROLE_SESSION_NAME_DEFAULT))
                .withDurationSeconds(obj.getInt("durationSeconds", CREDENTIAL_LIFETIME_MIN))
                .withExternalId(obj.getString("externalId", null))
                .build();
    }
}
