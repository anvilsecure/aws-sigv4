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

    private static final String STS_HOST = "sts.amazonaws.com";
    private static int CREDENTIAL_RENEWAL_AGE = 60; // seconds
    public static final int CREDENTIAL_LIFETIME_MIN = 900; // 900 is aws minimum
    public static final int CREDENTIAL_LIFETIME_MAX = 43200;
    public static final String ROLE_SESSION_NAME_DEFAULT = "burp-awsig";

    public String getRoleArn()
    {
        return this.roleArn;
    }
    public void setRoleArn(final String roleArn)
    {
        this.roleArn = roleArn;
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
    public void setDurationSeconds(int durationSeconds)
    {
        if (durationSeconds < CREDENTIAL_LIFETIME_MIN) {
            durationSeconds = CREDENTIAL_LIFETIME_MIN;
        }
        else if (durationSeconds > CREDENTIAL_LIFETIME_MAX) {
            durationSeconds = CREDENTIAL_LIFETIME_MAX;
        }
        this.durationSeconds = durationSeconds;
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
        // TODO validate these values? see regex patterns in AWSProfile
        private AWSAssumeRole assumeRole;
        public Builder(final String roleArn, BurpExtender burp) {
            this.assumeRole = new AWSAssumeRole(roleArn, burp);
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
            this.assumeRole.externalId = externalId;
            return this;
        }
        public AWSAssumeRole build() {
            return this.assumeRole;
        }
    }

    public AWSAssumeRole(final String roleArn, BurpExtender burp)
    {
        this.roleArn = roleArn;
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

    private boolean renewCredentials(final AWSCredentials permanentCredentials)
    {
        burp.logger.info("Fetching temporary credentials for role "+this.roleArn);
        List<String> headers = new ArrayList<>();
        headers.add("POST / HTTP/1.1");
        headers.add("Accept: application/json");
        headers.add("Content-Type: application/x-www-form-urlencoded; charset=utf-8");
        String bodyString = String.format("Action=AssumeRole&Version=2011-06-15&RoleArn=%s&RoleSessionName=%s&DurationSeconds=%d",
                burp.helpers.urlEncode(this.roleArn), burp.helpers.urlEncode(this.sessionName), this.durationSeconds);
        if (this.externalId != null && !this.externalId.equals("")) {
            bodyString += String.format("&ExternalId=%s", burp.helpers.urlEncode(this.externalId));
        }
        byte[] body = burp.helpers.stringToBytes(bodyString);

        AWSSignedRequest signedRequest = new AWSSignedRequest(
                burp.helpers.buildHttpService(STS_HOST, 443, true),
                burp.helpers.buildHttpMessage(headers, body),
                burp.helpers,
                burp.logger);
        AWSProfile stsProfile = new AWSProfile.Builder(
                "sts-temp",
                permanentCredentials.getAccessKeyId(),
                permanentCredentials.getSecretKey())
                .withService("sts")
                .build();
        signedRequest.applyProfile(stsProfile);
        byte[] signedBytes = signedRequest.getSignedRequestBytes(permanentCredentials);

        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        IRequestInfo requestInfo = burp.helpers.analyzeRequest(signedBytes);
        headers = requestInfo.getHeaders();
        headers.remove(0); // POST / HTTP/1.1

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .uri(URI.create("https://"+STS_HOST+"/"));
        for (String header : headers) {
            burp.logger.debug("Adding header: "+header);
            String[] value = header.split(": ", 2);
            // remove restricted headers
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
	    burp.logger.error(String.format("Failed to send request to %s: %s", STS_HOST, exc.toString()));
            return false;
        }

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
                .build();
    }

    public static AWSAssumeRole fromJsonObject(final JsonObject obj, BurpExtender burp) {
        return new AWSAssumeRole.Builder(obj.getString("roleArn"), burp)
                .withRoleSessionName(obj.getString("roleSessionName"))
                .withDurationSeconds(obj.getInt("durationSeconds"))
                .build();
    }
}
