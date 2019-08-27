package burp;

import jdk.internal.net.http.HttpRequestBuilderImpl;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

import javax.json.Json;
import javax.json.JsonObject;

public class AWSAssumeRole implements Cloneable
{
    private AWSProfile profile;
    private String roleArn;
    private String sessionName;
    private int durationSeconds;
    private AWSCredentials credentials;
    private BurpExtender burp;

    private static final String STS_HOST = "sts.amazonaws.com";
    private static int CREDENTIAL_RENEWAL_AGE = 60; // seconds
    public static final int CREDENTIAL_LIFETIME_MIN = 900; // 900 is aws minimum
    public static final String ROLE_SESSION_NAME_DEFAULT = "burp-awsig";

    public String getRoleArn()
    {
        return this.roleArn;
    }

    public String getSessionName()
    {
        return this.sessionName;
    }

    public int getDurationSeconds()
    {
	return this.durationSeconds;
    }

    protected AWSAssumeRole clone()
    {
        return new AWSAssumeRole(new AWSProfile(this.profile), this.roleArn, this.sessionName, this.durationSeconds, this.burp);
    }

    public AWSAssumeRole(final AWSProfile profile, final String roleArn, final String sessionName, final int durationSeconds, BurpExtender burp)
    {
        this.profile = profile;
        this.roleArn = roleArn;
        this.sessionName = sessionName;
	this.durationSeconds = durationSeconds < CREDENTIAL_LIFETIME_MIN ? CREDENTIAL_LIFETIME_MIN : durationSeconds;
        this.burp = burp;
    }

    public AWSCredentials getCredentials()
    {
        if ((this.credentials == null) || (this.credentials.secondsToExpire() < CREDENTIAL_RENEWAL_AGE)) {
            // signature is expired or about to expire. get new credentials
            renewCredentials();
        }
        return credentials;
    }

    private boolean renewCredentials()
    {
        burp.logger.info("Fetching temporary credentials for role "+this.roleArn);
        List<String> headers = new ArrayList<>();
        headers.add("POST / HTTP/1.1");
        headers.add("Accept: application/json");
        headers.add("Content-Type: application/x-www-form-urlencoded; charset=utf-8");
        byte[] body = burp.helpers.stringToBytes(
                String.format("Action=AssumeRole&Version=2011-06-15&RoleArn=%s&RoleSessionName=%s&DurationSeconds=%s",
                        burp.helpers.urlEncode(this.roleArn), burp.helpers.urlEncode(this.sessionName), this.durationSeconds));

        AWSSignedRequest signedRequest = new AWSSignedRequest(
                burp.helpers.buildHttpService(STS_HOST, 443, true),
                burp.helpers.buildHttpMessage(headers, body),
                burp.helpers,
                burp.logger);
        AWSProfile stsProfile = new AWSProfile(this.profile);
        stsProfile.service = "sts";
        signedRequest.applyProfile(stsProfile);
        byte[] signedBytes = signedRequest.getSignedRequestBytes(this.profile.getPermanentCredentials());

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
            burp.logger.error("Failed to retrieve temporary credentials for profile: "+this.profile.name);
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
}
