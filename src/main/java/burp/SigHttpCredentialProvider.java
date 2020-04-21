package burp;

import burp.error.SigCredentialProviderException;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

public class SigHttpCredentialProvider implements SigCredentialProvider
{
    public static final String PROVIDER_NAME = "HttpGet";
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getBurp().callbacks;
    private static final IExtensionHelpers helpers = BurpExtender.getBurp().helpers;

    private URI requestUri;
    private transient SigCredential credential;

    public URI getUrl()
    {
        return requestUri;
    }

    private SigHttpCredentialProvider() {};

    public SigHttpCredentialProvider(String url) {
        init(url);
    }

    private void init(String url) {
        try {
            requestUri = new URL(url).toURI();
        } catch (MalformedURLException | URISyntaxException exc) {
            throw new IllegalArgumentException("Invalid URL provided to HttpProvider: " + url);
        }

        if (!Arrays.asList("http", "https").contains(requestUri.getScheme())) {
            throw new IllegalArgumentException("Invalid protocol. Must be http(s)");
        }
    }

    private long expirationTimeToEpochSeconds(final String expiry) {
        try {
            return Long.parseLong(expiry);
        } catch (NumberFormatException ignored) {

        }

        try {
            return Instant.from(DateTimeFormatter.ISO_INSTANT.parse(expiry)).getEpochSecond();
        } catch (DateTimeException ignored) {

        }

        throw new IllegalArgumentException("Failed to parse expiration timestamp");
    }

    /*
    NOTE: Synchronization is intentionally omitted here for performance reasons. It is possible that 2 or more
    threads could refresh the credentials at the same time which is fine since a copy of valid credentials
    is always returned. For static credentials, synchronization is not desired at all. The http server is free to
    switch between static and temporary credentials for successive calls.
     */
    private SigCredential renewCredential() throws SigCredentialProviderException
    {
        credential = null;
        SigCredential newCredential = null;
        byte[] response;
        try {
            response = callbacks.makeHttpRequest(requestUri.getHost(),
                    requestUri.getPort(),
                    requestUri.getScheme().equalsIgnoreCase("https"),
                    helpers.buildHttpRequest(requestUri.toURL()));
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL for HttpGet: "+requestUri);
        }

        if (response == null) {
            throw new SigCredentialProviderException("Failed to get response from "+requestUri);
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        if (responseInfo.getStatusCode() != 200)
            throw new SigCredentialProviderException(String.format("GET request returned error: %d %s", responseInfo.getStatusCode(), requestUri));
        final String responseBody = helpers.bytesToString(Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length));

        try {
            // expect similar object to sts:AssumeRole
            JsonObject credentialObject = new Gson().fromJson(responseBody, JsonObject.class);
            if (credentialObject.has("SessionToken")) {
                newCredential = new SigTemporaryCredential(
                        credentialObject.get("AccessKeyId").getAsString(),
                        credentialObject.get("SecretAccessKey").getAsString(),
                        credentialObject.get("SessionToken").getAsString(),
                        expirationTimeToEpochSeconds(credentialObject.get("Expiration").getAsString()));
            } else {
                newCredential = new SigStaticCredential(
                        credentialObject.get("AccessKeyId").getAsString(),
                        credentialObject.get("SecretAccessKey").getAsString());
            }
        } catch (JsonParseException | NullPointerException | IllegalArgumentException exc) {
            throw new SigCredentialProviderException("Failed to parse HttpProvider response");
        }
        credential = newCredential;
        return newCredential;
    }

    @Override
    public SigCredential getCredential() throws SigCredentialProviderException
    {
        SigCredential credentialCopy = credential;
        if (credentialCopy == null) {
            credentialCopy = renewCredential();
        }
        else {
            if (credentialCopy.isTemporary()) {
                if (SigTemporaryCredential.shouldRenewCredential(((SigTemporaryCredential)credentialCopy))) {
                    // fewer than 30 seconds until expiration, refresh
                    credentialCopy = renewCredential();
                }
            }
            else {
                // always refresh permanent credentials. seems counter-intuitive but if the user
                // isn't just using a static provider there must be a reason.
                credentialCopy = renewCredential();
            }
        }
        if (credentialCopy == null) {
            throw new SigCredentialProviderException("Failed to get credential from "+ requestUri);
        }
        return credentialCopy;
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public String getClassName() { return getClass().getName();}

}
