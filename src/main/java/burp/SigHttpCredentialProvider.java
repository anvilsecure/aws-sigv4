package burp;

import burp.error.SigCredentialProviderException;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class SigHttpCredentialProvider implements SigCredentialProvider
{
    public static final String PROVIDER_NAME = "HttpGet";
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getBurp().callbacks;
    private static final IExtensionHelpers helpers = BurpExtender.getBurp().helpers;

    @Getter
    private URI requestUri;
    private List<String> customHeaders = List.of();
    private transient SigCredential credential;

    public Optional<String> getCustomHeader() {
        if (customHeaders.size() > 0) {
            return Optional.of(customHeaders.get(0));
        }
        return Optional.empty();
    }

    private SigHttpCredentialProvider() {};

    public SigHttpCredentialProvider(String url, String header) {
        init(url, header);
    }


    private void init(String url, String header) {
        try {
            requestUri = new URL(url).toURI();
        } catch (MalformedURLException | URISyntaxException exc) {
            throw new IllegalArgumentException("Invalid URL provided to HttpProvider: " + url);
        }

        if (!Arrays.asList("http", "https").contains(requestUri.getScheme())) {
            throw new IllegalArgumentException("Invalid protocol. Must be http(s)");
        }

        if (StringUtils.isNotEmpty(header)) {
            String[] nameAndValue = BurpExtender.splitHeader(header);
            if (nameAndValue[0].length() == 0) {
                throw new IllegalArgumentException("Empty header");
            }
            customHeaders = List.of(nameAndValue[0] + ": " + nameAndValue[1]);
        }
    }

    /*
    NOTE: Synchronization is intentionally omitted here for performance reasons. It is possible that 2 or more
    threads could refresh the credentials at the same time which is fine since a copy of valid credentials
    is always returned. For static credentials, synchronization is not desired at all. The http server is free to
    switch between static and temporary credentials for successive calls.
     */
    private SigCredential renewCredential() throws SigCredentialProviderException {
        byte[] response;
        try {
            IRequestInfo request = helpers.analyzeRequest(helpers.buildHttpRequest(requestUri.toURL()));
            List<String> headers = request.getHeaders();
            headers.addAll(customHeaders);
            response = callbacks.makeHttpRequest(requestUri.getHost(),
                    requestUri.getPort(),
                    requestUri.getScheme().equalsIgnoreCase("https"),
                    helpers.buildHttpMessage(headers, null));
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL for HttpGet: " + requestUri);
        }

        if (response == null) {
            throw new SigCredentialProviderException("Failed to get response from " + requestUri);
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(response);
        if (responseInfo.getStatusCode() != 200)
            throw new SigCredentialProviderException(String.format("GET request returned error: %d %s", responseInfo.getStatusCode(), requestUri));
        final String responseBody = helpers.bytesToString(Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length));

        // expect similar object to sts:AssumeRole
        Optional<SigProfile> profile = JSONCredentialParser.profileFromAssumeRoleJSON(responseBody);
        if (profile.isEmpty()) {
            throw new SigCredentialProviderException("Failed to parse HttpProvider response");
        }
        return profile.get().getCredential();
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
