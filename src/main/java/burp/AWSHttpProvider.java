package burp;

import burp.error.AWSCredentialProviderException;
import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;

public class AWSHttpProvider implements AWSCredentialProvider
{
    public static final String PROVIDER_NAME = "HttpGet";

    private URI requestUrl;
    private transient SSLContext sslContext;
    private transient HttpClient httpClient;
    private AWSCredential credential;
    private Path caBundlePath;

    private final transient BurpExtender burp = BurpExtender.getBurp();

    public URI getUrl()
    {
        return requestUrl;
    }

    public Path getCaBundlePath()
    {
        return caBundlePath;
    }

    private AWSHttpProvider() {};

    public AWSHttpProvider(String url, String caBundle) {
        init(url, caBundle);
    }

    private void init(String url, String caBundle) {
        try {
            requestUrl = new URL(url).toURI();
        } catch (MalformedURLException | URISyntaxException exc) {
            throw new IllegalArgumentException("Invalid URL provided to HttpProvider: " + url);
        }

        if (!requestUrl.getScheme().equals("http") && !requestUrl.getScheme().equals("https")) {
            throw new IllegalArgumentException("Invalid protocol. Must be http(s)");
        }

        caBundlePath = null;
        if (!caBundle.equals("")) {
            caBundlePath = Paths.get(caBundle);
        }
    }

    private void initializeHttpClient()
    {
        if (httpClient != null)
            return;

        if (caBundlePath != null) {
            if (!Files.exists(caBundlePath)) {
                throw new IllegalArgumentException("CA bundle path does not exist: " + caBundlePath.toString());
            }

            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                int count = 0;
                ArrayList<X509Certificate> caCertList = (ArrayList<X509Certificate>) certificateFactory.generateCertificates(new FileInputStream(caBundlePath.toString()));
                for (X509Certificate cert : caCertList) {
                    keyStore.setCertificateEntry(String.format("caCert-%d", count), cert);
                    count++;
                }
                trustManagerFactory.init(keyStore);
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
            } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException exc) {
                throw new IllegalArgumentException(String.format("Failed to load ca cert bundle from: %s: %s", caBundlePath, exc));
            }
        }

        HttpClient.Builder builder = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15));
        if (sslContext != null)
            builder.sslContext(sslContext);
        httpClient = builder.build();
    }

    private void renewCredential() throws AWSCredentialProviderException
    {
        try {
            initializeHttpClient();
        } catch (Exception exc) {
            throw new AWSCredentialProviderException(exc.getMessage());
        }

        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .GET()
                .uri(requestUrl);

        HttpResponse<String> httpResponse;
        try {
            httpResponse = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException | IOException exc) {
            //TODO determine if ssl error
            burp.logger.error("HttpGet failed: "+exc.getMessage());
            throw new AWSCredentialProviderException("Failed to send GET request to "+requestUrl);
        }

        if (httpResponse.statusCode() != 200)
            throw new AWSCredentialProviderException(String.format("GET request returned error: %d %s", httpResponse.statusCode(), requestUrl));

        // expect similar object to sts:AssumeRole
        JsonObject credentialObject = new Gson().fromJson(httpResponse.body(), JsonObject.class);

        try {
            if (credentialObject.has("SessionToken")) {
                credential = new AWSTemporaryCredential(
                        credentialObject.get("AccessKeyId").getAsString(),
                        credentialObject.get("SecretAccessKey").getAsString(),
                        credentialObject.get("SessionToken").getAsString(),
                        credentialObject.get("Expiration").getAsLong());
            } else {
                credential = new AWSPermanentCredential(
                        credentialObject.get("AccessKeyId").getAsString(),
                        credentialObject.get("SecretAccessKey").getAsString());
            }
        } catch (NullPointerException exc) {
            throw new AWSCredentialProviderException("Failed to parse HttpProvider response");
        }
    }

    @Override
    public AWSCredential getCredential() throws AWSCredentialProviderException
    {
        if (credential == null) {
            renewCredential();
        }
        else {
            if (credential.isTemporary()) {
                final long duration = ((AWSTemporaryCredential)credential).secondsToExpire();
                if (duration <= 30) {
                    // fewer than 30 seconds until expiration, refresh
                    renewCredential();
                }
            }
            else {
                // always refresh permanent credentials. seems counter-intuitive but if the user
                // isn't just using a static provider there must be a reason
                renewCredential();
            }
        }
        if (credential == null) {
            throw new AWSCredentialProviderException("Failed to get credential from "+requestUrl);
        }
        return credential;
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public String getClassName() { return getClass().getName();}

}
