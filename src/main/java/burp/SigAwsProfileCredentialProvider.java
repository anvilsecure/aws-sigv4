package burp;

import burp.error.SigCredentialProviderException;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.profiles.ProfileFileSupplier;

import java.time.Instant;
import java.util.List;

public class SigAwsProfileCredentialProvider implements SigCredentialProvider {

    public static final String PROVIDER_NAME = "AwsProfile";
    protected static LogWriter logger = LogWriter.getLogger();
    private transient long expirationInEpochSeconds = 0;
    private transient SigCredential latestCredential = null;
    private String profileName;

    private SigAwsProfileCredentialProvider() { };

    public SigAwsProfileCredentialProvider(final String profileName) {
        if (profileName == null || profileName.equals("")) {
            throw new IllegalArgumentException("Profile name must not be empty");
        }
        this.profileName = profileName;
    };

    public String getProfileName() {
        return profileName;
    }

    private boolean isCredentialExpired() {
        // check if the creds will be expired in the next 5 seconds
        if (expirationInEpochSeconds < (Instant.now().getEpochSecond() + 5)) {
            return true;
        }
        if (latestCredential == null) {
            return true;
        }
        return false;
    }

    @Override
    synchronized public SigCredential getCredential() throws SigCredentialProviderException {
        if (!isCredentialExpired()) {
            return latestCredential;
        }
        logger.debug(String.format("Refreshing credentials: profile=%s, expired=%d, now=%d", profileName, expirationInEpochSeconds, Instant.now().getEpochSecond()));

        AwsCredentials credential;
        try (var profileCredentialsProvider = ProfileCredentialsProvider.builder().profileFile(ProfileFileSupplier.defaultSupplier()).profileName(profileName).build()) {
            credential = profileCredentialsProvider.resolveCredentials();
        } catch (Exception exc) {
            var cause = exc.getCause();
            String msg = exc.getMessage();
            if (cause != null) {
                msg += ": "+cause.getMessage();
            }
            throw new SigCredentialProviderException(msg);
        }
        try {
            if (credential instanceof AwsBasicCredentials) {
                // Check AWS credential file every 60 seconds. Even though they are static creds, there may be a process periodically updating
                // the credential file.
                expirationInEpochSeconds = Instant.now().getEpochSecond() + 60;
                latestCredential = new SigStaticCredential(credential.accessKeyId(), credential.secretAccessKey());
                return latestCredential;
            } else if (credential instanceof AwsSessionCredentials session) {
                long expiration = Instant.now().getEpochSecond() + 60;
                if (session.expirationTime().isPresent()) {
                    expiration = session.expirationTime().get().getEpochSecond();
                }
                expirationInEpochSeconds = expiration;
                logger.debug("Refreshed credentials with expiry of "+expiration);
                latestCredential = new SigTemporaryCredential(session.accessKeyId(), session.secretAccessKey(), session.sessionToken(), expiration);
                return latestCredential;
            }
        } catch (IllegalArgumentException exc) {
            throw new SigCredentialProviderException(exc.getMessage());
        }
        throw new SigCredentialProviderException("Encountered unknown credential type for profile: "+profileName);
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    public static List<String> getAvailableProfileNames() {
        return ProfileFileSupplier.defaultSupplier().get().profiles().keySet().stream().sorted().toList();
    }
}
