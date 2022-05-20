package burp;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSyntaxException;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

public class JSONCredentialParser {
    protected static LogWriter logger = LogWriter.getLogger();

    public static Optional<SigProfile> profileFromJSON(final String jsonText) {
        Optional<SigProfile> profile = profileFromCognitoJSON(jsonText);
        if (profile.isPresent()) {
            return profile;
        }
        return profileFromAssumeRoleJSON(jsonText);
    }

    private static long expirationTimeToEpochSeconds(final String expiry) {
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

    public static Optional<SigProfile> profileFromAssumeRoleJSON(final String jsonText) {
        try {
            JsonObject jsonObject = new Gson().fromJson(jsonText, JsonObject.class);
            SigCredential staticCredential;
            if (jsonObject.has("SessionToken")) {
                staticCredential = new SigTemporaryCredential(
                        jsonObject.get("AccessKeyId").getAsString(),
                        jsonObject.get("SecretAccessKey").getAsString(),
                        jsonObject.get("SessionToken").getAsString(),
                        expirationTimeToEpochSeconds(jsonObject.get("Expiration").getAsString()));
            } else {
                staticCredential = new SigStaticCredential(
                        jsonObject.get("AccessKeyId").getAsString(),
                        jsonObject.get("SecretAccessKey").getAsString());
            }
            SigProfile profile = new SigProfile.Builder(jsonObject.get("AccessKeyId").getAsString()).
                    withCredentialProvider(
                            new SigStaticCredentialProvider(staticCredential),
                            SigProfile.DEFAULT_STATIC_PRIORITY).
                    build();
            return Optional.of(profile);
        } catch (JsonParseException | NullPointerException | IllegalArgumentException exc) {
            logger.error("Not a valid STS JSON credentials object");
        }
        return Optional.empty();
    }

    public static Optional<SigProfile> profileFromCognitoJSON(final String jsonText) {
        // Try to parse as Cognito.
        // See https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html#API_GetCredentialsForIdentity_ResponseSyntax
        try {
            JsonObject jsonObject = new Gson().fromJson(jsonText, JsonObject.class);
            // If this is from Cognito, we may have an IdentityId to use as the profile name.
            String profileName = null;
            if (jsonObject.get("IdentityId") != null) {
                profileName = jsonObject.get("IdentityId").getAsString();
            }
            if (jsonObject.get("Credentials") != null) {
                jsonObject = jsonObject.get("Credentials").getAsJsonObject();
            }
            if (jsonObject.get("AccessKeyId") == null || jsonObject.get("SecretKey") == null) {
                logger.error("Invalid JSON credentials object. AccessKeyId and SecretKey are required.");
                return Optional.empty();
            }
            if (profileName == null) {
                profileName = jsonObject.get("AccessKeyId").getAsString();
            }
            SigCredential staticCredential;
            if (jsonObject.get("SessionToken") != null) {
                long expiration = (System.currentTimeMillis() / 1000) + 43200;
                if (jsonObject.get("Expiration") != null) {
                    try {
                        expiration = jsonObject.get("Expiration").getAsLong();
                    } catch (ClassCastException | NumberFormatException e) {
                        logger.error("Invalid Expiration. Expected an integer.");
                    }
                }
                staticCredential = new SigTemporaryCredential(
                        jsonObject.get("AccessKeyId").getAsString(),
                        jsonObject.get("SecretKey").getAsString(),
                        jsonObject.get("SessionToken").getAsString(),
                        expiration);
            } else {
                staticCredential = new SigStaticCredential(
                        jsonObject.get("AccessKeyId").getAsString(),
                        jsonObject.get("SecretKey").getAsString());
            }
            SigProfile profile = new SigProfile.Builder(profileName).
                    withCredentialProvider(
                            new SigStaticCredentialProvider(staticCredential),
                            SigProfile.DEFAULT_STATIC_PRIORITY).
                    build();
            return Optional.of(profile);
        } catch (JsonSyntaxException e) {
            logger.error("Not a valid Cognito JSON credentials object");
        }
        return Optional.empty();
    }
}
