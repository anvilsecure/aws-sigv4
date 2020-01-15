package burp;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonValue;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

/*
Class represents a credential set for AWS services. Provides functionality
to import credentials from environment vars or a credential file.
*/
public class AWSProfile implements Cloneable
{
    private String name;
    private String accessKeyId;
    private String secretKey;
    private String sessionToken;
    private String region;
    private String service;

    private AWSAssumeRole assumeRole;
    private boolean assumeRoleEnabled;

    // see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    public static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{16,128}$");
    public static final Pattern secretKeyPattern = Pattern.compile("^[a-zA-Z0-9/+]{40,128}$"); // base64 characters. not sure on length
    //public static final Pattern sessionTokenPattern = Pattern.compile("^[a-zA-Z0-9/+]{40,512}[=]{,2}$") // not sure
    public static final Pattern regionPattern = Pattern.compile("^[a-zA-Z]{1,4}-[a-zA-Z]{1,16}-[0-9]{1,2}$");
    public static final Pattern servicePattern = Pattern.compile("^[\\w_-]{1,64}$");
    public static final Pattern roleArnPattern = Pattern.compile("^arn:aws:iam::[0-9]{12}:role/[0-9a-zA-Z+=,.@_-]{1,64}$"); // regionless
    public static final Pattern roleSessionNamePattern = Pattern.compile("^[a-zA-Z0-9+=@,._-]{2,64}$");
    public static final Pattern externalIdPattern = Pattern.compile("^[a-zA-Z0-9=@:/,._-]{2,1024}$");

    public String getName() { return this.name; }
    public String getAccessKeyId() { return this.accessKeyId; }
    public AWSAssumeRole getAssumeRole()
    {
        return this.assumeRole;
    }
    public boolean getAssumeRoleEnabled()
    {
        return this.assumeRoleEnabled;
    }
    public String getSecretKey() { return this.secretKey; }
    public String getSessionToken() { return this.sessionToken; }
    public String getRegion() { return this.region; }
    public String getService() { return this.service; }

    private void setName(final String name) {
        if (profileNamePattern.matcher(name).matches())
            this.name = name;
        else
            throw new IllegalArgumentException("AWSProfile name must match pattern "+profileNamePattern.pattern());
    }
    private void setAccessKeyId(final String accessKeyId) {
        if (accessKeyIdPattern.matcher(accessKeyId).matches())
            this.accessKeyId = accessKeyId;
        else
            throw new IllegalArgumentException("AWSProfile accessKeyId must match pattern "+accessKeyIdPattern.pattern());
    }
    private void setSecretKey(final String secretKey) {
        if (secretKeyPattern.matcher(secretKey).matches())
            this.secretKey = secretKey;
        else
            throw new IllegalArgumentException("AWSProfile secretKey must match pattern "+secretKeyPattern.pattern());
    }
    private void setRegion(final String region) {
        if (region.equals("") || regionPattern.matcher(region).matches())
            this.region = region;
        else
            throw new IllegalArgumentException("AWSProfile region must match pattern " + regionPattern.pattern());
    }

    private void setService(final String service) {
        if (service.equals("") || servicePattern.matcher(service).matches())
            this.service = service;
        else
            throw new IllegalArgumentException("AWSProfile service must match pattern " + servicePattern.pattern());
    }
    private void setAssumeRole(final AWSAssumeRole assumeRole) { this.assumeRole = assumeRole; }

    public static class Builder {
        private AWSProfile profile;
        public Builder(final String name, final String accessKeyId, final String secretKey) {
            this.profile = new AWSProfile(name, accessKeyId, secretKey);
        }
        public Builder(final AWSProfile profile) {
            this.profile = profile.clone();
        }
        public Builder withSessionToken(final String token) {
            this.profile.sessionToken = (token == null ? "" : token);
            return this;
        }
        public Builder withRegion(final String region) {
            this.profile.setRegion(region);
            return this;
        }
        public Builder withService(final String service) {
            this.profile.setService(service);
            return this;
        }
        public Builder withAssumeRoleEnabled(final boolean enabled) {
            this.profile.assumeRoleEnabled = enabled;
            return this;
        }
        public Builder withAssumeRole(final AWSAssumeRole assumeRole) {
            this.profile.setAssumeRole(assumeRole);
            return this;
        }
        public AWSProfile build() {
            return this.profile;
        }
    }

    public AWSProfile clone() {
        return new AWSProfile.Builder(this.name, this.accessKeyId, this.secretKey)
                .withSessionToken(this.sessionToken)
                .withRegion(this.region)
                .withService(this.service)
                .withAssumeRole(this.assumeRole != null ? this.assumeRole.clone() : null)
                .build();
    }

    private AWSProfile(final String name, final String accessKeyId, final String secretKey)
    {
        // NOTE: validation is intentionally omitted here. this allows users to specify
        // invalid values for testing purposes.
        setName(name);
        setAccessKeyId(accessKeyId);
        setSecretKey(secretKey);
        this.sessionToken = "";
        this.region = "";
        this.service = "";
        this.assumeRoleEnabled = false;
        this.assumeRole = null;
    }

    public static AWSProfile fromEnvironment()
    {
        final String envAccessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
        if (envAccessKeyId != null) {
            final String envSecretKey = System.getenv("AWS_SECRET_ACCESS_KEY");
            if (envSecretKey != null) {
                AWSProfile.Builder builder = new AWSProfile.Builder("ENV", envAccessKeyId, envSecretKey);
                if (System.getenv("AWS_DEFAULT_REGION") != null) {
                    builder.withRegion(System.getenv("AWS_DEFAULT_REGION"));
                }
                if (System.getenv("AWS_SESSION_TOKEN") != null) {
                    builder.withSessionToken(System.getenv("AWS_SESSION_TOKEN"));
                }
                return builder.build();
            }
        }
        return null;
    }

    public JsonObject toJsonObject()
    {
        return Json.createObjectBuilder()
                .add("name", name)
                .add("accessKeyId", accessKeyId)
                .add("secretKey", secretKey)
                .add("sessionToken", sessionToken)
                .add("region", region)
                .add("service", service)
                .add("assumeRoleEnabled", assumeRoleEnabled)
                .add("assumeRoleObject", assumeRole != null ? assumeRole.toJsonObject() : JsonValue.NULL)
                .build();
    }

    public static AWSProfile fromJsonObject(final JsonObject obj, BurpExtender burp)
    {
        return new AWSProfile.Builder(obj.getString("name"), obj.getString("accessKeyId"), obj.getString("secretKey"))
                .withSessionToken(obj.getString("sessionToken", ""))
                .withRegion(obj.getString("region"))
                .withService(obj.getString("service"))
                .withAssumeRoleEnabled(obj.getBoolean("assumeRoleEnabled", false))
                .withAssumeRole(
                        obj.get("assumeRoleObject").equals(JsonValue.NULL) ? null :
                        AWSAssumeRole.fromJsonObject(obj.getJsonObject("assumeRoleObject"), burp))
                .build();
    }

    public static ArrayList<AWSProfile> fromCredentialPath(final Path path, BurpExtender burp)
    {
        // parse credential file
        ArrayList<AWSProfile> profileList = new ArrayList<>();
        AWSConfigParser parser = new AWSConfigParser(path);
        HashMap<String, HashMap<String, String>> credentials = parser.parse();

        // get aws cli config for region info (if it exists). favor path defined in environment. fallback to default path.
        Path configPath = Paths.get(System.getProperty("user.home"), ".aws", "config");
        final String envFile = System.getenv("AWS_CONFIG_FILE");
        if (envFile != null) {
            if (Files.exists(Paths.get(envFile))) {
                configPath = Paths.get(envFile);
            }
        }
        HashMap<String, HashMap<String, String>> config = (new AWSConfigParser(configPath)).parse();

        // build profile list
        for (final String name : credentials.keySet()) {
            HashMap<String, String> section = credentials.get(name);
            if (section.containsKey("aws_access_key_id") && section.containsKey("aws_secret_access_key")) {
                HashMap<String, String> profile = config.getOrDefault("profile " + name, new HashMap<>());
                final String region = profile.getOrDefault("region", section.getOrDefault("region", ""));

                AWSAssumeRole assumeRole = null;
                try {
                    final String roleArn = profile.getOrDefault("role_arn", section.getOrDefault("role_arn", null));
                    if (roleArn != null) {
                        assumeRole = new AWSAssumeRole.Builder(roleArn, burp)
                                .tryRoleSessionName(profile.getOrDefault("role_session_name", section.getOrDefault("role_session_name", null)))
                                .withDurationSeconds(Integer.parseInt(profile.getOrDefault("duration_seconds", section.getOrDefault("duration_seconds", "0"))))
                                .tryExternalId(profile.getOrDefault("external_id", section.getOrDefault("external_id", null)))
                                .build();
                    }
                    AWSProfile newProfile = new AWSProfile.Builder(name, section.get("aws_access_key_id"), section.get("aws_secret_access_key"))
                            .withRegion(region)
                            .withService("")
                            .withAssumeRole(assumeRole)
                            .build();
                    profileList.add(newProfile);
                } catch (IllegalArgumentException exc) {
                    burp.logger.error(String.format("Failed to import profile [%s] from path %s: %s", name, path, exc.getMessage()));
                }
            }
        }
        return profileList;
    }

    /*
    minimum validation required for exporting
     */
    public boolean isExportable()
    {
        if (profileNamePattern.matcher(this.name).matches() && accessKeyIdPattern.matcher(this.accessKeyId).matches() &&
                secretKeyPattern.matcher(this.secretKey).matches()) {
            return true;
        }
        return false;
    }

    private String getExportString()
    {
        String export = "";
        if (isExportable()) {
            export += String.format("[%s]\n", this.name);
            export += String.format("aws_access_key_id = %s\n", this.accessKeyId);
            export += String.format("aws_secret_access_key = %s\n", this.secretKey);
            if (this.region != null && regionPattern.matcher(this.region).matches()) {
                export += String.format("region = %s\n", this.region);
            }

            if (this.assumeRole != null) {
                final String roleArn = this.assumeRole.getRoleArn();
                if (roleArn != null) {
                    export += String.format("role_arn = %s\n", roleArn);

                    final String sessionName = this.assumeRole.getSessionName();
                    if (sessionName != null) {
                        export += String.format("role_session_name = %s\n", sessionName);
                    }

                    final String externalId = this.assumeRole.getExternalId();
                    if (externalId != null) {
                        export += String.format("external_id = %s\n", externalId);
                    }

                    export += String.format("duration_seconds = %d\n", this.assumeRole.getDurationSeconds());
                }
            }
        }
        return export;
    }

    public static int exportToFilePath(final List<AWSProfile> awsProfiles, final Path exportPath)
    {
        List<String> exportLines = new ArrayList<>();
        for (final AWSProfile profile : awsProfiles) {
            final String export = profile.getExportString();
            if (!export.equals("")) {
                exportLines.add(export);
            }
        }
        if (exportLines.size() > 0) {
            try {
                Files.write(exportPath, exportLines, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, StandardOpenOption.CREATE);
            }
            catch (IOException exc) {
                exportLines.clear();
            }
        }
        return exportLines.size();
    }

    private AWSPermanentCredential getPermanentCredential()
    {
        return new AWSPermanentCredential(this.accessKeyId, this.secretKey);
    }

    public AWSCredential getCredential()
    {
        if (assumeRole != null && assumeRoleEnabled) {
            return assumeRole.getTemporaryCredential(getPermanentCredential());
        }
        if (sessionToken != null && !sessionToken.equals("")) {
            // we don't know the duration so put the minimum of 900
            return new AWSTemporaryCredential(accessKeyId, secretKey, sessionToken, Instant.now().getEpochSecond() + 900);
        }
        return getPermanentCredential();
    }

    @Override
    public String toString() {
        return String.format("name = '%s', aws_access_key_id = '%s', aws_secret_access_key = '%s', region = '%s', service = '%s'",
                name, accessKeyId, secretKey, region, service);
    }
}
