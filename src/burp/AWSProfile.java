package burp;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonValue;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
    private String region;
    private String service;

    private AWSAssumeRole assumeRole;

    // see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    public static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{16,128}$");
    public static final Pattern secretKeyPattern = Pattern.compile("^[a-zA-Z0-9/+]{40,128}$"); // base64 characters. not sure on length
    public static final Pattern regionPattern = Pattern.compile("^[a-zA-Z]{1,4}-[a-zA-Z]{1,16}-[0-9]{1,2}$");
    public static final Pattern roleArnPattern = Pattern.compile("^arn:aws:iam::[0-9]{12}:role/[0-9a-zA-Z+=,.@_-]{1,64}$"); // regionless
    public static final Pattern roleSessionNamePattern = Pattern.compile("^[a-zA-Z0-9+=@,.-]{2,64}$");
    public static final Pattern externalIdPattern = Pattern.compile("^[a-zA-Z0-9=@:/,._-]{2,64}$");

    public String getName() { return this.name; }
    public String getAccessKeyId() { return this.accessKeyId; }
    public AWSAssumeRole getAssumeRole()
    {
        return this.assumeRole;
    }
    public String getSecretKey() { return this.secretKey; }
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

    private void setService(final String service) { this.service = service; }
    private void setAssumeRole(final AWSAssumeRole assumeRole) { this.assumeRole = assumeRole; }

    public static class Builder {
        private AWSProfile profile;
        public Builder(final String name, final String accessKeyId, final String secretKey) {
            this.profile = new AWSProfile(name, accessKeyId, secretKey);
        }
        public Builder(final AWSProfile profile) {
            this.profile = profile.clone();
        }
        public Builder withRegion(final String region) {
            this.profile.setRegion(region);
            return this;
        }
        public Builder withService(final String service) {
            this.profile.setService(service);
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
                .withRegion(this.region)
                .withService(this.service)
                .withAssumeRole(this.assumeRole != null ? this.assumeRole.clone() : null)
                .build();
    }

    private AWSProfile(final String name, final String accessKeyId, final String secretKey)
    {
        // NOTE: validation is intentionally omitted here. this allows users to specify
        // invalid values for testing purposes.
        this.name = name;
        setAccessKeyId(accessKeyId);
        setSecretKey(secretKey);
        this.region = "";
        this.service = "";
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
                .add("region", region)
                .add("service", service)
                .add("assumeRoleObject", assumeRole != null ? assumeRole.toJsonObject() : JsonValue.NULL)
                .build();
    }

    public static AWSProfile fromJsonObject(final JsonObject obj, BurpExtender burp)
    {
        return new AWSProfile.Builder(obj.getString("name"), obj.getString("accessKeyId"), obj.getString("secretKey"))
                .withRegion(obj.getString("region"))
                .withService(obj.getString("service"))
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
                final String roleArn = profile.getOrDefault("role_arn", section.getOrDefault("role_arn", ""));
                final String roleSessionName = profile.getOrDefault("role_session_name", section.getOrDefault("role_session_name", AWSAssumeRole.ROLE_SESSION_NAME_DEFAULT));
                // TODO external_id, duration_seconds. add these in profile dialog, too?
                final int durationSeconds = Integer.parseInt(profile.getOrDefault("duration_seconds", section.getOrDefault("duration_seconds", Integer.toString(AWSAssumeRole.CREDENTIAL_LIFETIME_MIN))));
                final String externalId = profile.getOrDefault("external_id", section.getOrDefault("external_id", null));

                AWSAssumeRole assumeRole = null;
                if (roleArnPattern.matcher(roleArn).matches()) {
                    assumeRole = new AWSAssumeRole.Builder(roleArn, burp)
                            .withRoleSessionName(roleSessionName)
                            .withDurationSeconds(durationSeconds)
                            .withExternalId(externalId)
                            .build();
                }
                try {
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
    public boolean isValid()
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
        if (isValid()) {
            export += String.format("[%s]\n", this.name);
            export += String.format("aws_access_key_id = %s\n", this.accessKeyId);
            export += String.format("aws_secret_access_key = %s\n", this.secretKey);
            if (this.region != null && regionPattern.matcher(this.region).matches()) {
                export += String.format("region = %s\n", this.region);
            }
            if (this.assumeRole != null) {
                final String roleArn = this.assumeRole.getRoleArn();
                if (roleArn != null && roleArnPattern.matcher(roleArn).matches()) {
                    export += String.format("role_arn = %s\n", roleArn);

                    final String sessionName = this.assumeRole.getSessionName();
                    if (sessionName != null && roleSessionNamePattern.matcher(sessionName).matches()) {
                        export += String.format("role_session_name = %s\n", sessionName);
                    }

                    // duration must be in range [900, 43200]
                    int durationSeconds = this.assumeRole.getDurationSeconds();
                    if (durationSeconds < 900)
                        durationSeconds = 900;
                    if (durationSeconds > 43200)
                        durationSeconds = 43200;
                    export += String.format("duration_seconds = %d\n", durationSeconds);
                    final String externalId = this.assumeRole.getExternalId();
                    if (externalId != null && !externalId.equals("")) {
                        export += String.format("external_id = %s\n", externalId);
                    }
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

    public AWSCredentials getPermanentCredentials()
    {
        return new AWSCredentials(this.accessKeyId, this.secretKey);
    }

    public AWSCredentials getCredentials()
    {
        if (assumeRole != null) {
            return assumeRole.getTemporaryCredentials(getPermanentCredentials());
        }
        return getPermanentCredentials();
    }

    @Override
    public String toString() {
        return String.format("name = '%s', aws_access_key_id = '%s', aws_secret_access_key = '%s', region = '%s', service = '%s'",
                name, accessKeyId, secretKey, region, service);
    }
}
