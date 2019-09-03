package burp;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.IOException;
import java.io.Serializable;
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
public class AWSProfile implements Serializable
{
    public String name;
    public String accessKeyId;
    protected String secretKey;
    public String region;
    public String service;

    private AWSAssumeRole assumeRole;
    private BurpExtender burp;

    // see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    public static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{16,128}$");
    public static final Pattern secretKeyPattern = Pattern.compile("^[a-zA-Z0-9/+]{40,128}$"); // base64 characters. not sure on length
    public static final Pattern regionPattern = Pattern.compile("^[a-zA-Z]{1,4}-[a-zA-Z]{1,16}-[0-9]{1,2}$");
    public static final Pattern roleArnPattern = Pattern.compile("^arn:aws:iam::[0-9]{12}:role/[0-9a-zA-Z+=,.@_-]{1,64}$"); // regionless
    public static final Pattern roleSessionNamePattern = Pattern.compile("^[a-zA-Z0-9+=@,.-]{2,64}$");

    public AWSProfile(final AWSProfile profile)
    {
        this(profile.name, profile.accessKeyId, profile.secretKey, profile.region, profile.service);
        if (profile.assumeRole != null) {
            this.assumeRole = new AWSAssumeRole(this, profile.assumeRole.getRoleArn(), profile.assumeRole.getSessionName(), AWSAssumeRole.CREDENTIAL_LIFETIME_MIN, profile.burp);
        }
    }

    public AWSProfile(String name, String accessKeyId, String secretKey, String region, String service)
    {
        // NOTE: validation is intentionally omitted here. this allows users to specify
        // invalid values for testing purposes.
        this.name = name;
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
        this.region = region;
        this.service = service;
    }

    public AWSProfile(String name, String accessKeyId, String secretKey, String region, String service, String roleArn, String roleSessionName, BurpExtender burp)
    {
        this(name, accessKeyId, secretKey, region, service);
        if (roleArn != null && !roleArn.equals("")) {
            this.assumeRole = new AWSAssumeRole(this, roleArn, roleSessionName, AWSAssumeRole.CREDENTIAL_LIFETIME_MIN, burp);
        }
    }

    public static AWSProfile fromEnvironment()
    {
        final String envAccessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
        if (envAccessKeyId != null) {
            final String envSecretKey = System.getenv("AWS_SECRET_ACCESS_KEY");
            if (envSecretKey != null) {
                return new AWSProfile("ENV", envAccessKeyId, envSecretKey, "", "");
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
                .add("roleArn", assumeRole == null ? "" : assumeRole.getRoleArn())
                .add("roleSessionName", assumeRole == null ? "" : assumeRole.getSessionName())
                .add("durationSeconds", assumeRole == null ? 0 : assumeRole.getDurationSeconds())
                .build();
    }

    public static AWSProfile fromJsonObject(final JsonObject obj, BurpExtender burp)
    {
	// TODO durationSeconds
        return new AWSProfile(
                obj.getString("name"),
                obj.getString("accessKeyId"),
                obj.getString("secretKey"),
                obj.getString("region"),
                obj.getString("service"),
                obj.getString("roleArn"),
                obj.getString("roleSessionName"),
                burp);
    }

    public AWSAssumeRole getAssumeRole()
    {
        return this.assumeRole;
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
                HashMap<String, String> profile = config.get("profile " + name);
                if (profile == null) {
                    profile = new HashMap<>();
                }
                String region = section.get("region");
                String roleArn = section.get("role_arn");
                String roleSessionName = section.get("role_session_name");
                // TODO external_id, duration_seconds. add these in profile dialog, too?
                //String durationSeconds = section.get("duration_seconds");
                if (profile != null) {
                    if (region == null) {
                        region = profile.get("region");
                    }
                    if (roleArn == null) {
                        roleArn = profile.get("role_arn");
                    }
                    if (roleSessionName == null) {
                        roleSessionName = profile.get("role_session_name");
                    }
                }
                profileList.add(new AWSProfile(
                        name,
                        section.get("aws_access_key_id"),
                        section.get("aws_secret_access_key"),
                        region == null ? "" : region,
                        "", // service
                        roleArn,
                        roleSessionName == null ? AWSAssumeRole.ROLE_SESSION_NAME_DEFAULT : roleSessionName,
                        burp));
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
                final String sessionName = this.assumeRole.getSessionName();
                int durationSeconds = this.assumeRole.getDurationSeconds();
                if (roleArn != null && roleArnPattern.matcher(roleArn).matches()) {
                    export += String.format("role_arn = %s\n", roleArn);
                    if (sessionName != null && roleSessionNamePattern.matcher(sessionName).matches()) {
                        export += String.format("role_session_name = %s\n", sessionName);
                    }
                    // duration must be in range [900, 43200]
                    if (durationSeconds < 900)
                        durationSeconds = 900;
                    if (durationSeconds > 43200)
                        durationSeconds = 43200;
                    export += String.format("duration_seconds = %d\n", durationSeconds);
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
            return assumeRole.getCredentials();
        }
        return getPermanentCredentials();
    }

    @Override
    public String toString() {
        return String.format("name = '%s', aws_access_key_id = '%s', aws_secret_access_key = '%s', region = '%s', service = '%s'",
                name, accessKeyId, secretKey, region, service);
    }
}
