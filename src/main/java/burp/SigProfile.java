package burp;

import burp.error.SigCredentialProviderException;
import org.apache.commons.lang3.StringUtils;
import software.amazon.awssdk.profiles.Profile;
import software.amazon.awssdk.profiles.ProfileFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
Class represents a credential set for AWS services. Provides functionality
to import credentials from environment vars or a credential file.
*/
public class SigProfile implements Cloneable
{
    public static final int DEFAULT_STATIC_PRIORITY = 100;
    public static final int DEFAULT_HTTP_PRIORITY = 20;
    public static final int DEFAULT_ASSUMEROLE_PRIORITY = 50;
    public static final int DEFAULT_AWS_PROFILE_PRIORITY = 60;
    public static final int DISABLED_PRIORITY = -1;

    private static final transient LogWriter logger = LogWriter.getLogger();

    private String name;
    private String region;
    private String service;
    // accessKeyId is used to uniquely identify this profile for signing
    private String accessKeyId;

    private HashMap<String, SigCredentialProvider> credentialProviders;
    private HashMap<String, Integer> credentialProvidersPriority;

    // see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,\\.@\\-]{1,64}$");
    public static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{16,128}$");
    public static final Pattern regionPattern = Pattern.compile("^[a-zA-Z]{1,4}-(?:gov-)?[a-zA-Z]{1,16}-[0-9]{1,2}$");
    public static final Pattern servicePattern = Pattern.compile("^[\\w_\\.\\-]{1,64}$");

    public String getName() { return this.name; }
    public SigAssumeRoleCredentialProvider getAssumeRole()
    {
        return getAssumeRoleCredentialProvider();
    }

    private SigCredentialProvider getCredentialProviderByName(final String name) {
        return credentialProviders.getOrDefault(name, null);
    }

    public SigStaticCredentialProvider getStaticCredentialProvider()
    {
        return (SigStaticCredentialProvider) getCredentialProviderByName(SigStaticCredentialProvider.PROVIDER_NAME);
    }

    public SigAssumeRoleCredentialProvider getAssumeRoleCredentialProvider()
    {
        return (SigAssumeRoleCredentialProvider) getCredentialProviderByName(SigAssumeRoleCredentialProvider.PROVIDER_NAME);
    }

    public SigHttpCredentialProvider getHttpCredentialProvider()
    {
        return (SigHttpCredentialProvider) getCredentialProviderByName(SigHttpCredentialProvider.PROVIDER_NAME);
    }

    public SigAwsProfileCredentialProvider getAwsProfileCredentialProvider()
    {
        return (SigAwsProfileCredentialProvider) getCredentialProviderByName(SigAwsProfileCredentialProvider.PROVIDER_NAME);
    }

    public int getStaticCredentialProviderPriority()
    {
        SigCredentialProvider provider = getStaticCredentialProvider();
        if (provider != null)
            return credentialProvidersPriority.get(provider.getName());
        return DISABLED_PRIORITY;
    }

    public int getAssumeRolePriority()
    {
        SigCredentialProvider provider = getAssumeRoleCredentialProvider();
        if (provider != null)
            return credentialProvidersPriority.get(provider.getName());
        return DISABLED_PRIORITY;
    }

    public int getHttpCredentialProviderPriority()
    {
        SigCredentialProvider provider = getHttpCredentialProvider();
        if (provider != null)
            return credentialProvidersPriority.get(provider.getName());
        return DISABLED_PRIORITY;
    }

    public int getAwsProfileCredentialProviderPriority()
    {
        SigCredentialProvider provider = getAwsProfileCredentialProvider();
        if (provider != null)
            return credentialProvidersPriority.get(provider.getName());
        return DISABLED_PRIORITY;
    }

    public int getCredentialProviderCount()
    {
        return this.credentialProviders.size();
    }

    public String getRegion() { return this.region; }
    public String getService() { return this.service; }

    // NOTE that this value is used for matching incoming requests only and DOES NOT represent the accessKeyId
    // used to sign the request
    public String getAccessKeyId() { return this.accessKeyId; }

    /*
    get the signature accessKeyId that should be used for selecting this profile
     */
    public String getAccessKeyIdForProfileSelection()
    {
        if (getAccessKeyId() != null) {
            return getAccessKeyId();
        }
        if (getStaticCredentialProvider() != null) {
            return getStaticCredentialProvider().getCredential().getAccessKeyId();
        }
        return null;
    }

    private void setName(final String name) {
        if (profileNamePattern.matcher(name).matches())
            this.name = name;
        else
            throw new IllegalArgumentException("Profile name must match pattern "+profileNamePattern.pattern());
    }

    private void setRegion(final String region) {
        if (region.equals("") || regionPattern.matcher(region).matches())
            this.region = region;
        else
            throw new IllegalArgumentException("Profile region must match pattern " + regionPattern.pattern());
    }

    private void setService(final String service) {
        if (service.equals("") || servicePattern.matcher(service).matches())
            this.service = service;
        else
            throw new IllegalArgumentException("Profile service must match pattern " + servicePattern.pattern());
    }

    private void setAccessKeyId(final String accessKeyId) {
        if (accessKeyIdPattern.matcher(accessKeyId).matches())
            this.accessKeyId = accessKeyId;
        else
            throw new IllegalArgumentException("Profile accessKeyId must match pattern " + accessKeyIdPattern.pattern());
    }

    private void setCredentialProvider(final SigCredentialProvider provider, final int priority) {
        if (provider == null) {
            throw new IllegalArgumentException("Cannot set a null credential provider");
        }
        this.credentialProviders.put(provider.getName(), provider);
        this.credentialProvidersPriority.put(provider.getName(), priority);
    }

    public static class Builder {
        private SigProfile profile;
        public Builder(final String name) {
            this.profile = new SigProfile(name);
        }
        public Builder(final SigProfile profile) {
            this.profile = profile.clone();
        }
        public Builder withAccessKeyId(final String accessKeyId) {
            this.profile.setAccessKeyId(accessKeyId);
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
        public Builder withCredentialProvider(final SigCredentialProvider provider, final int priority) {
            // should only have 1 of each type: permanent/static, assumeRole, etc
            this.profile.setCredentialProvider(provider, priority);
            return this;
        }
        public SigProfile build() {
            return this.profile;
        }
    }

    public SigProfile clone() {
        SigProfile.Builder builder = new SigProfile.Builder(this.name)
                .withRegion(this.region)
                .withService(this.service);
        if (StringUtils.isNotEmpty(this.accessKeyId))
            builder.withAccessKeyId(this.accessKeyId);
        for (SigCredentialProvider provider : this.credentialProviders.values()) {
            builder.withCredentialProvider(provider, this.credentialProvidersPriority.get(provider.getName()));
        }
        return builder.build();
    }

    private SigProfile() {};

    private SigProfile(final String name)
    {
        setName(name);
        this.accessKeyId = null;
        this.credentialProviders = new HashMap<>();
        this.credentialProvidersPriority = new HashMap<>();
        this.region = "";
        this.service = "";
    }

    public static String getDefaultRegion()
    {
        final String defaultRegion = System.getenv("AWS_DEFAULT_REGION");
        return (defaultRegion == null) ? "" : defaultRegion;
    }

    public static SigProfile fromEnvironment()
    {
        final String envAccessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
        if (envAccessKeyId != null) {
            final String envSecretKey = System.getenv("AWS_SECRET_ACCESS_KEY");
            if (envSecretKey != null) {
                SigProfile.Builder builder = new SigProfile.Builder("ENV")
                        .withAccessKeyId(envAccessKeyId)
                        .withRegion(getDefaultRegion());
                final String envSessionToken = System.getenv("AWS_SESSION_TOKEN");
                if (envSessionToken == null) {
                    builder.withCredentialProvider(new SigStaticCredentialProvider(new SigStaticCredential(envAccessKeyId, envSecretKey)), DEFAULT_STATIC_PRIORITY);
                }
                else {
                    builder.withCredentialProvider(new SigStaticCredentialProvider(
                            new SigTemporaryCredential(envAccessKeyId, envSecretKey, envSessionToken, Instant.now().getEpochSecond() + 900)), DEFAULT_STATIC_PRIORITY);
                }
                return builder.build();
            }
        }
        return null;
    }

    // Extract profiles from text. Format should be one environment variable per line.
    // Formatted such that it can be pasted into your shell and recognized by the AWS CLI.
    public static SigProfile fromShellVars(final String text)
    {
        final var patterns = List.of(
                Pattern.compile(".*(?<name>AWS_[A-Z_]+)[= ]\"?(?<value>\"?[a-zA-Z0-9/+]+={0,2})\"?[ ]*")
        );
        String keyId = null;
        String keySecret = null;
        String keySession = null;
        String region = null;
        for (String line : text.split("[\r\n;]+")) {
            Optional<Matcher> matcher = patterns.stream().map(p -> p.matcher(line)).filter(Matcher::matches).findFirst();
            if (matcher.isPresent()) {
                final String value = matcher.get().group("value");
                switch (matcher.get().group("name")) {
                    case "AWS_ACCESS_KEY_ID":
                        keyId = value;
                        break;
                    case "AWS_SECRET_ACCESS_KEY":
                        keySecret = value;
                        break;
                    case "AWS_SESSION_TOKEN":
                        keySession = value;
                        break;
                    case "AWS_DEFAULT_REGION":
                        region = value;
                        break;
                }
            }
        }

        if (keyId != null && keySecret != null) {
            SigCredential credential;
            if (keySession != null) {
                credential = new SigTemporaryCredential(keyId, keySecret, keySession, Instant.now().getEpochSecond() + 86400);
            } else {
                credential = new SigStaticCredential(keyId, keySecret);
            }
            SigProfile.Builder builder = new SigProfile.Builder("env-"+keyId).withAccessKeyId(keyId);
            if (region != null) {
                builder.withRegion(region);
            }
            return builder.withCredentialProvider(new SigStaticCredentialProvider(credential), DEFAULT_STATIC_PRIORITY).build();
        }
        return null;
    }

    private static Path getCliConfigPath()
    {
        Path configPath;
        final String envFile = System.getenv("AWS_CONFIG_FILE");
        if (envFile != null && Files.exists(Paths.get(envFile))) {
            configPath = Paths.get(envFile);
        }
        else {
            configPath = Paths.get(System.getProperty("user.home"), ".aws", "config");
        }
        return configPath;
    }

    public static List<SigProfile> fromCLIConfig() {
        List<SigProfile> profileList = new ArrayList<>();
        SigAwsProfileCredentialProvider.getAvailableProfileNames().forEach(name -> {
            var awsProfileOption = ProfileFile.defaultProfileFile().profile(name);
            if (awsProfileOption.isPresent()) {
                final Profile awsProfile = awsProfileOption.get();
                Builder newProfileBuilder = new Builder(name)
                        .withService("")
                        .withCredentialProvider(new SigAwsProfileCredentialProvider(name), SigProfile.DEFAULT_AWS_PROFILE_PRIORITY);
                awsProfile.property("aws_access_key_id")
                                .ifPresent(newProfileBuilder::withAccessKeyId);
                awsProfile.property("region")
                        .ifPresent(newProfileBuilder::withRegion);
                profileList.add(newProfileBuilder.build());
            }
        });
        return profileList;
    }

    // refs: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
    //       https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html
    //
    // Read profiles from an aws cli credential file. Additional properties may be read from the config
    // file where profile names must be specified with a "profile " prefix.
    public static List<SigProfile> fromCredentialPath(final Path path)
    {
        // parse credential file
        List<SigProfile> profileList = new ArrayList<>();
        Map<String, Map<String, String>> credentials = ConfigParser.parse(path);

        // get aws cli config file if it exists.
        Map<String, Map<String, String>> config = ConfigParser.parse(getCliConfigPath());

        // build profile list. settings in credentials file will take precedence over the config file.
        for (final String name : credentials.keySet()) {
            // combine profile settings from credential and config file into a single map. add credentials last
            // to overwrite duplicate settings from the config map. we want to prioritize values in the credential file
            Map<String, String> section = new HashMap<>();
            section.putAll(config.getOrDefault("profile "+name, new HashMap<>()));
            section.putAll(credentials.getOrDefault(name, new HashMap<>()));

            if ((section.containsKey("aws_access_key_id") && section.containsKey("aws_secret_access_key")) || section.containsKey("source_profile")) {
                final String region = section.getOrDefault("region", "");
                String accessKeyId = section.getOrDefault("aws_access_key_id", null);
                String secretAccessKey = section.getOrDefault("aws_secret_access_key", null);
                String sessionToken = section.getOrDefault("aws_session_token", null);

                // if source_profile exists, check that profile for creds.
                if (section.containsKey("source_profile")) {
                    final String source = section.get("source_profile");
                    Map<String, String> sourceSection = new HashMap<>();
                    sourceSection.putAll(config.getOrDefault("profile "+source, new HashMap<>()));
                    sourceSection.putAll(credentials.getOrDefault(source, new HashMap<>()));
                    if (sourceSection.containsKey("aws_access_key_id") && sourceSection.containsKey("aws_secret_access_key")) {
                        accessKeyId = sourceSection.get("aws_access_key_id");
                        secretAccessKey = sourceSection.get("aws_secret_access_key");
                        sessionToken = sourceSection.getOrDefault("aws_session_token", null);
                    }
                    else {
                        logger.error(String.format("Profile [%s] refers to source_profile [%s] which does not contain credentials.", name, source));
                        continue;
                    }
                }

                SigProfile.Builder newProfileBuilder = new SigProfile.Builder(name)
                        .withAccessKeyId(accessKeyId)
                        .withRegion(region)
                        .withService(""); // service is not specified in config files
                try {
                    SigCredential staticCredential;
                    if (sessionToken != null) {
                        staticCredential = new SigTemporaryCredential(accessKeyId, secretAccessKey, sessionToken, 0);
                    }
                    else {
                        staticCredential = new SigStaticCredential(accessKeyId, secretAccessKey);
                    }
                    newProfileBuilder.withCredentialProvider(new SigStaticCredentialProvider(staticCredential), DEFAULT_STATIC_PRIORITY);
                    final String roleArn = section.getOrDefault("role_arn", null);
                    if (roleArn != null) {
                        SigAssumeRoleCredentialProvider assumeRole = new SigAssumeRoleCredentialProvider.Builder(roleArn, staticCredential)
                                .tryRoleSessionName(section.getOrDefault("role_session_name", null))
                                .withDurationSeconds(Integer.parseInt(section.getOrDefault("duration_seconds","0")))
                                .tryExternalId(section.getOrDefault("external_id", null))
                                .build();
                        newProfileBuilder.withCredentialProvider(assumeRole, DEFAULT_ASSUMEROLE_PRIORITY);
                    }
                    profileList.add(newProfileBuilder.build());
                } catch (IllegalArgumentException exc) {
                    logger.error(String.format("Failed to import profile [%s] from path %s: %s", name, path, exc.getMessage()));
                }
            }
        }
        return profileList;
    }

    private String formatLine(final String fmt, final Object ... params) {
        return String.format(fmt + System.lineSeparator(), params);
    }

    private String getExportString()
    {
        String export = "";
        SigCredentialProvider provider = getStaticCredentialProvider();
        if (provider != null) {
            export += formatLine("[%s]", this.name);
            try {
                export += provider.getCredential().getExportString();
            } catch (SigCredentialProviderException exc) {
                logger.error("Failed to export credential: "+export);
                return "";
            }
            if (this.region != null && regionPattern.matcher(this.region).matches()) {
                export += formatLine("region = %s", this.region);
            }

            SigAssumeRoleCredentialProvider assumeRole = getAssumeRole();
            if (assumeRole != null) {
                final String roleArn = assumeRole.getRoleArn();
                if (roleArn != null) {
                    export += formatLine("role_arn = %s", roleArn);

                    final String sessionName = assumeRole.getSessionName();
                    if (sessionName != null) {
                        export += formatLine("role_session_name = %s", sessionName);
                    }

                    final String externalId = assumeRole.getExternalId();
                    if (externalId != null) {
                        export += formatLine("external_id = %s", externalId);
                    }

                    export += formatLine("duration_seconds = %d", assumeRole.getDurationSeconds());
                    // specify that creds for calling sts:AssumeRole are in the same profile
                    export += formatLine("source_profile = %s", this.name);
                }
            }
        }
        return export;
    }

    public static int exportToFilePath(final List<SigProfile> sigProfiles, final Path exportPath)
    {
        List<String> exportLines = new ArrayList<>();
        for (final SigProfile profile : sigProfiles) {
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

    public SigCredentialProvider getActiveProvider()
    {
        // remove providers that are disabled (priority -1) and then sort remaining to find highest priority provider
        return credentialProviders
                .values()
                .stream()
                .filter(p -> credentialProvidersPriority.get(p.getName()) >= 0)
                .min((a, b) -> {
                    final int ap = credentialProvidersPriority.get(a.getName());
                    final int bp = credentialProvidersPriority.get(b.getName());
                    return Integer.compare(ap, bp);
                })
                .orElse(null);
    }

    public SigCredential getCredential() throws SigCredentialProviderException
    {
        final SigCredentialProvider provider = getActiveProvider();
        if (provider == null) {
            // this should never occur since a profile can't be created without a provider
            throw new SigCredentialProviderException("No active credential provider for profile: " + getName());
        }

        return provider.getCredential();
    }

    @Override
    public String toString() {
        return String.format("name = '%s', keyId = '%s', region = '%s', service = '%s'", name, accessKeyId, region, service);
    }
}
