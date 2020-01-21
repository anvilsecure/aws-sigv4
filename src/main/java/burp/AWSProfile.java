package burp;

import burp.error.AWSCredentialProviderException;

import javax.swing.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/*
Class represents a credential set for AWS services. Provides functionality
to import credentials from environment vars or a credential file.
*/
public class AWSProfile implements Cloneable
{
    public static final int DEFAULT_STATIC_PRIORITY = 100;
    public static final int DEFAULT_HTTP_PRIORITY = 20;
    public static final int DEFAULT_ASSUMEROLE_PRIORITY = 50;
    public static final int DISABLED_PRIORITY = -1;

    private static transient LogWriter logger = LogWriter.getLogger();

    private String name;
    private String region;
    private String service;
    // accessKeyId is used to uniquely identify this profile for signing
    private String accessKeyId;

    private HashMap<String, AWSCredentialProvider> credentialProviders;
    private HashMap<String, Integer> credentialProvidersPriority;

    // see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    public static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{16,128}$");
    public static final Pattern regionPattern = Pattern.compile("^[a-zA-Z]{1,4}-[a-zA-Z]{1,16}-[0-9]{1,2}$");
    public static final Pattern servicePattern = Pattern.compile("^[\\w_-]{1,64}$");

    public String getName() { return this.name; }
    public AWSAssumeRole getAssumeRole()
    {
        return getAssumeRoleCredentialProvider();
    }

    private AWSCredentialProvider getCredentialProviderByName(final String name) {
        return credentialProviders.getOrDefault(name, null);
    }

    public AWSStaticCredentialProvider getStaticCredentialProvider()
    {
        return (AWSStaticCredentialProvider) getCredentialProviderByName(AWSStaticCredentialProvider.PROVIDER_NAME);
    }

    public AWSAssumeRole getAssumeRoleCredentialProvider()
    {
        return (AWSAssumeRole) getCredentialProviderByName(AWSAssumeRole.PROVIDER_NAME);
    }

    public AWSHttpProvider getHttpCredentialProvider()
    {
        return (AWSHttpProvider) getCredentialProviderByName(AWSHttpProvider.PROVIDER_NAME);
    }

    public int getStaticCredentialProviderPriority()
    {
        AWSCredentialProvider provider = getStaticCredentialProvider();
        if (provider != null)
            return credentialProvidersPriority.get(provider.getName());
        return DISABLED_PRIORITY;
    }

    public int getAssumeRolePriority()
    {
        AWSCredentialProvider provider = getAssumeRoleCredentialProvider();
        if (provider != null)
            return credentialProvidersPriority.get(provider.getName());
        return DISABLED_PRIORITY;
    }

    public int getHttpCredentialProviderPriority()
    {
        AWSCredentialProvider provider = getHttpCredentialProvider();
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
            throw new IllegalArgumentException("AWSProfile name must match pattern "+profileNamePattern.pattern());
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

    private void setAccessKeyId(final String accessKeyId) {
        if (accessKeyIdPattern.matcher(accessKeyId).matches())
            this.accessKeyId = accessKeyId;
        else
            throw new IllegalArgumentException("AWSProfile accessKeyId must match pattern " + accessKeyIdPattern.pattern());
    }

    private void setCredentialProvider(final AWSCredentialProvider provider, final int priority) {
        if (provider == null) {
            throw new IllegalArgumentException("Cannot set a null credential provider");
        }
        this.credentialProviders.put(provider.getName(), provider);
        this.credentialProvidersPriority.put(provider.getName(), priority);
    }

    public static class Builder {
        private AWSProfile profile;
        public Builder(final String name) {
            this.profile = new AWSProfile(name);
        }
        public Builder(final AWSProfile profile) {
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
        public Builder withCredentialProvider(final AWSCredentialProvider provider, final int priority) {
            // should only have 1 of each type: permanent/static, assumeRole, etc
            this.profile.setCredentialProvider(provider, priority);
            return this;
        }
        public AWSProfile build() {
            return this.profile;
        }
    }

    public AWSProfile clone() {
        AWSProfile.Builder builder = new AWSProfile.Builder(this.name)
                .withRegion(this.region)
                .withService(this.service);
        for (AWSCredentialProvider provider : this.credentialProviders.values()) {
            builder.withCredentialProvider(provider, this.credentialProvidersPriority.get(provider.getName()));
        }
        return builder.build();
    }

    private AWSProfile() {};

    private AWSProfile(final String name)
    {
        setName(name);
        this.accessKeyId = null;
        this.credentialProviders = new HashMap<>();
        this.credentialProvidersPriority = new HashMap<>();
        this.region = "";
        this.service = "";
    }

    public static AWSProfile fromEnvironment()
    {
        final String envAccessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
        if (envAccessKeyId != null) {
            final String envSecretKey = System.getenv("AWS_SECRET_ACCESS_KEY");
            if (envSecretKey != null) {
                AWSProfile.Builder builder = new AWSProfile.Builder("ENV");
                builder.withAccessKeyId(envAccessKeyId);
                if (System.getenv("AWS_DEFAULT_REGION") != null) {
                    builder.withRegion(System.getenv("AWS_DEFAULT_REGION"));
                }
                final String envSessionToken = System.getenv("AWS_SESSION_TOKEN");
                if (envSessionToken == null) {
                    builder.withCredentialProvider(new AWSStaticCredentialProvider(new AWSPermanentCredential(envAccessKeyId, envSecretKey)), DEFAULT_STATIC_PRIORITY);
                }
                else {
                    builder.withCredentialProvider(new AWSStaticCredentialProvider(
                            new AWSTemporaryCredential(envAccessKeyId, envSecretKey, envSessionToken, Instant.now().getEpochSecond() + 900)), DEFAULT_STATIC_PRIORITY);
                }
                return builder.build();
            }
        }
        return null;
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
                AWSProfile.Builder newProfileBuilder = new AWSProfile.Builder(name)
                        .withAccessKeyId(section.get("aws_access_key_id"))
                        .withRegion(region)
                        .withService("");
                try {
                    final AWSPermanentCredential permanentCredential = new AWSPermanentCredential(section.get("aws_access_key_id"), section.get("aws_secret_access_key"));
                    newProfileBuilder.withCredentialProvider(new AWSStaticCredentialProvider(permanentCredential), DEFAULT_STATIC_PRIORITY);
                    final String roleArn = profile.getOrDefault("role_arn", section.getOrDefault("role_arn", null));
                    if (roleArn != null) {
                        AWSAssumeRole assumeRole = new AWSAssumeRole.Builder(roleArn, permanentCredential)
                                .tryRoleSessionName(profile.getOrDefault("role_session_name", section.getOrDefault("role_session_name", null)))
                                .withDurationSeconds(Integer.parseInt(profile.getOrDefault("duration_seconds", section.getOrDefault("duration_seconds", "0"))))
                                .tryExternalId(profile.getOrDefault("external_id", section.getOrDefault("external_id", null)))
                                .build();
                        newProfileBuilder.withCredentialProvider(assumeRole, DEFAULT_ASSUMEROLE_PRIORITY);
                    }
                    profileList.add(newProfileBuilder.build());
                } catch (IllegalArgumentException exc) {
                    burp.logger.error(String.format("Failed to import profile [%s] from path %s: %s", name, path, exc.getMessage()));
                }
            }
        }
        return profileList;
    }

    private String getExportString()
    {
        String export = "";
        AWSCredentialProvider provider = getStaticCredentialProvider();
        if (provider != null) {
            export += String.format("[%s]\n", this.name);
            try {
                export += provider.getCredential().getExportString();
            } catch (AWSCredentialProviderException exc) {
                logger.error("Failed to export credential: "+export);
                return "";
            }
            if (this.region != null && regionPattern.matcher(this.region).matches()) {
                export += String.format("region = %s\n", this.region);
            }

            AWSAssumeRole assumeRole = getAssumeRole();
            if (assumeRole != null) {
                final String roleArn = assumeRole.getRoleArn();
                if (roleArn != null) {
                    export += String.format("role_arn = %s\n", roleArn);

                    final String sessionName = assumeRole.getSessionName();
                    if (sessionName != null) {
                        export += String.format("role_session_name = %s\n", sessionName);
                    }

                    final String externalId = assumeRole.getExternalId();
                    if (externalId != null) {
                        export += String.format("external_id = %s\n", externalId);
                    }

                    export += String.format("duration_seconds = %d\n", assumeRole.getDurationSeconds());
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

    public AWSCredentialProvider getActiveProvider()
    {
        // remove providers that are disabled (priority 0) and then sort remaining to find highest priority provider
        List<AWSCredentialProvider> providerList = credentialProviders
                .values()
                .stream()
                .filter(p -> credentialProvidersPriority.get(p.getName()) >= 0)
                .collect(Collectors.toList());
        Collections.sort(providerList, (a, b) -> credentialProvidersPriority.get(a.getName()) < credentialProvidersPriority.get(b.getName()) ? -1 : 1);
        if (providerList.size() > 0) {
            return providerList.get(0);
        }
        return null;
    }

    public AWSCredential getCredential()
    {
        final AWSCredentialProvider provider = getActiveProvider();
        if (provider == null) {
            // this should never occur since a profile can't be created without a provider
            JOptionPane.showMessageDialog(BurpExtender.getBurp().getUiComponent(), "No active credential provider for profile: " + getName());
            throw new RuntimeException("No active credential provider for profile: " + getName());
        }

        try {
            return provider.getCredential();
        } catch (AWSCredentialProviderException exc) {
            logger.error("Failed to get credential: "+exc.getMessage());
            JOptionPane.showMessageDialog(BurpExtender.getBurp().getUiComponent(), exc.getMessage());
            throw new RuntimeException(exc.getMessage());
        }
    }

    @Override
    public String toString() {
        return String.format("name = '%s', keyId = '%s', region = '%s', service = '%s'", name, accessKeyId, region, service);
    }
}
