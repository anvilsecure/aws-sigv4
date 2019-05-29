package burp;

import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
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

    // see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
    public static final Pattern profileNamePattern = Pattern.compile("^[\\w+=,.@-]{1,64}$");
    public static final Pattern accessKeyIdPattern = Pattern.compile("^[\\w]{16,128}$");
    public static final Pattern secretKeyPattern = Pattern.compile("^[a-zA-Z0-9/+]{40,128}$"); // base64 characters. not sure on length

    public AWSProfile(String name, String accessKeyId, String secretKey, String region, String service)
    {
        this.name = name;
        this.accessKeyId = accessKeyId;
        this.secretKey = secretKey;
        this.region = region;
        this.service = service;
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

    public static ArrayList<AWSProfile> fromCredentialPath(Path path)
    {
        String profileName = "";
        HashMap<String, String> tmpProfile = new HashMap<>();
        ArrayList<AWSProfile> profileList = new ArrayList<>();
        try {
            for (Iterator<String> i = Files.lines(path).iterator(); i.hasNext(); ) {
                final String line = i.next().trim();
                if (line.startsWith("[") && line.endsWith("]")) {
                    tmpProfile.clear();
                    profileName = line.replace("[", "").replace("]", "").trim();
                }
                else if (line.startsWith("aws_access_key_id")) {
                    final String access_key = line.split("=")[1].trim();
                    tmpProfile.put("aws_access_key_id", access_key);
                }
                else if (line.startsWith("aws_secret_access_key")) {
                    final String secret_key = line.split("=")[1].trim();
                    tmpProfile.put("aws_secret_access_key", secret_key);
                }
                else if (line.length() > 0) {
                    //inf.println(String.format("Unrecognized content: '%s'", line));
                }

                if (!profileName.equals("") && tmpProfile.containsKey("aws_access_key_id") && tmpProfile.containsKey("aws_secret_access_key")) {
                    profileList.add(new AWSProfile(
                            profileName,
                            tmpProfile.get("aws_access_key_id"),
                            tmpProfile.get("aws_secret_access_key"),
                            "",
                            ""));
                    tmpProfile.clear();
                    profileName = "";
                }
            }
        } catch (IOException exc) {
        }
        return profileList;
    }

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
            export += "[" + this.name + "]\n";
            export += "aws_access_key_id = " + this.accessKeyId + "\n";
            export += "aws_secret_access_key = " + this.secretKey + "\n";
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

    @Override
    public String toString() {
        return String.format("name = '%s', aws_access_key_id = '%s', aws_secret_access_key = '%s', region = '%s', service = '%s'",
                name, accessKeyId, secretKey, region, service);
    }
}
