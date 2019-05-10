package burp;

import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/*
Class represents a credential set for AWS services. Provides functionality
to import credentials from environment vars or a credential file.
*/
public class AWSProfile implements Serializable {
    public String name;
    public String accessKeyId;
    protected String secretKey;
    public String region;
    public String service;

    public AWSProfile(String name, String accessKeyId, String secretKey, String region, String service) {
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

    @Override
    public String toString() {
        return String.format("name = '%s', aws_access_key_id = '%s', aws_secret_access_key = '%s', region = '%s', service = '%s'",
                name, accessKeyId, secretKey, region, service);
    }
}
