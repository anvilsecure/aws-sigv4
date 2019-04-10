package burp;

import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class AWSProfile implements Serializable {
    public String name;
    public String accessKeyId;
    public boolean accessKeyIdAuto;
    public String secretKey;
    public String region;
    public boolean regionAuto;
    public String service;
    public boolean serviceAuto;
    public boolean isActive;

    public AWSProfile(String name, String accessKeyId, boolean accessKeyIdAuto, String secretKey, String region, boolean regionAuto,
                      String service, boolean serviceAuto, boolean isActive) {
        this.name = name;
        this.accessKeyId = accessKeyId;
        this.accessKeyIdAuto = accessKeyIdAuto;
        this.secretKey = secretKey;
        this.region = region;
        this.regionAuto = regionAuto;
        this.service = service;
        this.serviceAuto = serviceAuto;
        this.isActive = isActive;
    }

    public static ArrayList<AWSProfile> fromCredentialPath(Path path)
    {
        String profileName = null;
        HashMap<String, String> tmpProfile = new HashMap<>();
        ArrayList<AWSProfile> profileList = new ArrayList<>();
        try {
            for (Iterator<String> i = Files.lines(path).iterator(); i.hasNext(); ) {
                final String line = i.next().trim();
                if (line.startsWith("[")) {
                    profileName = line.replace("[", "").replace("]", "").trim();
                } else if (line.startsWith("aws_access_key_id")) {
                    final String access_key = line.split("=")[1].trim();
                    tmpProfile.put("aws_access_key_id", access_key);
                } else if (line.startsWith("aws_secret_access_key")) {
                    final String secret_key = line.split("=")[1].trim();
                    tmpProfile.put("aws_secret_access_key", secret_key);
                } else if (line.length() > 0) {
                    //inf.println(String.format("Unrecognized content: '%s'", line));
                }

                if (tmpProfile.size() == 2) {
                    profileList.add(new AWSProfile(
                            profileName,
                            tmpProfile.get("aws_access_key_id"),
                            true,
                            tmpProfile.get("aws_secret_access_key"),
                            "",
                            true,
                            "",
                            true,
                            true));
                    tmpProfile.clear();
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
