package burp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
class for parsing aws cli config files.
see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html
 */
public class ConfigParser
{
    private static final Pattern sectionPattern = Pattern.compile("^\\s*\\[\\s*([^]]{1,256}?)\\s*\\]\\s*$");
    private static final Pattern valuePattern = Pattern.compile("^\\s*([^=]{1,256}?)\\s*=\\s*(.{1,256}?)\\s*$");

    public static Map<String, Map<String, String>> parse(final Path path)
    {
        Map<String, Map<String, String>> config = new HashMap<>();
        try {
            Map<String, String> sectionMap = null;
            for (Iterator<String> i = Files.lines(path).iterator(); i.hasNext();) {
                final String line = i.next();
                Matcher sectionMatch = sectionPattern.matcher(line);
                if (sectionMatch.matches()) {
                    final String sectionName = sectionMatch.group(1);
                    sectionMap = new HashMap<>();
                    config.put(sectionName, sectionMap);
                }
                else if (sectionMap != null) {
                    Matcher valueMatch = valuePattern.matcher(line);
                    if (valueMatch.matches()) {
                        final String key = valueMatch.group(1);
                        final String value = valueMatch.group(2);
                        sectionMap.put(key, value);
                    }
                }
            }
        } catch (IOException ignore) {
        }
        return config;
    }
}
