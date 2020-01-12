package burp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
class for parsing aws cli config files.
see https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html
 */
public class AWSConfigParser
{
    private Path path;
    private final Pattern sectionPattern = Pattern.compile("^\\s*\\[\\s*([^]]{1,256}?)\\s*\\]\\s*$");
    private final Pattern valuePattern = Pattern.compile("^\\s*([^=]{1,256}?)\\s*=\\s*(.{1,256}?)\\s*$");

    public AWSConfigParser(final Path path)
    {
        this.path = path;
    }

    public HashMap<String, HashMap<String, String>> parse()
    {
        HashMap<String, HashMap<String, String>> config = new HashMap<>();
        try {
            HashMap<String, String> sectionMap = null;
            for (Iterator<String> i = Files.lines(this.path).iterator(); i.hasNext();) {
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
        } catch (IOException exc) {
        }
        return config;
    }
}
