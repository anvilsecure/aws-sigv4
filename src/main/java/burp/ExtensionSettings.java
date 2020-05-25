package burp;

import com.google.gson.annotations.Since;
import lombok.*;
import lombok.experimental.Accessors;

import java.util.List;
import java.util.Map;

@Builder
@Accessors(fluent=true)
@Value
@AllArgsConstructor
@NoArgsConstructor
public class ExtensionSettings {

    // use this field to track settings version. when adding a new setting, bump this value
    // and annotate the new setting with @Since(NEW_VERSION). when the extension loads an
    // old settings file, it will just use the defaults for new settings.
    @Setter(AccessLevel.NONE)
    double settingsVersion = 0.0;

    @Since(0)
    @Builder.Default
    int logLevel = LogWriter.DEFAULT_LEVEL;

    @Since(0)
    @Builder.Default
    String extensionVersion = "0.0.0";

    @Since(0)
    @Builder.Default
    boolean persistProfiles = false;

    @Since(0)
    @Builder.Default
    boolean extensionEnabled = true;

    @Since(0)
    @Builder.Default
    String defaultProfileName = null;

    @Since(0)
    @Builder.Default
    List<String> customSignedHeaders = List.of();

    @Since(0)
    @Builder.Default
    boolean customSignedHeadersOverwrite = false;

    @Since(0)
    @Builder.Default
    List<String> additionalSignedHeaderNames = List.of();

    @Since(0)
    @Builder.Default
    boolean inScopeOnly = false;

    @Since(0)
    @Builder.Default
    boolean preserveHeaderOrder = true;

    @Since(0)
    @Builder.Default
    long presignedUrlLifetimeInSeconds = 900;

    @Since(0)
    @Builder.Default
    String contentMD5HeaderBehavior = "ignore";

    @Since(0)
    @Builder.Default
    Map<String, SigProfile> profiles = Map.of();

    @Since(0)
    @Builder.Default
    boolean signingEnabledForProxy = true;

    @Since(0)
    @Builder.Default
    boolean signingEnabledForSpider = true;

    @Since(0)
    @Builder.Default
    boolean signingEnabledForScanner = true;

    @Since(0)
    @Builder.Default
    boolean signingEnabledForIntruder = true;

    @Since(0)
    @Builder.Default
    boolean signingEnabledForRepeater = true;

    @Since(0)
    @Builder.Default
    boolean signingEnabledForSequencer = true;

    @Since(0)
    @Builder.Default
    boolean signingEnabledForExtender = true;
}
