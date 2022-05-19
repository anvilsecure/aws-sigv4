package burp;

import com.google.gson.annotations.Since;
import lombok.*;
import lombok.experimental.Accessors;
import lombok.experimental.NonFinal;

import java.util.List;
import java.util.Map;

@Builder
@Accessors(fluent=true)
@Value
@AllArgsConstructor
@NoArgsConstructor
public class ExtensionSettings {

    // use this field to track settings version. when adding a new setting, bump this value
    // and annotate the new setting with @Since(x.y). when the extension loads an
    // old settings file, it will just use the defaults for new settings.
    public static final double SETTINGS_VERSION = 0.2;

    // ref: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
    public static final long PRESIGNED_URL_LIFETIME_MIN_SECONDS = 1;
    public static final long PRESIGNED_URL_LIFETIME_MAX_SECONDS = 604800; // 7 days
    public static final long PRESIGNED_URL_LIFETIME_DEFAULT_SECONDS = 900; // 15 minutes

    public static final String CONTENT_MD5_UPDATE = "update"; // recompute a valid md5
    public static final String CONTENT_MD5_REMOVE = "remove"; // remove the header
    public static final String CONTENT_MD5_IGNORE = "ignore"; // do nothing
    public static final String CONTENT_MD5_DEFAULT = CONTENT_MD5_IGNORE;

    // Inherit the behavior of the `x-amz-content-sha256` header in the original request.
    // If absent, do not include it in the signed request. If it is "UNSIGNED-PAYLOAD", then
    // do the same for the signed request. If it's a valid hash, compute a new hash and sign it.
    public static final String PAYLOAD_SIGNING_ALL_SERVICES = "all-services";
    // The default. Same behavior as above but only applies to S3 requests.
    public static final String PAYLOAD_SIGNING_S3ONLY = "s3-only";

    @Setter(AccessLevel.NONE)
    double settingsVersion = SETTINGS_VERSION;

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
    @NonFinal
    @With
    long presignedUrlLifetimeInSeconds = PRESIGNED_URL_LIFETIME_DEFAULT_SECONDS;

    @Since(0)
    @Builder.Default
    @NonFinal
    @With
    String contentMD5HeaderBehavior = CONTENT_MD5_IGNORE;

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

    @Since(0.1)
    @Builder.Default
    boolean addProfileComment = false;

    @Since(0.2)
    @Builder.Default
    @NonFinal
    @With
    String payloadSigningBehavior = PAYLOAD_SIGNING_S3ONLY;
}
