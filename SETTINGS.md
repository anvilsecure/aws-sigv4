# Extension Settings

This file describes the JSON settings for the extension. Most settings can be
configured in the UI tab, but some more advanced settings are only available by
first exporting the settings JSON, modifying the setting, then importing.  

### AdditionalSignedHeaderNames

**UI name: Signed Headers**

By default, SigV4 will include headers such as "Host", "X-Amz-Date", and others.
Any header names specified here will be added to the signature if they exist in the
original request. Note that some headers cannot be included, such as User-Agent as
the AWS SDK will ignore them. 

### CustomSignedHeaders

**UI name: Custom Signed Headers**

Specifies headers (name and value) to add to all signatures regardless of profile.

### CustomSignedHeadersOverwrite

**UI name: Overwrite existing headers**

If true, overwrite headers in the original request with the custom header of the
same name. If false, custom headers are simply appended.

### DefaultProfileName

**UI name: Default Profile**

If specified, sign all requests with the named profile. By default, the AccessKeyId
in the original request's Authorization header is matched with the unique KeyId
(or AccessKeyId if blank) of a profile. Additionally, a profile can be specified in
the header X-BurpSigV4-Profile which will take priority.

### ExtensionEnabled

**UI name: Signing Enabled**

If true, enable SigV4 signing. This is still subject to scope control settings,
such as *InScopeOnly*. If false, do not sign any outgoing requests but context
menu actions will remain.

### ExtensionVersion

The version of the AWS SigV4 plugin that generated the settings file.

### InScopeOnly

**UI name: In-scope Only**

If true, only sign requests that are defined in the project scope.

### LogLevel

**UI name: Log Level**

Set verbosity of logging to Extender logs. Debug is the most verbose.

### PersistentProfiles

**UI name: Persist Profiles**

If true, save profiles to Burp settings store. This will include any configured
credentials. Alternatively, there is some support for saving profiles by using
the "Export" button.

### PreserveHeaderOrder

If true, preserve the order of request headers after signing. This is simply for
aesthetic reasons when displaying the signed request in the message editor tab.

### PresignedUrlLifetimeInSeconds

Sets the lifetime of a presigned URL created using the "Copy Signed URL" context
menu item. See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html.

### SerializedProfileList

**UI name: AWS Credentials**

If *PersistentProfiles* is true, this contains the GSON serialized profiles.