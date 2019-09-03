package burp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/*
This class computes the SigV4 for AWS requests using SHA256.

See documentation here: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
*/
public class AWSSignedRequest
{
    // set of headers to remove and update
    private HashSet<String> updateHeaderSet = new HashSet<>(Arrays.asList(
            "x-amz-credential", "x-amz-date", "x-amz-algorithm", "x-amz-expires", "x-amz-signedheaders", "x-amz-signature", "x-amz-content-sha256", "x-amz-security-token"
    ));

    private final String algorithm = "AWS4-HMAC-SHA256"; // we only compute the SHA256
    private int queryExpirationSeconds = 60; // lifetime of a signed url in seconds
    private String accessKeyId = "";
    private String region = "";
    private String service = "";
    private Set<String> signedHeaderSet; // headers to sign
    private LogWriter logger;
    private IExtensionHelpers helpers;
    private IRequestInfo request;
    private byte[] requestBytes;
    private IHttpService httpService;
    private String amzDate; // UTC date string for X-Amz-Date header
    private String amzDateYMD;
    private boolean signatureInHeaders = false;

    // regex for the "Credential" parameter in the "Authorization" header or the "X-Amz-Credential" query string param
    private static Pattern credentialRegex = Pattern.compile("^Credential=[a-z0-9]{1,64}/[0-9]{8}/[a-z0-9-]{0,64}/[a-z0-9-]{0,64}/aws4_request,?$",
            Pattern.CASE_INSENSITIVE);
    private static Pattern credentialValueRegex = Pattern.compile("^[a-z0-9]{1,64}/[0-9]{8}/[a-z0-9-]{0,64}/[a-z0-9-]{0,64}/aws4_request,?$",
            Pattern.CASE_INSENSITIVE);

    // service names used in credential parameter and ARNs
    private static final String SERVICE_NAME_S3 = "s3";
    private static final String SERVICE_NAME_SAR = "serverlessrepo";

    @Override
    public String toString()
    {
        return String.format("AWSSignedRequest\n.accessKeyId = %s\n.region = %s\n.service = %s\n.amzDate = %s\n.amzDateYMD = %s\n",
                this.accessKeyId, this.region, this.service, this.amzDate, this.amzDateYMD);
    }

    private void init(byte[] requestBytes)
    {
        this.requestBytes = requestBytes;
        this.request = helpers.analyzeRequest(this.httpService, requestBytes);
        this.signedHeaderSet = new HashSet<String>();
        // make sure required host and date headers are part of signature.
        // TODO: for http/2, we need authority header
        this.signedHeaderSet.add("host");
        // requests require either one of these date headers.
        this.signedHeaderSet.add("x-amz-date");
        this.signedHeaderSet.add("date");

        // make sure host header is present
        boolean hasHostHeader = false;
        for (String header : this.request.getHeaders()) {
            if (header.toLowerCase().startsWith("host:")) {
                hasHostHeader = true;
                break;
            }
        }
        if (!hasHostHeader) {
            List<String> headers = this.request.getHeaders();
            headers.add("Host: "+this.httpService.getHost());
            this.requestBytes = this.helpers.buildHttpMessage(headers, getPayloadBytes());
            this.request = helpers.analyzeRequest(this.httpService, this.requestBytes);
        }

        // attempt to parse header and query string for all requests. we only expect to see the query string
        // parameters with GET requests but this will be robust
        signatureInHeaders = !parseAuthorizationQueryString();
        parseAuthorizationHeader();
    }

    public AWSSignedRequest(IHttpService httpService, byte[] requestBytes, IExtensionHelpers helpers, LogWriter logger)
    {
        this.helpers = helpers;
        this.logger = logger;
        this.httpService = httpService;
        init(requestBytes);
    }

    public AWSSignedRequest(IHttpRequestResponse messageInfo, IExtensionHelpers helpers, LogWriter logger)
    {
        this.helpers = helpers;
        this.logger = logger;
        this.httpService = messageInfo.getHttpService();
        init(messageInfo.getRequest());
    }

    public void setRegion(String region) { this.region = region; }

    public String getRegion() { return this.region; }

    public void setService(String service) { this.service = service; }

    public String getService() { return this.service; }

    public void setAccessKeyId(String accessKeyId) { this.accessKeyId = accessKeyId; }

    public String getAccessKeyId() { return this.accessKeyId; }

    /*
    check service to determine if this is an s3 request. s3 requests must be handled differently.
     */
    public boolean isS3Request()
    {
        return this.service.toLowerCase().equals(SERVICE_NAME_S3);
    }

    /*
    Update request params from an instance of AWSProfile. This allows requests to be signed with
    credentials that differ from the original request.
    */
    public void applyProfile(final AWSProfile profile)
    {
        if (!profile.service.equals("")) {
            this.setService(profile.service);
        }
        if (!profile.region.equals("")) {
            this.setRegion(profile.region);
        }
        // this is a NOP unless using a default profile
        this.setAccessKeyId(profile.accessKeyId);
    }

    public AWSProfile getAnonymousProfile()
    {
        return new AWSProfile("", this.accessKeyId, "", this.region, this.service);
    }

    public static AWSSignedRequest fromUnsignedRequest(final IHttpRequestResponse messageInfo, final AWSProfile profile, IExtensionHelpers helpers, LogWriter logger)
    {
        AWSSignedRequest signedRequest = new AWSSignedRequest(messageInfo, helpers, logger);
        signedRequest.applyProfile(profile);
        // XXX if we call init() here and the original request has a signature, the key in profile is overridden.
        // there was a reason for calling init() here but not sure if its still necessary
        //signedRequest.init(signedRequest.requestBytes);
        return signedRequest;
    }

    /*
    return array of {name, value} with leading and trailing whitespace removed
     */
    private String[] splitHttpHeader(final String header)
    {
        String[] tokens = header.trim().split("[\\s:]+", 2);
        if (tokens.length < 2) {
            return new String[]{tokens[0], ""};
        }
        return new String[]{tokens[0], tokens[1]};
    }

    /*
    Get authorization information from the query string in the url.
    */
    private boolean parseAuthorizationQueryString()
    {
        boolean sigInQueryString = false;
        for (final IParameter param : this.request.getParameters()) {
            final String name = helpers.urlDecode(param.getName());
            final String value = helpers.urlDecode(param.getValue());
            if (name.toLowerCase().equals("x-amz-credential")) {
                // extract fields from Credential parameter
                Matcher m = credentialValueRegex.matcher(value);
                if (!m.matches()) {
                    logger.error("Invalid Credential parameter in Authorization query passed to AWSSignedRequest");
                    return false;
                }
                final String[] creds = value.split("/");
                this.accessKeyId = creds[0];
                this.amzDateYMD = creds[1];
                this.region = creds[2];
                this.service = creds[3];
                sigInQueryString = true;
            }
            else if (name.toLowerCase().equals("x-amz-signedheaders")) {
                for (String header : value.split("[\\s;]+")) {
                    this.signedHeaderSet.add(header.toLowerCase());
                }
            }
            else if (name.toLowerCase().equals("x-amz-date")) {
                this.amzDate = value;
            }
            else if (name.toLowerCase().equals("x-amz-expires")) {
                try {
                    this.queryExpirationSeconds = Integer.parseInt(value);
                } catch (NumberFormatException exc) {
                    this.queryExpirationSeconds = 60; // 1 minute
                }
            }
        }
        return sigInQueryString;
    }

    /*
    parse required fields from "Authorization" header. this includes region, service name, and access key id.
    */
    private boolean parseAuthorizationHeader()
    {
        String authHeader = null;
        for (final String header : this.request.getHeaders()) {
            if (header.toLowerCase().startsWith("authorization:")) {
                authHeader = header;
            }
            else if (header.toLowerCase().startsWith("x-amz-date:")) {
                this.amzDate = splitHttpHeader(header)[1];
            }
        }

        if (authHeader == null) {
            return false;
        }

        // verify that we have a valid authorization header for AWS
        final String[] tokens = authHeader.trim().split("[\\s,]+");

        for (int i = 2; i < tokens.length; i++) {
            if (tokens[i].toLowerCase().startsWith("credential=")) {
                // extract fields from Credential parameter
                Matcher m = credentialRegex.matcher(tokens[i]);
                if (!m.matches()) {
                    logger.error("Credential parameter in authorization header is invalid.");
                    return false;
                }
                final String[] creds = tokens[2].split("/");
                this.accessKeyId = creds[0].substring(11); // skip "Credential="
                this.amzDateYMD = creds[1];
                this.region = creds[2];
                this.service = creds[3];
            }
            else if (tokens[i].toLowerCase().startsWith("signedheaders=")) {
                for (String header : tokens[i].substring(14).split("[\\s;]+")) {
                    this.signedHeaderSet.add(header.toLowerCase());
                }
            }
        }
        return true;
    }

    /*
    Update member amzDate to current UTC time. this should be called prior to signing the request
    */
    private void updateAmzDate()
    {
        final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        this.amzDate = dateFormat.format(new Date()); // full date and time for signing
        this.amzDateYMD = this.amzDate.substring(0, 8); // date for credential param
    }

    /*
    use this method to add additional signed headers.
    */
    public void addSignedHeaders(final List<String> newHeaders, final boolean overwriteDupes)
    {
        if (newHeaders.size() > 0) {
            List<String> finalHeaders = new ArrayList<>();
            List<String> originalHeaders = this.request.getHeaders();
            if (overwriteDupes) {
                Map<String, String> newHeadersMap = new HashMap<>();
                for (String header : newHeaders) {
                    final String[] h = splitHttpHeader(header);
                    newHeadersMap.put(h[0], header);
                }

                // build set of existing header names
                Set<String> headerNameSet = new HashSet<>();
                finalHeaders.add(originalHeaders.remove(0)); // get path, method

                // handle name conflicts between old and new headers
                for (final String header : originalHeaders) {
                    final String[] h = splitHttpHeader(header);
                    headerNameSet.add(h[0]);
                    if (newHeadersMap.containsKey(h[0])) {
                        // ignore original header in favor of new value
                        logger.debug("Adding custom header: " + h[0]);
                        finalHeaders.add(newHeadersMap.get(h[0]));
                    }
                    else {
                        finalHeaders.add(header);
                    }
                }
                // now handle newHeaders that were not in original header list
                for (final String header : newHeaders) {
                    if (!headerNameSet.contains(splitHttpHeader(header)[0])) {
                        finalHeaders.add(header);
                    }
                }
            }
            else {
                // allow dupes
                finalHeaders.addAll(originalHeaders);
                finalHeaders.addAll(newHeaders);
            }
            for (final String header : newHeaders) {
                this.signedHeaderSet.add(splitHttpHeader(header)[0].toLowerCase());
            }
            this.requestBytes = this.helpers.buildHttpMessage(finalHeaders, getPayloadBytes());
            this.request = helpers.analyzeRequest(this.httpService, this.requestBytes);
        }
    }

    /* add names of headers to sign. this can be used to sign additional headers from
    the original request
    */
    public void addSignedHeaderNames(List<String> headerNames)
    {
        for (final String name : headerNames) {
            this.signedHeaderSet.add(name.toLowerCase());
        }
    }

    private String getCanonicalQueryString()
    {
        // check for empty query
        final String queryString = this.request.getUrl().getQuery();
        if (queryString == null || queryString.equals("")) {
            return "";
        }

        // sort query string parameters by name/value
        ArrayList<IParameter> sortedParameters = new ArrayList<>();
        for (final String param : queryString.split("&")) {
            final String[] tokens = param.split("=", 2);
            if (tokens[0].toLowerCase().equals("x-amz-signature")) {
                continue;
            }
            if (tokens.length == 1) {
                sortedParameters.add(helpers.buildParameter(tokens[0], "", IParameter.PARAM_URL));
            }
            else if (tokens.length >= 2) {
                sortedParameters.add(helpers.buildParameter(tokens[0], tokens[1], IParameter.PARAM_URL));
            }
        }
        // sort params by name. sort by value if names match.
        Comparator comparator = new Comparator<IParameter>()
        {
            public int compare(IParameter param1, IParameter param2)
            {
                if (param1.getName().equals(param2.getName())) {
                    return param1.getValue().compareTo(param2.getValue());
                }
                return param1.getName().compareTo(param2.getName());
            }
        };
        Collections.sort(sortedParameters, comparator);
        String canonicalQueryString = "";
        for (final IParameter param : sortedParameters) {
            if (canonicalQueryString.length() > 0) {
                canonicalQueryString += "&";
            }
            canonicalQueryString += String.format("%s=%s",
                    param.getName().replace("/", "%2F"),
                    param.getValue().replace("/", "%2F"));
        }
        return canonicalQueryString;
    }

    private String getCanonicalUri()
    {
        String uri = this.request.getUrl().getPath();
        if (!isS3Request()) {
            // for services other than s3 the URI must be normalized by removing relative elements and duplicate path separators
            uri = uri.replaceAll("[/]{2,}", "/");

            // checks for other non-s3 services
            if (this.service.toLowerCase().equals(SERVICE_NAME_SAR)) {
                // need to double url encode
                uri = this.helpers.urlEncode(uri);
            }
        }
        if (uri.equals("")) {
            uri = "/";
        }
        return uri;
    }

    private String getCanonicalHeaders()
    {
        // need at least Host header for HTTP/1.1 and authority header for http/2
        ArrayList<String> signedHeaderArray = new ArrayList<>();
        HashMap<String, String> signedHeaderMap = new HashMap<>();
        for (final String header : this.request.getHeaders()) {
            String[] kv = splitHttpHeader(header);
            final String nameLower = kv[0].trim().toLowerCase();
            String value = kv[1].trim().replaceAll("[ ]{2,}", " "); // shrink whitespace
            if (this.signedHeaderSet.contains(kv[0].toLowerCase())) {
                if (nameLower.equals("x-amz-date")) {
                    // make sure to use current date
                    value = this.amzDate;
                }
                else if (nameLower.equals("x-amz-content-sha256")) {
                    if (isS3Request()) {
                        value = getPayloadHash();
                    }
                }
                else if (nameLower.equals("content-md5")) {
                    value = getContentMD5();
                }

                if (signedHeaderMap.containsKey(nameLower)) {
                    // duplicate headers have values comma-separated in the order that they appear
                    value = signedHeaderMap.get(nameLower) + "," + value;
                }
                else {
                    signedHeaderArray.add(nameLower);
                }
                signedHeaderMap.put(nameLower, value);
            }
        }
        Collections.sort(signedHeaderArray);
        String canonicalHeaders = "";
        for (final String nameLower : signedHeaderArray) {
            canonicalHeaders += String.format("%s:%s\n", nameLower, signedHeaderMap.get(nameLower));
        }
        return canonicalHeaders;
    }

    /*
    Create the signed headers string for use in the signature and either the X-Amz-SignedHeaders or Authorization header.
    Only headers that exist will be included.
    */
    private String getCanonicalSignedHeaders()
    {
        // build list of headers to sign, then sort them.
        Set<String> validSignedHeaderSet = new HashSet<>();
        for (final String header : this.request.getHeaders()) {
            final String nameLower = splitHttpHeader(header)[0].toLowerCase();
            if (this.signedHeaderSet.contains(nameLower)) {
                validSignedHeaderSet.add(nameLower);
            }
        }
        List<String> signedHeaderList = new ArrayList<>(validSignedHeaderSet);
        Collections.sort(signedHeaderList);
        return String.join(";", signedHeaderList);
    }

    private byte[] getPayloadBytes()
    {
        if (getPayloadSize() > 0) {
            return Arrays.copyOfRange(this.requestBytes, this.request.getBodyOffset(), this.requestBytes.length);
        }
        return new byte[]{};
    }

    private int getPayloadSize()
    {
        if (this.request.getBodyOffset() < this.requestBytes.length) {
            return this.requestBytes.length - this.request.getBodyOffset();
        }
        return 0;
    }

    private String getHttpHeaderValue(final String name)
    {
        for (final String header : this.request.getHeaders()) {
            if (header.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                return splitHttpHeader(header)[1];
            }
        }
        return null;
    }

    /*
    get hash suitable for Content-MD5 http header. result will be base64 encoded digest.
    */
    private String getContentMD5()
    {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException exc) {
            return null;
        }
        return this.helpers.base64Encode(digest.digest(getPayloadBytes()));
    }

    /*
    get payload hash used in signature and X-Amz-Content-SHA256 header
     */
    private String getPayloadHash()
    {
        // s3 payload signing is optional. The string "UNSIGNED-PAYLOAD" is used to signify no payload signing.
        // if there is no payload (eg GET request) then return "UNSIGNED-PAYLOAD".
        // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        if (isS3Request()) {
            if (this.request.getMethod().toUpperCase().equals("GET")) {
                return "UNSIGNED-PAYLOAD";
            }
            // check if original request is unsigned
            final String value = getHttpHeaderValue("x-amz-content-sha256");
            if ((value == null) || (value != null && value.equals("UNSIGNED-PAYLOAD"))) {
                return "UNSIGNED-PAYLOAD";
            }
        }
        // hash payload (POST body)
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exc) {
            return null;
        }

        // if request has a body, hash it. if no body, use hash of empty string
        return DatatypeConverter.printHexBinary(digest.digest(getPayloadBytes())).toLowerCase();
    }

    private String getHashedCanonicalRequest()
    {
        final String canonicalRequest = String.join("\n",
                this.request.getMethod().toUpperCase(),
                getCanonicalUri(),
                getCanonicalQueryString(),
                getCanonicalHeaders(),
                getCanonicalSignedHeaders(),
                getPayloadHash());

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exc) {
            return null;
        }

        logger.debug("\n===========BEGIN CANONICAL REQUEST==========\n" + canonicalRequest + "\n===========END CANONICAL REQUEST============");
        return DatatypeConverter.printHexBinary(digest.digest(canonicalRequest.getBytes())).toLowerCase();
    }


    private byte[] stringToBytes(String s)
    {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /* compute a SHA256 HMAC */
    private byte[] getHmac(byte[] key, byte[] data)
    {
        try {
            Mac sha256_hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            sha256_hmac.init(keySpec);
            return sha256_hmac.doFinal(data);
        } catch (NoSuchAlgorithmException exc) {
        } catch (InvalidKeyException exc) {
        }
        return null;
    }

    /*
    string to sign does not include the accessKeyId. the Authorization header and X-Amz-Credential parameter must include the id
    */
    private String getCredentialScope(boolean withAccessKeyId)
    {
        if (withAccessKeyId) {
            return String.format("%s/%s/%s/%s/aws4_request", this.accessKeyId, this.amzDateYMD, this.region, this.service);
        }
        return String.format("%s/%s/%s/aws4_request", this.amzDateYMD, this.region, this.service);
    }

    private String getSignature(final String secretKey)
    {
        final String toSign = String.join("\n",
                this.algorithm.toUpperCase(),
                this.amzDate,
                getCredentialScope(false),
                getHashedCanonicalRequest());

        logger.debug("\n===========BEGIN STRING TO SIGN=============\n" + toSign + "\n===========END STRING TO SIGN===============");

        final byte[] kDate = getHmac(stringToBytes("AWS4" + secretKey), stringToBytes(this.amzDateYMD));
        final byte[] kRegion = getHmac(kDate, stringToBytes(this.region));
        final byte[] kService = getHmac(kRegion, stringToBytes(this.service));
        final byte[] kSigning = getHmac(kService, stringToBytes("aws4_request"));
        return DatatypeConverter.printHexBinary(getHmac(kSigning, stringToBytes(toSign))).toLowerCase();
    }

    // get the Authorization header for the request. this contains the signature using current timestamp
    private String getAuthorizationHeader(final String secretKey)
    {
        final String signature = getSignature(secretKey);
        return String.format("Authorization: %s Credential=%s, SignedHeaders=%s, Signature=%s",
                this.algorithm, getCredentialScope(true), getCanonicalSignedHeaders(), signature);
    }

    /*
    update URL parameters for signed GET requests
    For query string params: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
    */
    private boolean updateQueryString(final AWSCredentials credentials, final int expires)
    {
        // NOTE: updateParameter is case sensitive so we remove after a lowercase name compare then re-add with proper case.
        for (IParameter param : this.request.getParameters()) {
            final String nameLower = helpers.urlDecode(param.getName()).toLowerCase();
            if (this.updateHeaderSet.contains(nameLower)) {
                this.requestBytes = helpers.removeParameter(this.requestBytes, param);
                if (nameLower.equals("x-amz-content-sha256") && isS3Request()) {
                    // only update this one if it was in the original request. all other params are required.
                    this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Content-SHA256", getPayloadHash(), IParameter.PARAM_URL));
                }
            }
        }

        this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Credential", getCredentialScope(true), IParameter.PARAM_URL));
        this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Date", this.amzDate, IParameter.PARAM_URL));
        this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Algorithm", this.algorithm, IParameter.PARAM_URL));
        this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Expires", Integer.toString(expires), IParameter.PARAM_URL));

        // NOTE: whether or not this is part of the signature may be service dependent
        if (credentials.getSessionToken() != null) {
            this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Security-Token", credentials.getSessionToken(), IParameter.PARAM_URL));
        }

        // save signed headers and signature for last, after all other params have been updated.
        this.request = helpers.analyzeRequest(this.httpService, this.requestBytes);
        this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-SignedHeaders", getCanonicalSignedHeaders().replace(";", "%3B"), IParameter.PARAM_URL));
        this.request = helpers.analyzeRequest(this.httpService, this.requestBytes);
        this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Signature", getSignature(credentials.getSecretKey()), IParameter.PARAM_URL));

        // update request object since we modified the parameters
        this.request = helpers.analyzeRequest(this.httpService, this.requestBytes);
        return true;
    }

    private boolean updateQueryString(final AWSCredentials credentials)
    {
        return updateQueryString(credentials, this.queryExpirationSeconds);
    }

    public String getSignedUrl(final AWSCredentials credentials, final int expires)
    {
        updateAmzDate();
        // sign just the host header since we can't control which headers are sent when this
        // url is pasted into the browser.
        HashSet<String> headerSet = new HashSet<>(this.signedHeaderSet);
        this.signedHeaderSet = new HashSet<>(Arrays.asList("host"));
        String url = "";
        if (updateQueryString(credentials, expires)) {
            url = this.request.getUrl().toString();
        }
        this.signedHeaderSet = headerSet;
        return url;
    }

    public byte[] getSignedRequestBytes(final AWSCredentials credentials)
    {
        // update timestamp before signing. will be good for 15 minutes
        updateAmzDate();

        // set this in case we are using temporary credentials and the id changed
        setAccessKeyId(credentials.getAccessKeyId());

        // attempt to keep signature in original location (url or headers). if there is a mix of signature
        // params in headers and the query string, this will likely break
        if (this.signatureInHeaders) {
            // update headers and preserve order. replace authorization header with new signature.
            List<String> headers = this.request.getHeaders();
            final String newAmzDateHeader = "X-Amz-Date: " + this.amzDate;
            final String newSha256Header = "X-Amz-Content-SHA256: " + getPayloadHash();
            boolean dateUpdated = false;
            boolean sha256Updated = false;
            boolean sessionTokenUpdated = false;
            for (int i = 0; i < headers.size(); i++) {
                final String nameLower = headers.get(i).toLowerCase();
                if (nameLower.startsWith("x-amz-date:")) {
                    headers.set(i, newAmzDateHeader);
                    dateUpdated = true;
                }
                else if (nameLower.startsWith("x-amz-content-sha256:")) {
                    if (isS3Request()) {
                        headers.set(i, newSha256Header);
                        sha256Updated = true;
                    }
                }
                else if (nameLower.startsWith("content-md5:")) {
                    // update this header if it already exists, otherwise, don't bother adding it.
                    headers.set(i, String.format("Content-MD5: %s", getContentMD5()));
                }
                else if (nameLower.startsWith("x-amz-security-token:")) {
                    if (credentials.getSessionToken() != null) {
                        headers.set(i, String.format("X-Amz-Security-Token: %s", credentials.getSessionToken()));
                        sessionTokenUpdated = true;
                    }
                }
            }

            // if the headers didn't exist in the original request, add them here
            if (!dateUpdated) {
                headers.add(newAmzDateHeader);
            }
            if (!sha256Updated && isS3Request()) {
                headers.add(newSha256Header);
            }

            // NOTE: whether or not this is part of the signature may be service dependent
            if (!sessionTokenUpdated && credentials.getSessionToken() != null) {
                headers.add(String.format("X-Amz-Security-Token: %s", credentials.getSessionToken()));
            }

            // save Authorization header for last since it is dependent on other headers which may have changed.
            // if request was modified (header added), rebuild the message in case we ended up adding
            // a new header to sign. XXX consider storing headers and body separately until message is signed
            // so rebuilding isn't necessary?
            this.requestBytes = this.helpers.buildHttpMessage(headers, getPayloadBytes());
            this.request = helpers.analyzeRequest(this.httpService, this.requestBytes);
            headers = this.request.getHeaders();

            boolean authUpdated = false;
            final String newAuthHeader = getAuthorizationHeader(credentials.getSecretKey());
            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).toLowerCase().startsWith("authorization:")) {
                    headers.set(i, newAuthHeader);
                    authUpdated = true;
                    break;
                }
            }
            if (!authUpdated) {
                headers.add(newAuthHeader);
            }
            return this.helpers.buildHttpMessage(headers, getPayloadBytes());
        }

        // for non-POST requests, update signature in query string. this will almost always be a GET request.
        if (updateQueryString(credentials)) {
            byte[] payload = getPayloadBytes();
            return this.helpers.buildHttpMessage(this.request.getHeaders(), payload.length == 0 ? null : payload);
        }
        return null;
    }

}
