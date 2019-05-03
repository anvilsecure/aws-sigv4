package burp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.net.URL;
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
public class AWSSignedRequest {
    private final String algorithm = "AWS4-HMAC-SHA256"; // we only compute the SHA256
    private String accessKeyId;
    private String secretKey;
    private String region;
    private String service;
    private Set<String> signedHeaderSet; // headers to sign

    private LogWriter logger;
    private IExtensionHelpers helpers;
    private IRequestInfo request;
    private byte[] requestBytes;
    private String amzDate; // UTC date string for X-Amz-Date header
    private String amzDateYMD;
    private URL originalUrl;
    private boolean signatureInHeaders = false;

    private static Pattern credentialRegex = Pattern.compile("^Credential=[a-z0-9]{1,64}/[0-9]{8}/[a-z0-9-]{1,64}/[a-z0-9=]{1,64}/aws4_request,?$",
            Pattern.CASE_INSENSITIVE);
    private static Pattern credentialValueRegex = Pattern.compile("^[a-z0-9]{1,64}/[0-9]{8}/[a-z0-9-]{1,64}/[a-z0-9=]{1,64}/aws4_request,?$",
            Pattern.CASE_INSENSITIVE);

    @Override
    public String toString()
    {
        return String.format("AWSSignedRequest\n.accessKeyId = %s\n.region = %s\n.service = %s\n.amzDate = %s\n.amzDateYMD = %s\n",
                this.accessKeyId, this.region, this.service, this.amzDate, this.amzDateYMD);
    }

    private void init(byte[] requestBytes)
    {
        this.requestBytes = requestBytes;
        this.request = helpers.analyzeRequest(requestBytes);
        this.signedHeaderSet = new HashSet<String>();
        // make sure required host header is part of signature
        // TODO: for http/2, we need authority header
        this.signedHeaderSet.add("host");

        // attempt to parse header and query string for all requests. we only expect to see the query string
        // parameters with GET requests but this will be robust
        parseAuthorizationQueryString();
        signatureInHeaders = parseAuthorizationHeader();
    }

    public AWSSignedRequest(URL originalUrl, byte[] requestBytes, IExtensionHelpers helpers, LogWriter logger)
    {
        this.helpers = helpers;
        this.logger = logger;

        this.originalUrl = originalUrl;
        init(requestBytes);
    }

    public AWSSignedRequest(IHttpRequestResponse messageInfo, IExtensionHelpers helpers, LogWriter logger)
    {
        this.helpers = helpers;
        this.logger = logger;

        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        this.originalUrl = requestInfo.getUrl();
        init(messageInfo.getRequest());
    }

    private IRequestInfo getRequestInfo()
    {
        return helpers.analyzeRequest(this.requestBytes);
    }

    public void setRegion(String region) { this.region = region; }

    public void setService(String service) { this.service = service; }

    public void setAccessKeyId(String accessKeyId) { this.accessKeyId = accessKeyId; }

    public String getAccessKeyId() { return this.accessKeyId; }

    /*
    Update request params from an instance of AWSProfile. this allows requests to be signed with
    credentials that differ from the original request
    */
    public void applyProfile(final AWSProfile profile)
    {
        if (!profile.serviceAuto) {
            this.setService(profile.service);
        }
        if (!profile.regionAuto) {
            this.setRegion(profile.region);
        }
        // this is a NOP unless using a default profile
        this.setAccessKeyId(profile.accessKeyId);
        this.secretKey = profile.secretKey;
    }

    /*
    return array of {name, value} with leading and trailing whitespace removed
     */
    private String[] splitHttpHeader(final String header)
    {
        String[] tokens = header.trim().split("[\\s:]+", 2);
        if (tokens.length < 2) {
            return new String[] {tokens[0], ""};
        }
        return new String[] {tokens[0], tokens[1]};
    }

    /*
    Get authorization information from the query string in the url.
    */
    private boolean parseAuthorizationQueryString()
    {
        for (final IParameter param : this.request.getParameters()) {
            final String name = helpers.urlDecode(param.getName());
            final String value = helpers.urlDecode(param.getValue());
            if (name.toLowerCase().equals("x-amz-credential")) {
                // extract fields from Credential parameter
                Matcher m = credentialValueRegex.matcher(value);
                if (!m.matches()) {
                    //throw new IllegalArgumentException("Invalid Credential parameter in Authorization query passed to AWSSignedRequest");
                    return false;
                }
                String[] creds = value.split("/+");
                this.accessKeyId = creds[0];
                this.amzDateYMD = creds[1];
                this.region = creds[2];
                this.service = creds[3];
            }
            else if (name.toLowerCase().equals("x-amz-signedheaders")) {
                for (String header : value.split("[\\s;]+")) {
                    this.signedHeaderSet.add(header.toLowerCase());
                }
            }
            else if (name.toLowerCase().equals("x-amz-date")) {
                this.amzDate = value;
            }
        }
        return true;
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
        String[] tokens = authHeader.trim().split("[\\s,]+");

        for (int i = 2; i < tokens.length; i++) {
            if (tokens[i].toLowerCase().startsWith("credential=")) {
                // extract fields from Credential parameter
                Matcher m = credentialRegex.matcher(tokens[i]);
                if (!m.matches()) {
                    logger.error("Credential parameter in authorization header is invalid.");
                    return false;
                }
                String[] creds = tokens[2].split("/+");
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

    /* use this method to add additional signed headers. no attempt is made to prevent
    adding duplicate headers.
    */
    public void addSignedHeaders(final List<String> newHeaders)
    {
        if (newHeaders.size() > 0) {
            ArrayList<String> headers = (ArrayList<String>) this.request.getHeaders();
            for (final String header : newHeaders) {
                logger.debug("Adding custom signed header: "+header);
                this.signedHeaderSet.add(splitHttpHeader(header)[0].toLowerCase());
                headers.add(header);
            }
            this.requestBytes = this.helpers.buildHttpMessage(headers, this.requestBytes);
            this.request = helpers.analyzeRequest(this.requestBytes);
        }
    }

    private String getCanonicalQueryString()
    {
        // check for empty query
        final String queryString = this.originalUrl.getQuery();
        if (queryString == null || queryString == "") {
            return "";
        }

        // sort query string parameters by name/value
        ArrayList<IParameter> sortedParameters = new ArrayList<>();
        for (final String param : queryString.split("&")) {
            String[] tokens = param.split("=", 2);
            if (tokens.length == 1) {
                sortedParameters.add(helpers.buildParameter(tokens[0], "", IParameter.PARAM_URL));
            }
            else if (tokens.length >= 2) {
                sortedParameters.add(helpers.buildParameter(tokens[0], tokens[1], IParameter.PARAM_URL));
            }
        }
        Comparator comparator = new Comparator<IParameter> () {
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
                    this.helpers.urlEncode(param.getName()).replace("/", "%2f"),
                    this.helpers.urlEncode(param.getValue()).replace("/", "%2f"));
        }
        return canonicalQueryString;
    }

    private String getCanonicalUri()
    {
        String uri = this.originalUrl.getPath();
        if (!this.service.toLowerCase().equals("s3")) {
            // for services other than s3, URI must be normalized by removing relative elements and duplicate path separators
            uri = uri.replaceAll("[/]{2,}", "/");
        }
        if (uri.equals("")) {
            uri = "/";
        }
        return uri;
    }

    private String getCanonicalHeaders()
    {
        // get canonical headers. need at least Host header for HTTP/1.1 and authority header for http/2
        ArrayList<String> signedHeadersArray = new ArrayList<>();
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
                if (signedHeaderMap.containsKey(nameLower)) {
                    // duplicate headers have values comma-separated
                    value = value + "," + signedHeaderMap.get(nameLower);
                }
                signedHeadersArray.add(nameLower);
                signedHeaderMap.put(nameLower, value);
            }
        }
        Collections.sort(signedHeadersArray);
        String canonicalHeaders = "";
        for (final String nameLower : signedHeadersArray) {
            canonicalHeaders += String.format("%s:%s\n", nameLower, signedHeaderMap.get(nameLower));
        }
        return canonicalHeaders;
    }

    private String getCanonicalSignedHeaders()
    {
        // build list of headers to sign, then sort them.
        ArrayList<String> signedHeadersArray = new ArrayList<>();
        for (final String header : request.getHeaders()) {
            final String nameLower = splitHttpHeader(header)[0].toLowerCase();
            if (this.signedHeaderSet.contains(nameLower)) {
                signedHeadersArray.add(nameLower);
            }
        }
        Collections.sort(signedHeadersArray);
        return String.join(";", signedHeadersArray);
    }

    private String getPayload()
    {
        String payload = "";
        if (this.request.getBodyOffset() < this.requestBytes.length) {
            payload = new String(this.requestBytes, this.request.getBodyOffset(), this.requestBytes.length - this.request.getBodyOffset(), StandardCharsets.UTF_8);
        }
        return payload;
    }

    private String getPayloadHash()
    {
        if (this.service.toLowerCase().equals("s3")) {
            return "UNSIGNED-PAYLOAD";
        }
        // hash payload (POST body)
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exc) {
            return null;
        }

        // if request has a body, hash it. if no body, use hash of empty string
        String payload = getPayload();
        return DatatypeConverter.printHexBinary(digest.digest(payload.getBytes())).toLowerCase();
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

        logger.debug("===========BEGIN CANONICAL REQUEST==========");
        logger.debug(canonicalRequest);
        logger.debug("===========END CANONICAL REQUEST============");
        return DatatypeConverter.printHexBinary(digest.digest(canonicalRequest.getBytes())).toLowerCase();
    }

    /*
    Create the signed headers string for use in the signature and either the X-Amz-SignedHeaders or Authorization header.
    Only headers that exist will be included.
    */
    private String getSignedHeadersString()
    {
        // build list of headers to sign, then sort them.
        ArrayList<String> signedHeadersArray = new ArrayList<>();
        for (final String header : request.getHeaders()) {
            final String name = splitHttpHeader(header)[0];
            if (this.signedHeaderSet.contains(name.toLowerCase())) {
                signedHeadersArray.add(name);
            }
        }
        Collections.sort(signedHeadersArray);

        // build ';' separated list of all signed headers.
        return String.join(";", signedHeadersArray).toLowerCase();
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

        logger.debug("===========BEGIN STRING TO SIGN=============");
        logger.debug(toSign);
        logger.debug("===========END STRING TO SIGN===============");

        final byte[] kDate = getHmac(stringToBytes("AWS4"+secretKey), stringToBytes(this.amzDateYMD));
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
                this.algorithm, getCredentialScope(true), getSignedHeadersString(), signature);
    }

    /*
    update required URL parameters for signed GET requests
    */
    private boolean updateQueryString(String secretKey)
    {
        boolean updatedCredential = false;
        boolean updatedDate = false;
        boolean updatedSignature = false;
        boolean updatedSignedHeaders = false;

        // replace parameters that already exist
        for (IParameter param : this.request.getParameters()) {
            final String name = helpers.urlDecode(param.getName());
            if (name.toLowerCase().equals("x-amz-credential")) {
                this.requestBytes = helpers.updateParameter(this.requestBytes, helpers.buildParameter(name, getCredentialScope(true), IParameter.PARAM_URL));
                updatedCredential = true;
            }
            else if (name.toLowerCase().equals("x-amz-date")) {
                this.requestBytes = helpers.updateParameter(this.requestBytes, helpers.buildParameter(name, this.amzDate, IParameter.PARAM_URL));
                updatedDate = true;
            }
            else if (name.toLowerCase().equals("x-amz-signature")) {
                this.requestBytes = helpers.updateParameter(this.requestBytes, helpers.buildParameter(name, getSignature(secretKey), IParameter.PARAM_URL));
                updatedSignature = true;
            }
            else if (name.toLowerCase().equals("x-amz-signedheaders")) {
                this.requestBytes = helpers.updateParameter(this.requestBytes, helpers.buildParameter(name, getSignedHeadersString(), IParameter.PARAM_URL));
                updatedSignedHeaders = true;
            }
        }

        // handle cases where parameter was not in original request
        if (!updatedCredential) {
            this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Credential", getCredentialScope(true), IParameter.PARAM_URL));
        }
        if (!updatedDate) {
            this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Date", this.amzDateYMD, IParameter.PARAM_URL));
        }
        if (!updatedSignature) {
            this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-Signature", getSignature(secretKey), IParameter.PARAM_URL));
        }
        if (!updatedSignedHeaders) {
            this.requestBytes = helpers.addParameter(this.requestBytes, helpers.buildParameter("X-Amz-SignedHeaders", getSignedHeadersString(), IParameter.PARAM_URL));
        }

        // update request object since we modified the parameters
        this.request = helpers.analyzeRequest(this.requestBytes);
        return true;
    }


    public byte[] getSignedRequestBytes()
    {
        // update timestamp before signing. will be good for 15 minutes
        updateAmzDate();

        final String method = this.request.getMethod().toUpperCase();
        // attempt to keep signature in original location (url or headers)
        if (this.signatureInHeaders) {//xxx method.equals("POST") || method.equals("PUT")) {
            // update headers and preserve order. replace authorization header with new signature.
            ArrayList<String> headers = new ArrayList<>(this.request.getHeaders());
            final String newAuthHeader = getAuthorizationHeader(this.secretKey);
            final String newAmzDateHeader = "X-Amz-Date: " + this.amzDate;
            boolean authUpdated = false;
            boolean dateUpdated = false;
            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).toLowerCase().startsWith("authorization:")) {
                    headers.set(i, newAuthHeader);
                    authUpdated = true;
                } else if (headers.get(i).toLowerCase().startsWith("x-amz-date:")) {
                    headers.set(i, newAmzDateHeader);
                    dateUpdated = true;
                }
            }

            // if the headers didn't exist in the original request, add them here
            if (!authUpdated) {
                headers.add(newAuthHeader);
            }
            if (!dateUpdated) {
                headers.add(newAmzDateHeader);
            }
            final String body = getPayload();
            return this.helpers.buildHttpMessage(headers, body.getBytes());
        }

        // for non-POST requests, update signature in query string. this will almost always be a GET request.
        if (updateQueryString(this.secretKey)) {
            return this.helpers.buildHttpMessage(this.request.getHeaders(), null);
        }
        return null;
    }

}
