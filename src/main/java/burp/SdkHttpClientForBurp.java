package burp;

import org.apache.commons.lang3.StringUtils;
import software.amazon.awssdk.http.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.*;

/*
An http client impl for aws sdk that uses Burp networking. This is used
to make sure the aws sdk uses any configured upstream proxies.
 */
public class SdkHttpClientForBurp implements SdkHttpClient {
    private static final IBurpExtenderCallbacks callbacks = BurpExtender.getBurp().callbacks;
    private static final IExtensionHelpers helpers = BurpExtender.getBurp().helpers;

    @Override
    public ExecutableHttpRequest prepareRequest(HttpExecuteRequest request) {
        return new ExecutableHttpRequestForBurp(request);
    }

    @Override
    public void close() {
        // nothing to do
    }

    private static class ExecutableHttpRequestForBurp implements ExecutableHttpRequest {
        final private HttpExecuteRequest request;

        public ExecutableHttpRequestForBurp(HttpExecuteRequest request) {
            this.request = request;
        }

        @Override
        public HttpExecuteResponse call() throws IOException {
            //
            // Handle request
            //

            // get request body
            byte[] content = {};
            if (request.contentStreamProvider().isPresent()) {
                content = request.contentStreamProvider().get().newStream().readAllBytes();
            }

            final URI requestUri = request.httpRequest().getUri();
            final String requestPathQuery = String.format("%s%s",
                    StringUtils.isEmpty(requestUri.getRawPath()) ? "/" : requestUri.getRawPath(),
                    StringUtils.isEmpty(requestUri.getRawQuery()) ? "" : "?" + requestUri.getRawQuery());

            // get request headers. first header for Burp HTTP requests is the verb line
            List<String> requestHeaders = new ArrayList<>();
            requestHeaders.add(String.format("%s %s HTTP/1.1",
                    request.httpRequest().method(),
                    requestPathQuery));

            // tell this extension to ignore this SigV4 request
            requestHeaders.add(BurpExtender.SKIP_SIGNING_HEADER);

            // flatten header map into a list
            Map<String, List<String>> requestHeadersMap = request.httpRequest().headers();
            requestHeadersMap.keySet().forEach(k -> {
                requestHeadersMap.get(k).forEach(v -> {
                    requestHeaders.add(String.format("%s: %s", k, v));
                });
            });

            // send request through Burp
            final byte[] responseBytes = callbacks.makeHttpRequest(
                    request.httpRequest().host(),
                    request.httpRequest().port(),
                    request.httpRequest().protocol().equalsIgnoreCase("https"),
                    helpers.buildHttpMessage(requestHeaders, content));
            if (responseBytes == null || responseBytes.length == 0)
                throw new IOException("Failed to send Http request through Burp");

            //
            // Handle response
            //
            final IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            final byte[] body = Arrays.copyOfRange(responseBytes, responseInfo.getBodyOffset(), responseBytes.length);
            SdkHttpResponse.Builder builder = SdkHttpFullResponse.builder()
                    .statusCode(responseInfo.getStatusCode());
            responseInfo.getHeaders().stream()
                    .skip(1) // eg HTTP/1.1 200 OK
                    .forEach(h -> {
                        String[] header = BurpExtender.splitHeader(h);
                        builder.appendHeader(header[0], header[1]);
                    });
            return HttpExecuteResponse.builder()
                    .response(builder.build())
                    .responseBody(AbortableInputStream.create(new ByteArrayInputStream(body)))
                    .build();
        }

        @Override
        public void abort() {
            // nothing to do
        }
    }
}
