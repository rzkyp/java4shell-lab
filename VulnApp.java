import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.Executors;

/**
 * Java4Shell (CVE-2026-114938) lab target.
 *
 * Vulnerable path: java.util.Base64.getDecoder().decode(...) uses an
 * AVX-512 VBMI-optimised assembly intrinsic on x86-64 CPUs that support it.
 * A malformed Base64 value (length not a multiple of 4, trailing '=')
 * makes the intrinsic compute a negative length and write 62 bytes past
 * the heap buffer before the JVM rejects the input.
 *
 * This app is for AUTHORISED local lab use only.
 */
public class VulnApp {

    static final Path LOG = Paths.get(System.getProperty("lab.log", "vulnapp.log"));
    static final int PORT = Integer.parseInt(System.getProperty("lab.port", "8080"));

    static void log(String msg) {
        try {
            Files.writeString(LOG, Instant.now() + " " + msg + System.lineSeparator(),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
        }
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/", new Handler());
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.start();
        log("STARTED port=" + PORT
                + " java=" + System.getProperty("java.version")
                + " vm=" + System.getProperty("java.vm.name")
                + " vendor=" + System.getProperty("java.vendor"));
        System.out.println("VulnApp listening on http://127.0.0.1:" + PORT
                + "  java=" + System.getProperty("java.version"));
    }

    static class Handler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            try {
                if (path.equals("/health")) {
                    send(ex, 200, "OK");
                    return;
                }
                if (path.equals("/decode") && method.equalsIgnoreCase("GET")) {
                    String data = param(ex.getRequestURI().getQuery(), "data");
                    if (data == null) {
                        send(ex, 400, "missing data");
                        return;
                    }
                    // *** VULNERABLE CALL ***
                    byte[] out = Base64.getDecoder().decode(data);
                    log("GET decode inLen=" + data.length() + " outLen=" + out.length);
                    send(ex, 200, "decoded=" + out.length);
                    return;
                }
                if (path.equals("/decode") && method.equalsIgnoreCase("POST")) {
                    byte[] body = readAll(ex.getRequestBody());
                    String data = new String(body, StandardCharsets.UTF_8).trim();
                    // *** VULNERABLE CALL ***
                    byte[] out = Base64.getDecoder().decode(data);
                    log("POST decode inLen=" + data.length() + " outLen=" + out.length);
                    send(ex, 200, "decoded=" + out.length);
                    return;
                }
                if (path.equals("/decode-basic")) {
                    String h = ex.getRequestHeaders().getFirst("Authorization");
                    if (h != null && h.toLowerCase().startsWith("basic ")) {
                        String b64 = h.substring(6).trim();
                        // *** VULNERABLE CALL ***
                        byte[] out = Base64.getDecoder().decode(b64);
                        log("basic decode inLen=" + b64.length() + " outLen=" + out.length);
                        send(ex, 200, "basic-decoded=" + out.length);
                        return;
                    }
                    send(ex, 400, "no basic auth header");
                    return;
                }
                send(ex, 200, "Java4Shell lab target.\n"
                        + "GET  /decode?data=<base64>\n"
                        + "POST /decode  (raw body = base64)\n"
                        + "GET  /decode-basic  (Authorization: Basic <base64>)\n"
                        + "GET  /health\n");
            } catch (IllegalArgumentException e) {
                log("IllegalArgumentException: " + e.getMessage());
                send(ex, 400, "bad base64: " + e.getMessage());
            } catch (Throwable t) {
                log("ERROR: " + t);
                send(ex, 500, "error: " + t);
            }
        }
    }

    static byte[] readAll(java.io.InputStream in) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    static String param(String query, String name) {
        if (query == null) {
            return null;
        }
        for (String p : query.split("&")) {
            int i = p.indexOf('=');
            if (i > 0 && p.substring(0, i).equals(name)) {
                return p.substring(i + 1);
            }
        }
        return null;
    }

    static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
