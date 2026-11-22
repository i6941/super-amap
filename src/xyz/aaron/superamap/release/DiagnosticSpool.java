package xyz.aaron.superamap.release;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;

/** Single-process spool. The caller schedules uploads and supplies device-local enrollment. */
public final class DiagnosticSpool {
    private static final int MAX_BODY = 128 * 1024;
    private static final int MAX_PENDING = 128;
    private static final Pattern PENDING = Pattern.compile("([1-9][0-9]{0,9})-([a-f0-9]{64})\\.tsv");
    private final File directory;

    public DiagnosticSpool(File privateDirectory) {
        directory = privateDirectory;
    }

    public synchronized String enqueue(int versionCode, byte[] events) throws Exception {
        if (versionCode <= 0 || events.length == 0 || events.length > MAX_BODY
                || events[events.length - 1] != '\n') throw new IllegalArgumentException("Invalid diagnostic batch");
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException("No diagnostics spool");
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update((versionCode + "\n").getBytes(StandardCharsets.US_ASCII));
        String identity = UpdateVerifier.hex(hash.digest(events));
        File target = new File(directory, versionCode + "-" + identity + ".tsv");
        if (target.isFile()) return identity;
        if (pending().length >= MAX_PENDING) throw new IOException("Diagnostic spool full");
        File partial = File.createTempFile("diagnostic-", ".part", directory);
        try {
            try (FileOutputStream output = new FileOutputStream(partial)) {
                output.write(events);
                output.getFD().sync();
            }
            Files.move(partial.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(partial.toPath());
        }
        return identity;
    }

    public synchronized int flush(URI endpoint, String device, String token) throws Exception {
        String path = endpoint.getRawPath();
        if (!"https".equals(endpoint.getScheme()) || endpoint.getHost() == null
                || endpoint.getUserInfo() != null || endpoint.getRawQuery() != null || endpoint.getRawFragment() != null
                || !(path.isEmpty() || path.equals("/") || path.equals("/v1/diagnostics"))
                || !device.matches("[a-zA-Z0-9_-]{1,64}") || !token.matches("[a-zA-Z0-9_-]{32,128}")) {
            throw new IllegalArgumentException("Invalid diagnostic enrollment");
        }
        File[] files = pending();
        Arrays.sort(files, Comparator.comparingLong(File::lastModified));
        int sent = 0;
        for (File file : files) {
            Matcher metadata = PENDING.matcher(file.getName());
            if (!metadata.matches() || file.length() <= 0 || file.length() > MAX_BODY)
                throw new IOException("Invalid pending file");
            send(endpoint.resolve("/v1/diagnostics"), device, token, metadata.group(1), metadata.group(2),
                    Files.readAllBytes(file.toPath()));
            Files.delete(file.toPath());
            sent++;
        }
        return sent;
    }

    private File[] pending() throws IOException {
        if (!directory.exists()) return new File[0];
        File[] files = directory.listFiles((parent, name) -> PENDING.matcher(name).matches());
        if (files == null) throw new IOException("Cannot list diagnostics spool");
        return files;
    }

    private static void send(URI endpoint, String device, String token, String version, String batch, byte[] events)
            throws Exception {
        HttpsURLConnection connection = (HttpsURLConnection) endpoint.toURL().openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(15000);
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setFixedLengthStreamingMode(events.length);
            connection.setRequestProperty("Authorization", "Bearer " + token);
            connection.setRequestProperty("Content-Type", "text/tab-separated-values");
            connection.setRequestProperty("X-Device-ID", device);
            connection.setRequestProperty("X-Version-Code", version);
            connection.setRequestProperty("X-Batch-ID", batch);
            try (OutputStream output = connection.getOutputStream()) {
                output.write(events);
            }
            if (connection.getResponseCode() != 200) throw new IOException("Diagnostic receipt unavailable");
            try (InputStream input = connection.getInputStream()) {
                ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                for (int n; (n = input.read(buffer)) != -1;) {
                    if (bytes.size() + n > 4096) throw new IOException("Oversized diagnostic receipt");
                    bytes.write(buffer, 0, n);
                }
                JSONObject receipt = new JSONObject(new String(bytes.toByteArray(), StandardCharsets.US_ASCII));
                if (receipt.length() != 1 || !batch.equals(receipt.optString("batchId")))
                    throw new IOException("Wrong diagnostic receipt");
            }
        } finally {
            connection.disconnect();
        }
    }
}
