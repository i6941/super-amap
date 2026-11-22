package xyz.aaron.superamap.release;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import javax.net.ssl.HttpsURLConnection;

/** Network and disk work for a background update worker. */
public final class UpdateDownload {
    private UpdateDownload() {}

    public static UpdateVerifier check(URI manifest, URI signature, byte[] publicKey,
                                       PackageInfo installed) throws Exception {
        return UpdateVerifier.verifyManifest(readSmall(manifest, 16 * 1024),
                readSmall(signature, 1024), publicKey, installed);
    }

    public static File download(UpdateVerifier release, URI mirror, File directory, PackageManager packages)
            throws Exception {
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException("No update cache");
        File target = new File(directory, "update-" + release.versionCode + ".apk");
        File partial = File.createTempFile("update-pending-", ".apk", directory);
        try {
            HttpsURLConnection connection = open(mirror == null ? release.url : mirror);
            try (InputStream input = connection.getInputStream(); FileOutputStream output = new FileOutputStream(partial)) {
                copy(input, output, release.size);
                output.getFD().sync();
            } finally {
                connection.disconnect();
            }
            release.verifyApk(partial, packages);
            Files.move(partial.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            return target;
        } finally {
            Files.deleteIfExists(partial.toPath());
        }
    }

    private static byte[] readSmall(URI url, int maximum) throws Exception {
        HttpsURLConnection connection = open(url);
        try (InputStream input = connection.getInputStream()) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            copy(input, bytes, maximum);
            return bytes.toByteArray();
        } finally {
            connection.disconnect();
        }
    }

    private static HttpsURLConnection open(URI uri) throws Exception {
        for (int hop = 0; hop < 5; hop++) {
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null)
                throw new IOException("Update requires HTTPS");
            HttpsURLConnection connection = (HttpsURLConnection) uri.toURL().openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(15000);
            int status;
            try {
                status = connection.getResponseCode();
                if (status == 200) return connection;
                String redirect = connection.getHeaderField("Location");
                if (status < 300 || status >= 400 || redirect == null)
                    throw new IOException("Update request failed with HTTP " + status);
                uri = uri.resolve(redirect);
            } catch (Exception failure) {
                connection.disconnect();
                throw failure;
            }
            connection.disconnect();
        }
        throw new IOException("Too many release redirects");
    }

    private static void copy(InputStream input, OutputStream output, long maximum) throws IOException {
        byte[] buffer = new byte[32768];
        long size = 0;
        for (int n; (n = input.read(buffer)) != -1;) {
            size += n;
            if (size > maximum) throw new IOException("Update response exceeds declared size");
            output.write(buffer, 0, n);
        }
    }
}
