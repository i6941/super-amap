package xyz.aaron.superamap.release;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.json.JSONObject;

/** Checks exact release bytes and installed package identity before showing an installer. */
public final class UpdateVerifier {
    private static final long MAX_APK = 512L * 1024 * 1024;
    public final String packageName, sha256, certificateSha256;
    public final int versionCode;
    public final long size;
    public final URI url;
    /** Route that supplied the authenticated manifest, for display only. */
    public String channel = "";

    private UpdateVerifier(JSONObject data) throws Exception {
        packageName = data.getString("package");
        sha256 = data.getString("sha256");
        certificateSha256 = data.getString("certificateSha256");
        versionCode = data.getInt("versionCode");
        size = data.getLong("size");
        url = new URI(data.getString("url"));
        if (data.length() != 7 || data.getInt("schema") != 1
                || !packageName.matches("[a-zA-Z]\\w*(\\.[a-zA-Z]\\w*)+")
                || !sha256.matches("[a-f0-9]{64}") || !certificateSha256.matches("[a-f0-9]{64}")
                || versionCode <= 0 || size <= 0 || size > MAX_APK
                || !"https".equals(url.getScheme()) || url.getHost() == null
                || url.getUserInfo() != null || url.getFragment() != null) {
            throw new IllegalArgumentException("Invalid update fields");
        }
    }

    public static UpdateVerifier verifyManifest(byte[] payload, byte[] signature, byte[] publicKey,
                                                 PackageInfo installed) throws Exception {
        UpdateVerifier release = inspectManifest(payload, signature, publicKey, installed);
        if (release.versionCode <= installed.versionCode) throw new SecurityException("Non-increasing version");
        return release;
    }

    static UpdateVerifier inspectManifest(byte[] payload, byte[] signature, byte[] publicKey,
                                          PackageInfo installed) throws Exception {
        if (payload.length > 16 * 1024 || signature.length > 1024 || publicKey.length > 2048)
            throw new IllegalArgumentException("Oversized update metadata");
        RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicKey));
        if (key.getModulus().bitLength() < 2048) throw new SecurityException("Invalid release public key");
        java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key);
        verifier.update(payload);
        if (!verifier.verify(signature)) throw new SecurityException("Manifest signature mismatch");
        UpdateVerifier release = new UpdateVerifier(new JSONObject(new String(payload, StandardCharsets.UTF_8)));
        if (!release.packageName.equals(installed.packageName)
                || !release.certificateSha256.equals(fingerprint(installed.signatures)))
            throw new SecurityException("Unexpected update identity");
        return release;
    }

    public void verifyApk(File file, PackageManager packages) throws Exception {
        if (file.length() != size) throw new SecurityException("APK size mismatch");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[32768];
            for (int n; (n = input.read(buffer)) != -1;) digest.update(buffer, 0, n);
        }
        if (!sha256.equals(hex(digest.digest()))) throw new SecurityException("APK digest mismatch");
        PackageInfo found = packages.getPackageArchiveInfo(file.getPath(), PackageManager.GET_SIGNATURES);
        if (found == null || !packageName.equals(found.packageName) || versionCode != found.versionCode
                || !certificateSha256.equals(fingerprint(found.signatures))) {
            throw new SecurityException("APK package, version or certificate mismatch");
        }
    }

    private static String fingerprint(Signature[] certificates) throws Exception {
        if (certificates == null || certificates.length != 1) throw new SecurityException("Expected one signer");
        return hex(MessageDigest.getInstance("SHA-256").digest(certificates[0].toByteArray()));
    }

    static String hex(byte[] data) {
        final String digits = "0123456789abcdef";
        StringBuilder result = new StringBuilder(data.length * 2);
        for (byte value : data) result.append(digits.charAt(value >>> 4 & 15)).append(digits.charAt(value & 15));
        return result.toString();
    }
}
