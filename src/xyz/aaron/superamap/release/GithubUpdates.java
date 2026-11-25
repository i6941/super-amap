package xyz.aaron.superamap.release;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

final class GithubUpdates {
    static final String MAIN = "com.aaronlab.superamap";
    static final String RELAY = "com.autonavi.amapauto";
    private static final String RELAY_SETTINGS = "xyz.aaron.oemrelay.RelaySettings";
    private static final String REPOSITORY = "i6941/super-amap";
    private static final String FEED = "https://raw.githubusercontent.com/" + REPOSITORY + "/main/updates/";
    private static final String ASSETS = "/" + REPOSITORY + "/releases/download/";
    private static final List<String> PREFIXES = Arrays.asList("", "https://ghfast.top/", "https://ghproxy.net/");

    private GithubUpdates() {}

    static PackageInfo installed(PackageManager packages, String name) throws PackageManager.NameNotFoundException {
        if (RELAY.equals(name)) packages.getActivityInfo(new ComponentName(RELAY, RELAY_SETTINGS), 0);
        else if (!MAIN.equals(name)) throw new PackageManager.NameNotFoundException(name);
        return packages.getPackageInfo(name, PackageManager.GET_SIGNATURES);
    }

    static UpdateVerifier check(PackageManager packages, PackageInfo installed, byte[] key) throws Exception {
        String file = FEED + installed.packageName;
        Exception failure = null;
        UpdateVerifier newestMirror = null;
        for (String prefix : PREFIXES) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
            try {
                UpdateVerifier offer = UpdateDownload.inspect(URI.create(prefix + file + ".json"),
                        URI.create(prefix + file + ".sig"), key, packages, installed);
                if (!isReleaseAsset(offer.url)) throw new SecurityException("Unexpected release repository");
                offer.channel = channel(prefix);
                if (prefix.isEmpty()) return offer.versionCode > installed.versionCode ? offer : null;
                if (newestMirror == null || offer.versionCode > newestMirror.versionCode) newestMirror = offer;
            } catch (Exception rejected) {
                failure = rejected;
            }
        }
        if (newestMirror != null) return newestMirror.versionCode > installed.versionCode ? newestMirror : null;
        throw new IOException("No authenticated update channel", failure);
    }

    private static String channel(String prefix) {
        if (prefix.isEmpty()) return "GitHub 直连";
        if (prefix.contains("ghfast.top")) return "GHFast";
        if (prefix.contains("ghproxy.net")) return "GHproxy";
        return "备用通路";
    }

    static boolean isReleaseAsset(URI url) {
        String path = url.getRawPath();
        if (!"https".equals(url.getScheme()) || !"github.com".equals(url.getHost())
                || url.getRawQuery() != null || url.getRawFragment() != null || url.getUserInfo() != null
                || url.getPort() != -1 || path == null || !path.startsWith(ASSETS)) return false;
        return path.substring(ASSETS.length()).matches("[a-zA-Z0-9][a-zA-Z0-9_.-]*/[a-zA-Z0-9][a-zA-Z0-9_.-]*\\.apk");
    }

    static File fetch(Context context, UpdateVerifier offer) throws Exception {
        PackageManager packages = context.getPackageManager();
        PackageInfo installed = installed(packages, offer.packageName);
        if (offer.versionCode <= installed.versionCode) throw new IOException("An equal or newer version is installed");
        File directory = directory(context, offer.packageName);
        // Only one installer can be staged at a time. Keep the cache bounded across releases.
        File[] previous = directory.listFiles((parent, name) -> name.matches("update-[0-9]+\\.apk"));
        if (previous != null) for (File old : previous) old.delete();
        Exception failure = null;
        for (String prefix : PREFIXES) {
            if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
            try {
                File apk = UpdateDownload.download(offer, URI.create(prefix + offer.url), directory, packages);
                if (RELAY.equals(offer.packageName) && !isRelay(packages, apk)) {
                    apk.delete();
                    throw new SecurityException("APK is missing the LX relay component");
                }
                return apk;
            } catch (Exception rejected) {
                failure = rejected;
            }
        }
        throw new IOException("All verified APK download routes failed", failure);
    }

    static File directory(Context context, String name) {
        if (!MAIN.equals(name) && !RELAY.equals(name)) throw new IllegalArgumentException("Unknown update target");
        return new File(new File(context.getCacheDir(), "verified-updates"), name);
    }

    private static boolean isRelay(PackageManager packages, File apk) {
        PackageInfo info = packages.getPackageArchiveInfo(apk.getPath(), PackageManager.GET_ACTIVITIES);
        if (info != null && info.activities != null) {
            for (ActivityInfo activity : info.activities) if (RELAY_SETTINGS.equals(activity.name)) return true;
        }
        return false;
    }
}
