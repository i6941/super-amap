package xyz.aaron.superamap.release;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.List;

/** Shares only the selected, verified APK with the system installer. */
public final class UpdateApkProvider extends ContentProvider {
    static final String AUTHORITY = "com.aaronlab.superamap.update-apk";

    static Uri apkUri(UpdateVerifier offer) {
        return new Uri.Builder().scheme("content").authority(AUTHORITY)
                .appendPath(offer.packageName).appendPath(Integer.toString(offer.versionCode)).build();
    }

    @Override public boolean onCreate() { return true; }

    @Override public String getType(Uri uri) { return "application/vnd.android.package-archive"; }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException("Read-only update");
        File apk = file(getContext(), uri);
        if (apk == null) throw new FileNotFoundException("Unknown update");
        return ParcelFileDescriptor.open(apk, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] arguments, String sortOrder) {
        String[] columns = projection == null
                ? new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
        MatrixCursor results = new MatrixCursor(columns, 1);
        File apk = file(getContext(), uri);
        if (apk == null || !apk.isFile()) return results;
        Object[] values = new Object[columns.length];
        for (int index = 0; index < columns.length; index++) {
            if (OpenableColumns.DISPLAY_NAME.equals(columns[index])) values[index] = apk.getName();
            if (OpenableColumns.SIZE.equals(columns[index])) values[index] = apk.length();
        }
        results.addRow(values);
        return results;
    }

    private static File file(Context context, Uri uri) {
        List<String> path = uri.getPathSegments();
        if (!AUTHORITY.equals(uri.getAuthority()) || path.size() != 2
                || !path.get(1).matches("[1-9][0-9]{0,9}")) return null;
        String name = path.get(0);
        if (!GithubUpdates.MAIN.equals(name) && !GithubUpdates.RELAY.equals(name)) return null;
        return new File(GithubUpdates.directory(context, name), "update-" + path.get(1) + ".apk");
    }

    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String selection, String[] args) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] args) {
        throw new UnsupportedOperationException();
    }
}
