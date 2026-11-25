package xyz.aaron.superamap.release;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class UpdateActivity extends Activity {
    private static final int INSTALL = 1;
    private static final String RELEASE_KEY = "superamap-update-key.der";
    private final ExecutorService worker = Executors.newFixedThreadPool(2);
    private final Row main = new Row(GithubUpdates.MAIN, "超级高德");
    private final Row relay = new Row(GithubUpdates.RELAY, "LX 转接包");
    private final Row[] rows = {main, relay};
    private Button refresh;
    private byte[] releaseKey;
    private int checking;
    private boolean installing;
    private boolean destroyed;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        content.setPadding(padding, padding, padding, padding);
        addRow(content, main);
        addRow(content, relay);
        refresh = new Button(this);
        refresh.setText("检查更新");
        refresh.setOnClickListener(view -> check());
        content.addView(refresh);
        scroll.addView(content);
        setContentView(scroll);

        if (Build.VERSION.SDK_INT < 27) {
            unavailable("在线更新要求 Android 8.1 或更高版本");
            return;
        }
        try {
            releaseKey = readKey();
            check();
        } catch (IOException missing) {
            unavailable("更新验证公钥不可用");
        }
    }

    private void addRow(LinearLayout content, Row row) {
        TextView title = new TextView(this);
        title.setText(row.title);
        title.setTextSize(20);
        content.addView(title);
        row.status = new TextView(this);
        row.status.setTextSize(16);
        content.addView(row.status);
        row.download = new Button(this);
        row.download.setText("下载并确认安装");
        row.download.setEnabled(false);
        row.download.setOnClickListener(view -> download(row));
        content.addView(row.download);
    }

    private void unavailable(String message) {
        refresh.setEnabled(false);
        for (Row row : rows) row.status.setText(message);
    }

    private byte[] readKey() throws IOException {
        try (InputStream input = getAssets().open(RELEASE_KEY)) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[512];
            for (int n; (n = input.read(buffer)) != -1;) {
                if (output.size() + n > 2048) throw new IOException("Oversized update key");
                output.write(buffer, 0, n);
            }
            return output.toByteArray();
        }
    }

    private void check() {
        if (checking != 0 || installing) return;
        checking = rows.length;
        for (Row row : rows) {
            row.offer = null;
            row.status.setText("正在检查更新…");
            worker.execute(() -> checkRow(row));
        }
        updateButtons();
    }

    private void checkRow(Row row) {
        UpdateVerifier found = null;
        String message;
        String current = "";
        try {
            PackageInfo installed = GithubUpdates.installed(getPackageManager(), row.packageName);
            current = "已装 " + installed.versionCode + "，";
            found = GithubUpdates.check(installed, releaseKey);
            message = current + (found == null ? "已是最新版本"
                    : "可更新至 " + found.versionCode
                    + (found.channel.isEmpty() ? "" : "（" + found.channel + "）"));
        } catch (PackageManager.NameNotFoundException absent) {
            message = "当前未安装可更新的" + row.title;
        } catch (Exception failure) {
            message = current + "暂时无法验证更新，请重试";
        }
        final String result = message;
        final UpdateVerifier offer = found;
        runOnUiThread(() -> {
            if (destroyed) return;
            row.offer = offer;
            row.status.setText(result);
            checking--;
            updateButtons();
        });
    }

    private void download(Row row) {
        final UpdateVerifier offer = row.offer;
        if (offer == null || installing || checking != 0) return;
        installing = true;
        row.status.setText("正在下载并校验 " + offer.versionCode + "…");
        updateButtons();
        worker.execute(() -> {
            try {
                GithubUpdates.fetch(getApplicationContext(), offer);
                runOnUiThread(() -> showInstaller(row, offer));
            } catch (Exception failure) {
                runOnUiThread(() -> finishDownload(row, "下载或校验失败，请重试"));
            }
        });
    }

    private void showInstaller(Row row, UpdateVerifier offer) {
        if (destroyed || isFinishing()) return;
        Intent intent = new Intent(Intent.ACTION_INSTALL_PACKAGE).setData(UpdateApkProvider.apkUri(offer))
                .putExtra(Intent.EXTRA_RETURN_RESULT, true).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        try {
            row.status.setText("已校验，等待系统安装确认");
            startActivityForResult(intent, INSTALL);
        } catch (RuntimeException unavailable) {
            finishDownload(row, "系统安装器不可用");
        }
    }

    private void finishDownload(Row row, String message) {
        if (destroyed) return;
        installing = false;
        row.status.setText(message);
        updateButtons();
    }

    private void updateButtons() {
        refresh.setEnabled(!installing && checking == 0);
        for (Row row : rows) row.download.setEnabled(row.offer != null && !installing && checking == 0);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == INSTALL) {
            installing = false;
            check();
        }
    }

    @Override protected void onDestroy() {
        destroyed = true;
        worker.shutdownNow();
        super.onDestroy();
    }

    private static final class Row {
        final String packageName, title;
        TextView status;
        Button download;
        UpdateVerifier offer;

        Row(String packageName, String title) {
            this.packageName = packageName;
            this.title = title;
        }
    }
}
