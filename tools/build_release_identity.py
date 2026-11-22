"""Build a local Super Amap candidate under the official application ID."""

import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile

from androguard.core.apk import APK
from androguard.core.dex import DEX

from build_instrument_extras_106 import (
    APKTOOL, BUILD_TOOLS, N, PROJECT_CERT, ROOT, compile_verifier, once, package_and_sign, run, tree,
)
from build_native_settings_130 import assemble_dex, decode_dex
from sign_candidate import digest
from verify_integrated_energy import semantics


BASE = ROOT / "capture/20261122/native-settings-code153/super-amap-native-settings-code26000153.apk"
BASE_HASH = "fa3a6a7663a4348f09c82489b9b680d626ac372aacc87d4f53a0a0ab2fb5ba54"
OLD_ID = "xyz.aaron.superamap"
APPLICATION_ID = "com.aaronlab.superamap"
CODE = 26000157
OWNER = "Lxyz/aaron/superamap/energy/EnergyController;"
HOOK = (OWNER, "attach", "(Landroid/view/View;Landroid/view/View;I)V")


def rename_manifest(manifest):
    if manifest.get("package") != OLD_ID or manifest.get(N + "sharedUserId"):
        raise ValueError("Unexpected application identity")
    manifest.set("package", APPLICATION_ID)
    for element in manifest.iter():
        for attribute in (N + "name", N + "authorities"):
            value = element.get(attribute, "")
            if attribute == N + "name" and element.tag not in ("permission", "uses-permission"):
                continue
            if value.startswith(OLD_ID):
                element.set(attribute, APPLICATION_ID + value[len(OLD_ID):])


def update_energy_gate(project, stage):
    target = project / "classes2.dex"
    dex_project = decode_dex(stage, "energy-gate", target.read_bytes(), BASE)
    owner = dex_project / "smali" / (OWNER[1:-1] + ".smali")
    source = owner.read_text(encoding="utf-8")
    old, new = (f'    const-string p2, "{name}"' for name in (OLD_ID, APPLICATION_ID))
    owner.write_text(once(source, old, new), encoding="utf-8")
    target.write_bytes(assemble_dex(dex_project, stage / "energy-gate.apk"))


def verify(stage, signed):
    run([BUILD_TOOLS / "zipalign.exe", "-c", "-P", "16", "4", signed])
    signature = json.loads(run(compile_verifier(stage) + [signed]))
    if (not signature["verified"] or not signature["v2"] or signature["warnings"]
            or signature["certificate_sha256"] != PROJECT_CERT):
        raise ValueError("Local candidate signature mismatch")
    expected = APK(str(BASE)).get_android_manifest_xml()
    rename_manifest(expected)
    expected.set(N + "versionCode", str(CODE))
    actual = APK(str(signed)).get_android_manifest_xml()
    if tree(expected) != tree(actual):
        raise ValueError("Unexpected installed manifest")
    with ZipFile(BASE) as old, ZipFile(signed) as new:
        def payload(archive):
            return {entry.filename: (entry.file_size, entry.CRC) for entry in archive.infolist()
                    if not entry.is_dir() and not entry.filename.startswith("META-INF/")}

        before, after = payload(old), payload(new)
        changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
        if changed != {"AndroidManifest.xml", "classes2.dex", "resources.arsc"} or new.testzip():
            raise ValueError(f"Unexpected changed entries: {sorted(changed)}")
        first, last = (semantics(DEX(z.read("classes2.dex"))) for z in (old, new))
        method_delta = {key for key in first.keys() | last.keys() if first.get(key) != last.get(key)}
        if method_delta != {HOOK}:
            raise ValueError(f"Unexpected DEX changes: {sorted(method_delta)[:8]}")
    return {"apk": signed.name, "package": APPLICATION_ID, "version_code": CODE,
            "sha256": digest(signed), "signature": signature, "signing": "local test identity",
            "changed_payload": sorted(changed), "changed_methods": sorted(method_delta),
            "can_upgrade_trial_package": False, "vehicle_validated": False}


def main(stage):
    if digest(BASE) != BASE_HASH:
        raise ValueError("Unexpected code153 baseline SHA-256")
    stage.mkdir(parents=True, exist_ok=False)
    project = stage / "project"
    run(["java", "-jar", APKTOOL, "d", "-s", "-j", "4", "-o", project, BASE])
    config = project / "apktool.yml"
    config.write_text(once(config.read_text(encoding="utf-8"), "versionCode: 26000153",
                           f"versionCode: {CODE}"), encoding="utf-8")
    manifest = project / "AndroidManifest.xml"
    ET.register_namespace("android", N[1:-1])
    document = ET.parse(manifest)
    rename_manifest(document.getroot())
    document.write(manifest, encoding="utf-8", xml_declaration=True)
    update_energy_gate(project, stage)
    signed = stage / f"super-amap-local-code{CODE}.apk"
    package_and_sign(project, stage, signed)
    (stage / "report.json").write_text(json.dumps(verify(stage, signed), indent=2) + "\n", encoding="utf-8")
    print(signed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=lambda path: Path(path).resolve(), required=True)
    main(parser.parse_args().stage)
