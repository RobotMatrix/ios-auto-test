#!/usr/bin/env python3
"""
iOS Utility Tools: Symbol restoration and auto code-signing.

Usage integrated into ios_auto_test.py:
  --restore-symbols     Symbolicate crash reports after test
  --auto-sign           Add required entitlements and re-sign IPA
  --sign-entitlements   Comma-separated list of extra entitlements to add
"""

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from typing import Optional

RESTORE_SYMBOL = shutil.which("restore-symbol") or "restore-symbol"


# ---------------------------------------------------------------------------
# Symbol Restoration (UUID-aware, multi-binary)
# ---------------------------------------------------------------------------

def find_signing_identity() -> Optional[str]:
    """Find a valid Apple Development signing identity."""
    result = subprocess.run(
        ["security", "find-identity", "-v", "-p", "codesigning"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.split("\n"):
        match = re.search(r'"(.+)"', line)
        if match:
            return match.group(1)
    return None


def get_binary_uuid(path: str) -> Optional[str]:
    """Get UUID of a Mach-O binary via dwarfdump."""
    try:
        r = subprocess.run(
            ["dwarfdump", "--uuid", path],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.split("\n"):
            if "UUID:" in line:
                return line.split("UUID:")[1].strip().split()[0].strip("()")
    except Exception:
        pass
    return None


def extract_ipa_binary_map(ipa_path: str, extract_dir: str) -> dict[str, str]:
    """Extract IPA and build a UUID → binary-path map for all Mach-O binaries.

    Returns {uuid: path} dict. The extract_dir is NOT cleaned up (caller manages).
    """
    uuid_map: dict[str, str] = {}
    with zipfile.ZipFile(ipa_path, "r") as zf:
        zf.extractall(extract_dir)

    app_dirs = [n for n in os.listdir(os.path.join(extract_dir, "Payload"))
                if n.endswith(".app")]
    if not app_dirs:
        return uuid_map
    app_path = os.path.join(extract_dir, "Payload", app_dirs[0])

    binaries_to_check: list[str] = []

    with open(os.path.join(app_path, "Info.plist"), "rb") as f:
        info = plistlib.load(f)
    exec_name = info.get("CFBundleExecutable", "")
    binaries_to_check.append(os.path.join(app_path, exec_name))

    fw_dir = os.path.join(app_path, "Frameworks")
    if os.path.isdir(fw_dir):
        for fw in os.listdir(fw_dir):
            fw_path = os.path.join(fw_dir, fw)
            if fw.endswith(".framework"):
                bn = os.path.join(fw_path, fw.replace(".framework", ""))
                if os.path.isfile(bn):
                    binaries_to_check.append(bn)
            elif fw.endswith(".dylib"):
                binaries_to_check.append(fw_path)

    plug_dir = os.path.join(app_path, "PlugIns")
    if os.path.isdir(plug_dir):
        for plug in os.listdir(plug_dir):
            plug_path = os.path.join(plug_dir, plug)
            if plug.endswith(".appex"):
                pi = os.path.join(plug_path, "Info.plist")
                if os.path.exists(pi):
                    with open(pi, "rb") as f:
                        pinfo = plistlib.load(f)
                    pb = pinfo.get("CFBundleExecutable", "")
                    pb_path = os.path.join(plug_path, pb)
                    if os.path.isfile(pb_path):
                        binaries_to_check.append(pb_path)

    for b in binaries_to_check:
        uuid = get_binary_uuid(b)
        if uuid:
            uuid_map[uuid.upper()] = b

    return uuid_map


def resolve_frame_symbol(binary_map: dict[str, str], img_uuid: str,
                          img_base: int, offset: int) -> str:
    """Resolve a single frame address to a symbol using the correct binary.

    Args:
        binary_map: {UUID: binary_path} from extract_ipa_binary_map
        img_uuid: UUID of the image from the crash report
        img_base: Load address (base) of the image
        offset: Offset into the image

    Returns symbol string.
    """
    addr = img_base + offset
    binary_path = binary_map.get(img_uuid.upper())

    if binary_path:
        try:
            r = subprocess.run(
                ["atos", "-arch", "arm64e", "-o", binary_path,
                 "-l", hex(img_base), hex(addr)],
                capture_output=True, text=True, timeout=5,
            )
            result = r.stdout.strip()
            if result and result != hex(addr):
                return result
        except Exception:
            pass

    return f"0x{addr:x}"


def parse_ips_crash(ips_path: str) -> Optional[dict]:
    """Parse an .ips crash report (JSON format).

    .ips files have two JSON objects: a one-line header, then the crash data.
    We need the second one.
    """
    try:
        with open(ips_path, "r", errors="ignore") as f:
            content = f.read()

        lines = content.split("\n")
        json_start = -1
        in_first = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("{") and not in_first:
                in_first = True
                continue
            if in_first and stripped.startswith("{"):
                json_start = i
                break

        if json_start == -1:
            first_brace = content.find("{")
            if first_brace == -1:
                return None
            return json.loads(content[first_brace:].split("\n")[0])

        crash_json = "\n".join(lines[json_start:])
        return json.loads(crash_json)
    except Exception:
        return None


def symbolicate_crash_report(crash_path: str, binary_map: dict[str, str],
                             output_path: Optional[str] = None) -> str:
    """Symbolicate a crash report using UUID-matched binaries from the IPA.

    Each frame's image UUID is matched against the binary_map. If found,
    atos resolves it against the correct framework/dylib binary.
    """
    crash_data = parse_ips_crash(crash_path)
    if not crash_data:
        return f"ERROR: Could not parse crash report: {crash_path}"

    used_images = crash_data.get("usedImages", [])
    uuid_match_count = 0
    uuid_miss_count = 0

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append(f"SYMBOLICATED CRASH REPORT")
    lines.append(f"Source: {os.path.basename(crash_path)}")
    lines.append(f"IPA binaries indexed: {len(binary_map)}")
    lines.append("=" * 70)
    lines.append("")

    app_name = crash_data.get("procName", crash_data.get("app_name", "Unknown"))
    bundle_id = crash_data.get("bundleID", crash_data.get("coalitionName", "Unknown"))
    os_ver = crash_data.get("osVersion", {})
    os_str = f"{os_ver.get('train', '')} ({os_ver.get('build', '')})" if isinstance(os_ver, dict) else str(os_ver)

    lines.append(f"App:       {app_name}")
    lines.append(f"Bundle ID: {bundle_id}")
    lines.append(f"OS:        {os_str}")
    lines.append(f"Bug Type:  {crash_data.get('bug_type', 'N/A')}")
    lines.append("")

    exception = crash_data.get("exception", {})
    termination = crash_data.get("termination", {})
    lines.append("--- EXCEPTION ---")
    lines.append(f"Type:      {exception.get('type', 'N/A')}")
    lines.append(f"Signal:    {exception.get('signal', 'N/A')}")
    lines.append(f"Subtype:   {exception.get('subtype', 'N/A')}")
    lines.append(f"Termination: {termination.get('namespace', 'N/A')} "
                 f"{termination.get('indicator', '')}")
    faulting_thread = crash_data.get("faultingThread", -1)
    lines.append(f"Faulting Thread: {faulting_thread}")
    lines.append("")

    threads = crash_data.get("threads", [])
    for ti, thread in enumerate(threads):
        thread_name = thread.get("name", "")
        queue = thread.get("queue", "")
        is_faulting = (ti == faulting_thread)

        header = f"Thread {ti}"
        if is_faulting:
            header += " *** FAULTING THREAD ***"
        if thread_name:
            header += f" [{thread_name}]"
        if queue:
            header += f" queue={queue}"
        lines.append(f"--- {header} ---")

        frames = thread.get("frames", [])
        for fi, frame in enumerate(frames):
            img_idx = frame.get("imageIndex", -1)
            offset = frame.get("imageOffset", 0)
            symbol = frame.get("symbol", "")
            sym_loc = frame.get("symbolLocation", 0)

            img = used_images[img_idx] if 0 <= img_idx < len(used_images) else {}
            img_name = img.get("name", "???")
            img_base = img.get("base", 0)
            img_uuid = img.get("uuid", "")

            if symbol:
                resolved = f"{symbol} + {sym_loc}" if sym_loc else symbol
            else:
                resolved = resolve_frame_symbol(
                    binary_map, img_uuid, img_base, offset,
                )
                if img_uuid.upper() in binary_map:
                    uuid_match_count += 1
                else:
                    uuid_miss_count += 1

            prefix = " ->" if fi == 0 else "   "
            lines.append(
                f"{prefix} {fi:3d}  {img_name:<45s} "
                f"0x{img_base + offset:016x}  {resolved}"
            )
        lines.append("")

    lines.append(f"--- SYMBOL RESOLUTION ---")
    lines.append(f"UUID-matched frames: {uuid_match_count}")
    lines.append(f"UUID-missed frames:  {uuid_miss_count}")
    lines.append(f"IPA binaries:        {len(binary_map)}")
    lines.append("")

    vm_summary = crash_data.get("vmSummary", "")
    if vm_summary:
        lines.append("--- VM SUMMARY ---")
        lines.append(vm_summary)
        lines.append("")

    output = "\n".join(lines)

    if output_path:
        with open(output_path, "w") as f:
            f.write(output)
    else:
        print(output)

    return output


def generate_lldb_symbol_script(ipa_path: str, output_path: str,
                                 extract_dir: Optional[str] = None) -> str:
    """Generate an lldb command script to load symbols from all IPA binaries.

    Extracts IPA to extract_dir (or a persistent cache). When sourced in lldb
    (`command source /path/to/script`), this loads DWARF debug info for every
    binary so lldb can show proper symbols during debugging.

    Returns the path to the script.
    """
    own_tmp = False
    if extract_dir is None:
        extract_dir = os.path.join(
            tempfile.gettempdir(),
            f"ipa_symbols_{os.path.splitext(os.path.basename(ipa_path))[0]}"
        )
        own_tmp = True

    os.makedirs(extract_dir, exist_ok=True)
    binary_map = extract_ipa_binary_map(ipa_path, extract_dir)

    if not binary_map:
        return ""

    lines = [
        "# LLDB Symbol Loading Script",
        f"# Generated from: {os.path.basename(ipa_path)}",
        f"# Extract dir: {extract_dir}",
        f"# {len(binary_map)} binaries indexed",
        f"#",
        f"# Usage in lldb:",
        f"#   (lldb) command source {output_path}",
        "",
    ]

    for uuid, path in sorted(binary_map.items()):
        lines.append(f"target modules add \"{path}\"")

    lines.append("")
    lines.append(f"# Alternative: set debug-file-search-paths")
    lines.append(f"# settings set target.debug-file-search-paths {extract_dir}")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    script = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(script)

    return output_path


def symbolicate_all_reports(crash_dir: str, ipa_path: str,
                            output_dir: str) -> list[str]:
    """Symbolicate all .ips files using UUID-matched binaries from the IPA."""
    tmpdir = tempfile.mkdtemp(prefix="symbol_")
    binary_map: dict[str, str] = {}
    try:
        binary_map = extract_ipa_binary_map(ipa_path, tmpdir)
        if not binary_map:
            print(f"[ERROR] No binaries found in IPA: {ipa_path}")
            shutil.rmtree(tmpdir, ignore_errors=True)
            return []
    except Exception as e:
        print(f"[ERROR] Failed to extract IPA: {e}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return []

    print(f"[INFO] Indexed {len(binary_map)} binaries by UUID")

    output_paths = []
    os.makedirs(output_dir, exist_ok=True)
    for root, _dirs, files in os.walk(crash_dir):
        for f in files:
            if not f.endswith(".ips"):
                continue
            crash_path = os.path.join(root, f)
            out_name = f.replace(".ips", "_symbolicated.txt")
            out_path = os.path.join(output_dir, out_name)
            try:
                symbolicate_crash_report(crash_path, binary_map, out_path)
                output_paths.append(out_path)
                print(f"[OK] Symbolicated: {out_path}")
            except Exception as e:
                print(f"[ERROR] Failed to symbolicate {f}: {e}")

    shutil.rmtree(tmpdir, ignore_errors=True)
    return output_paths


# ---------------------------------------------------------------------------
# Auto Signing
# ---------------------------------------------------------------------------

DEFAULT_EXTRA_ENTITLEMENTS = [
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.debugger",
]


def get_existing_entitlements(binary_path: str) -> Optional[dict]:
    """Extract existing entitlements from a signed binary."""
    result = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", binary_path],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    ent_start = result.stdout.find("<?xml")
    if ent_start == -1:
        return {}
    try:
        return plistlib.loads(result.stdout[ent_start:].encode())
    except Exception:
        return {}


def get_entitlements_from_profile(profile_path: str) -> Optional[dict]:
    """Extract entitlements from an embedded.mobileprovision file."""
    result = subprocess.run(
        ["security", "cms", "-D", "-i", profile_path],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    try:
        data = plistlib.loads(result.stdout.encode())
        return data.get("Entitlements", {})
    except Exception:
        return None


def _find_macho_binaries(app_path: str) -> list[str]:
    """Find all Mach-O executable binaries in an .app bundle."""
    binaries: list[str] = []
    for root, _dirs, files in os.walk(app_path):
        for f in files:
            fpath = os.path.join(root, f)
            if os.path.islink(fpath) or os.path.getsize(fpath) < 1000:
                continue
            try:
                r = subprocess.run(
                    ["file", "-b", fpath], capture_output=True, text=True,
                    timeout=5,
                )
                if "Mach-O" in r.stdout:
                    binaries.append(fpath)
            except Exception:
                pass
    return binaries


def restore_stripped_symbols_in_app(app_path: str) -> int:
    """Run restore-symbol on all Mach-O binaries in the app to recover
    Objective-C method symbols that may have been stripped.

    Returns the number of binaries processed.
    """
    if not shutil.which("restore-symbol"):
        print("[WARN] restore-symbol not found, skipping symbol restoration")
        return 0

    binaries = _find_macho_binaries(app_path)
    count = 0
    for bin_path in binaries:
        tmp_out = bin_path + "_restored"
        try:
            r = subprocess.run(
                [RESTORE_SYMBOL, bin_path, "-o", tmp_out],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode == 0 and os.path.getsize(tmp_out) > 0:
                os.replace(tmp_out, bin_path)
                count += 1
                rel = os.path.relpath(bin_path, app_path)
                print(f"  [OK] {rel}")
            elif os.path.exists(tmp_out):
                os.remove(tmp_out)
        except Exception as e:
            if os.path.exists(tmp_out):
                os.remove(tmp_out)
            print(f"  [FAIL] {os.path.basename(bin_path)}: {e}")

    return count


def sign_binary(binary_path: str, identity: str, entitlements_path: str,
                force: bool = True) -> bool:
    """Sign a binary with the given identity and entitlements."""
    cmd = ["codesign", "-s", identity, "--entitlements", entitlements_path]
    if force:
        cmd.append("-f")
    cmd.append(binary_path)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [FAIL] codesign {os.path.basename(binary_path)}: "
              f"{result.stderr.strip()[:200]}")
        return False
    print(f"  [OK] Signed: {os.path.basename(binary_path)}")
    return True


def auto_sign_ipa(ipa_path: str, output_path: Optional[str] = None,
                   extra_entitlements: Optional[list[str]] = None,
                   identity: Optional[str] = None,
                   provision_profile: Optional[str] = None,
                   restore_stripped: bool = False) -> Optional[str]:
    """Auto-sign an IPA with required entitlements for JIT/memory execution.

    Steps:
      1. Extract IPA
      1.5 (optional) restore-symbol on all Mach-O binaries
      2. Get existing entitlements + add required ones
      3. Find signing identity (+ use custom provision profile)
      4. Re-sign main binary + all embedded frameworks/appex
      5. Re-package into IPA

    Args:
        ipa_path: Path to source IPA
        output_path: Path for output IPA (auto-generated if None)
        extra_entitlements: Additional entitlements to add
        identity: Signing identity (auto-detected if None)
        provision_profile: Path to .mobileprovision to embed
        restore_stripped: Run restore-symbol on all binaries before signing
    """
    if extra_entitlements is None:
        extra_entitlements = DEFAULT_EXTRA_ENTITLEMENTS

    if identity is None:
        identity = find_signing_identity()
        if not identity:
            print("[ERROR] No signing identity found. "
                  "Check 'security find-identity -v -p codesigning'")
            return None
    print(f"[INFO] Using identity: {identity}")

    if output_path is None:
        base = os.path.splitext(os.path.basename(ipa_path))[0]
        output_path = os.path.join(os.path.dirname(ipa_path) or ".",
                                   f"{base}_resigned.ipa")

    tmpdir = tempfile.mkdtemp(prefix="sign_")
    app_path = None
    exec_name = ""

    try:
        # Step 1: Extract IPA
        print(f"[INFO] Extracting IPA -> {tmpdir}")
        with zipfile.ZipFile(ipa_path, "r") as zf:
            zf.extractall(tmpdir)
        payload = os.path.join(tmpdir, "Payload")
        if not os.path.isdir(payload):
            print("[ERROR] No Payload directory in IPA")
            return None
        app_dirs = [d for d in os.listdir(payload) if d.endswith(".app")]
        if not app_dirs:
            print("[ERROR] No .app in Payload")
            return None
        app_path = os.path.join(payload, app_dirs[0])
        print(f"[INFO] App: {app_dirs[0]}")

        # Get executable name
        info_plist = os.path.join(app_path, "Info.plist")
        with open(info_plist, "rb") as f:
            info = plistlib.load(f)
        exec_name = info.get("CFBundleExecutable", "")
        main_binary = os.path.join(app_path, exec_name)

        if restore_stripped:
            print("[INFO] Restoring stripped ObjC symbols (restore-symbol)...")
            count = restore_stripped_symbols_in_app(app_path)
            print(f"[INFO] {count} binaries processed")

        # Step 2: Get/modify entitlements
        print("[INFO] Fetching entitlements...")

        entitlements: dict = {}
        if provision_profile and os.path.isfile(provision_profile):
            print(f"[INFO] Using provision profile: {os.path.basename(provision_profile)}")
            shutil.copy2(provision_profile, os.path.join(app_path, "embedded.mobileprovision"))
            prov_ent = get_entitlements_from_profile(provision_profile) or {}
            entitlements = dict(prov_ent)
            for ent in extra_entitlements:
                if ent not in entitlements:
                    print(f"[WARN] Entitlement '{ent}' not in profile, skipping")
        else:
            existing_ent = get_existing_entitlements(main_binary) or {}
            profile_path = os.path.join(app_path, "embedded.mobileprovision")
            if os.path.exists(profile_path):
                prov_ent = get_entitlements_from_profile(profile_path) or {}
                for k, v in prov_ent.items():
                    if k not in existing_ent:
                        existing_ent[k] = v
            entitlements = dict(existing_ent)
            for ent in extra_entitlements:
                if ent not in entitlements:
                    entitlements[ent] = True

        # Write entitlements plist
        ent_path = os.path.join(tmpdir, "entitlements.plist")
        with open(ent_path, "wb") as f:
            plistlib.dump(entitlements, f)

        # Step 3: Re-sign all binaries (main + frameworks + appex)
        print("[INFO] Signing binaries...")
        binaries_to_sign = [main_binary]

        frameworks_dir = os.path.join(app_path, "Frameworks")
        if os.path.isdir(frameworks_dir):
            for fw in os.listdir(frameworks_dir):
                fw_path = os.path.join(frameworks_dir, fw)
                if fw.endswith(".framework"):
                    fw_bin = os.path.join(fw_path, fw.replace(".framework", ""))
                    if os.path.isfile(fw_bin):
                        binaries_to_sign.append(fw_bin)
                elif fw.endswith(".dylib"):
                    binaries_to_sign.append(fw_path)

        plugins_dir = os.path.join(app_path, "PlugIns")
        if os.path.isdir(plugins_dir):
            for plug in os.listdir(plugins_dir):
                plug_path = os.path.join(plugins_dir, plug)
                if plug.endswith(".appex"):
                    plug_info = os.path.join(plug_path, "Info.plist")
                    if os.path.exists(plug_info):
                        with open(plug_info, "rb") as f:
                            pinfo = plistlib.load(f)
                        plug_bin = pinfo.get("CFBundleExecutable", "")
                        plug_bin_path = os.path.join(plug_path, plug_bin)
                        if os.path.isfile(plug_bin_path):
                            binaries_to_sign.append(plug_bin_path)

        # Sign frameworks/appex first, then main binary
        framework_bins = [b for b in binaries_to_sign if b != main_binary]
        all_ok = True
        for bin_path in framework_bins:
            if not sign_binary(bin_path, identity, ent_path):
                all_ok = False
        if not sign_binary(main_binary, identity, ent_path):
            all_ok = False

        if not all_ok:
            print("[WARN] Some binaries failed to sign")

        # Step 4: Re-package IPA
        print(f"[INFO] Packaging -> {output_path}")
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(tmpdir):
                for f in files:
                    fpath = os.path.join(root, f)
                    arcname = os.path.relpath(fpath, tmpdir)
                    zf.write(fpath, arcname)

        # Verify
        result = subprocess.run(
            ["codesign", "-v", main_binary], capture_output=True, text=True,
        )
        if result.returncode == 0:
            print("[OK] Verification passed")
        else:
            print(f"[WARN] Verification: {result.stderr.strip()[:200]}")

        print(f"[DONE] Signed IPA: {output_path}")
        return output_path

    except Exception as e:
        print(f"[ERROR] Auto-sign failed: {e}")
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI entry (standalone usage)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="iOS Utility Tools - Symbol restoration & Auto signing"
    )
    sub = parser.add_subparsers(dest="command")

    sym_parser = sub.add_parser("symbolicate",
                                help="Symbolicate crash reports")
    sym_parser.add_argument("--ipa", required=True, help="Path to IPA")
    sym_parser.add_argument("--crash-dir", required=True,
                            help="Directory with .ips crash reports")
    sym_parser.add_argument("--output-dir", default="./symbolicated",
                            help="Output directory")

    sign_parser = sub.add_parser("sign", help="Auto-sign IPA")
    sign_parser.add_argument("--ipa", required=True, help="Path to IPA")
    sign_parser.add_argument("--output", default=None,
                             help="Output IPA path")
    sign_parser.add_argument("--entitlements", default=None,
                             help="Extra entitlements (comma-separated)")
    sign_parser.add_argument("--identity", default=None,
                             help="Signing identity")

    args = parser.parse_args()

    if args.command == "symbolicate":
        symbolicate_all_reports(args.crash_dir, args.ipa, args.output_dir)
    elif args.command == "sign":
        extra = (args.entitlements.split(",") if args.entitlements
                 else DEFAULT_EXTRA_ENTITLEMENTS)
        auto_sign_ipa(args.ipa, args.output, extra, args.identity)
    else:
        parser.print_help()
