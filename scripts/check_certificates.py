#!/usr/bin/env python3
# scripts/check_certificates.py
"""
Checks every certificate folder, calls check-p12.applep12.com,
parses the returned HTML alert block into structured data, updates README.md,
and writes certificates.json with the full certificates array.

Designed to run inside GitHub Actions (or locally).
"""
import re
import requests
import os
import json
from bs4 import BeautifulSoup, NavigableString, Tag
from pathlib import Path
from datetime import datetime
import sys

BASE_URL = "https://check-p12.applep12.com/"

# ---------- Helpers ----------
def get_token(session):
    """Get the CSRF token from the check page."""
    r = session.get(BASE_URL, timeout=20, headers=COMMON_HEADERS)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "__RequestVerificationToken"})
    if not token_input:
        raise RuntimeError("Couldn't find __RequestVerificationToken on page")
    return token_input.get("value")


COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Referer": BASE_URL,
    "Origin": "https://check-p12.applep12.com"
}

def submit_check(session, token, p12_path, p12_password, mp_path):
    """Submit files for checking (multipart form)."""
    files = {
        "P12File": (p12_path.name, open(p12_path, "rb"), "application/x-pkcs12"),
        "MobileProvisionFile": (mp_path.name, open(mp_path, "rb"), "application/octet-stream"),
    }
    data = {
        "P12PassWord": p12_password or "",
        "__RequestVerificationToken": token
    }
    r = session.post(BASE_URL, files=files, data=data, headers=COMMON_HEADERS, timeout=90)
    r.raise_for_status()
    return r.text

def split_kv(line):
    parts = re.split(r'[:：]\s*', line, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return parts[0].strip(), ""

def clean_value(raw):
    if raw is None:
        return ""
    v = re.sub(r'\s+', ' ', raw).strip()
    return v

def lines_from_alert_div(alert_div):
    """Extract text lines from the alert div (split on <br> boundaries)."""
    lines = []
    cur = []
    for node in alert_div.children:
        if isinstance(node, NavigableString):
            txt = str(node).strip()
            if txt:
                cur.append(txt)
        elif isinstance(node, Tag):
            if node.name == "br":
                if cur:
                    joined = " ".join(cur).strip()
                    if joined:
                        lines.append(joined)
                cur = []
            else:
                txt = node.get_text(" ", strip=True)
                if txt:
                    cur.append(txt)
    if cur:
        joined = " ".join(cur).strip()
        if joined:
            lines.append(joined)
    return [re.sub(r'\s+', ' ', ln).strip() for ln in lines if ln.strip()]

def normalize_date(txt):
    """
    Convert strings like:
      "2023-02-08 19:07:10 GMT+08:00"
      "2026-02-07 19:07:09 GMT+08:00"
      "2025-04-09 20:50:26+08:00"
    into ISO-ish "YYYY-MM-DDTHH:MM:SS+08:00" or return original if unknown.
    """
    if not txt:
        return None
    s = txt.strip()
    # Replace 'GMT+08:00' -> '+08:00'
    s = re.sub(r'GMT(?=\+|\-)', '', s)
    s = s.replace('  ', ' ')
    # If there's a timezone like +08:00 at end
    tz_match = re.search(r'([+\-]\d{2}:\d{2})$', s)
    if tz_match:
        tz = tz_match.group(1)
        core = s[: -len(tz)].strip()
        core = core.replace(' ', 'T', 1)
        return f"{core}{tz}"
    # If ends with 'GMT' or no tz provided, fallback to replacing first space with T and append Z
    s2 = s.replace(' ', 'T', 1)
    return s2

# ---------- HTML parsing ----------
def parse_checker_html(html):
    """Return dict with Certificate and ProvisioningProfile structures (best-effort)."""
    soup = BeautifulSoup(html, "html.parser")
    alert_div = soup.find(lambda tag: tag.name == "div" and tag.get("class") and any("alert" in c for c in tag.get("class")))
    if not alert_div:
        return {"error": "No certificate info found in response", "raw_html": html}

    lines = lines_from_alert_div(alert_div)
    # We'll walk lines and capture sections
    cert = {}
    prov = {}
    binding_certs = []

    i = 0
    # helper to get next line safely
    def peek(j):
        return lines[j] if 0 <= j < len(lines) else ""

    # parse whole lines looking for known keys
    while i < len(lines):
        line = lines[i]
        k, v = split_kv(line)
        lk = k.lower()
        val = clean_value(v)

        # Top-level Certificate fields
        if lk.startswith("certname") or lk.startswith("cert name"):
            cert["CertName"] = val
        elif lk.startswith("effective date") and "EffectiveDate" not in cert:
            cert["EffectiveDate"] = normalize_date(val)
        elif lk.startswith("expiration date") and "ExpirationDate" not in cert:
            cert["ExpirationDate"] = normalize_date(val)
        elif lk.startswith("issuer"):
            cert["Issuer"] = val
        elif lk.startswith("country"):
            cert["Country"] = val
        elif lk.startswith("organization"):
            cert["Organization"] = val
        elif re.search(r'certificate number.*hex', k, re.I):
            # top certificate hex
            cert.setdefault("CertificateNumber", {})
            cert["CertificateNumber"]["Hex"] = val
        elif re.search(r'certificate number.*decimal', k, re.I):
            cert.setdefault("CertificateNumber", {})
            cert["CertificateNumber"]["Decimal"] = val
        elif lk.startswith("certificate status"):
            cert["CertificateStatus"] = val
        elif lk.startswith("revocation time"):
            cert["RevocationTime"] = normalize_date(val)

        # Provisioning profile fields
        elif lk.startswith("mp name") or lk.startswith("mpname") or lk.startswith("mp name"):
            prov["MPName"] = val
        elif lk.startswith("app id") or lk.startswith("appid"):
            prov["AppID"] = val
        elif lk.startswith("identifier"):
            prov["Identifier"] = val
        elif lk.startswith("platform"):
            prov["Platform"] = val
        elif lk.startswith("effective date") and "EffectiveDate" not in prov and ("MPName" in prov):
            prov["EffectiveDate"] = normalize_date(val)
        elif lk.startswith("expiration date") and "ExpirationDate" not in prov and ("MPName" in prov):
            prov["ExpirationDate"] = normalize_date(val)
        elif lk.startswith("binding certificates"):
            # parse subsequent certificates blocks
            j = i + 1
            while j < len(lines):
                ln = lines[j]
                if re.match(r'certificate\s*\d+', ln, re.I):
                    # start new binding cert
                    entry = {}
                    j2 = j + 1
                    while j2 < len(lines) and not re.match(r'certificate\s*\d+', lines[j2], re.I):
                        kk, vv = split_kv(lines[j2])
                        kvk = kk.lower()
                        if kvk.startswith("certificate status"):
                            entry["CertificateStatus"] = clean_value(vv)
                        elif re.search(r'certificate number.*hex', kk, re.I):
                            entry.setdefault("CertificateNumber", {})
                            entry["CertificateNumber"]["Hex"] = clean_value(vv)
                        elif re.search(r'certificate number.*decimal', kk, re.I):
                            entry.setdefault("CertificateNumber", {})
                            entry["CertificateNumber"]["Decimal"] = clean_value(vv)
                        else:
                            # break if next major sections appear
                            if re.search(r'certificate matching status|permission status|devices limit', kk, re.I):
                                break
                        j2 += 1
                    binding_certs.append(entry)
                    j = j2
                    continue
                else:
                    # if the line is certificate matching status or permissions etc, break outer parsing
                    if re.search(r'certificate matching status|permission status|devices limit', ln, re.I):
                        break
                j += 1
            i = j - 1  # continue loop after finished binding parsing
        elif lk.startswith("certificate matching status"):
            prov["CertificateMatchingStatus"] = val
        elif lk.startswith("permission status"):
            # collect following permission lines until devices limit or end
            perms = {}
            j = i + 1
            while j < len(lines):
                ln = lines[j]
                if re.search(r'devices limit', ln, re.I):
                    break
                m = re.split(r'[:：]\s*', ln, maxsplit=1)
                if len(m) == 2:
                    perms[m[0].strip()] = m[1].strip()
                j += 1
            prov["PermissionStatus"] = perms
        elif re.search(r'devices limit', line, re.I):
            prov["DevicesLimit"] = clean_value(split_kv(line)[1])
        i += 1

    if binding_certs:
        prov["BindingCertificates"] = binding_certs

    return {"Certificate": cert, "ProvisioningProfile": prov, "raw_lines": lines}

# ---------- folder processing ----------
def get_certificate_folder_list():
    """Assume current working directory contains the certificate folders (repo root)."""
    # We consider top-level directories in repo root excluding .github, scripts, etc.
    root = Path('.')
    ignore = {'.git', '.github', 'scripts', '__pycache__'}
    folders = [p for p in root.iterdir() if p.is_dir() and p.name not in ignore]
    return sorted(folders, key=lambda p: p.name.lower())

def get_password_for_folder(folder: Path):
    p = folder / 'password.txt'
    if p.exists():
        return p.read_text(encoding='utf-8').strip()
    # fallback default used in your original script
    return "nezushub.vip"

def check_one_folder(folder: Path):
    p12_files = list(folder.glob("*.p12"))
    mp_files = list(folder.glob("*.mobileprovision"))

    if not p12_files or not mp_files:
        print(f"Skipping {folder} (missing .p12 or .mobileprovision)")
        return None

    p12_path = p12_files[0]
    mp_path = mp_files[0]
    password = get_password_for_folder(folder)

    print(f"Checking {folder.name} -> {p12_path.name} + {mp_path.name}")
    try:
        with requests.Session() as session:
            token = get_token(session)
            html = submit_check(session, token, p12_path, password, mp_path)
            parsed = parse_checker_html(html)

            # normalise structure into expected JSON schema
            certificate = parsed.get("Certificate", {}) or {}
            provisioning = parsed.get("ProvisioningProfile", {}) or {}

            # ensure certificate number object exists
            if "CertificateNumber" in certificate:
                # try to fill missing Decimal if HTML had it elsewhere in lines
                pass

            entry = {
                "Certificate": {
                    "CertName": certificate.get("CertName"),
                    "EffectiveDate": certificate.get("EffectiveDate"),
                    "ExpirationDate": certificate.get("ExpirationDate"),
                    "Issuer": certificate.get("Issuer"),
                    "Country": certificate.get("Country"),
                    "Organization": certificate.get("Organization"),
                    "CertificateNumber": certificate.get("CertificateNumber", {}),
                    "CertificateStatus": certificate.get("CertificateStatus"),
                    "RevocationTime": certificate.get("RevocationTime")
                },
                "ProvisioningProfile": {
                    "MPName": provisioning.get("MPName"),
                    "AppID": provisioning.get("AppID"),
                    "Identifier": provisioning.get("Identifier"),
                    "Platform": provisioning.get("Platform"),
                    "EffectiveDate": provisioning.get("EffectiveDate"),
                    "ExpirationDate": provisioning.get("ExpirationDate"),
                    "BindingCertificates": provisioning.get("BindingCertificates", []),
                    "CertificateMatchingStatus": provisioning.get("CertificateMatchingStatus"),
                    "PermissionStatus": provisioning.get("PermissionStatus", {}),
                    "DevicesLimit": provisioning.get("DevicesLimit")
                },
                "source": folder.name,
                "raw": parsed.get("raw_lines", [])
            }

            return entry

    except Exception as e:
        print(f"Error checking {folder.name}: {e}")
        return {
            "Certificate": None,
            "ProvisioningProfile": None,
            "source": folder.name,
            "error": str(e)
        }

# ---------- README table parsing/updating (kept from your script) ----------
def parse_readme_table(readme_content):
    lines = readme_content.split('\n')
    table_start = -1
    for i, line in enumerate(lines):
        if line.startswith('| Company | Type | Status |'):
            table_start = i
            break
    if table_start == -1:
        return [], lines
    certificates = []
    for i in range(table_start + 2, len(lines)):
        line = lines[i].rstrip('\n')
        if not line.startswith('|') or line.startswith('|---'):
            break
        cells = [cell.strip() for cell in line.split('|')[1:-1]]
        if len(cells) >= 5:
            cert_info = {
                "company": cells[0],
                "type": cells[1],
                "status": cells[2],
                "valid_from": cells[3],
                "valid_to": cells[4],
                "download": cells[5] if len(cells) > 5 else "",
                "line_index": i
            }
            certificates.append(cert_info)
    return certificates, lines

def update_readme_table(certificates, lines):
    updated_lines = lines.copy()
    for cert in certificates:
        idx = cert['line_index']
        row_parts = updated_lines[idx].split('|')
        if cert.get('status', '').lower() == 'valid':
            new_status = '✅ Signed'
        elif cert.get('status', '').lower() == 'revoked':
            new_status = '❌ Revoked'
        elif cert.get('status', '').lower() == 'unknown':
            new_status = '⚠️ Status: Unknown'
        else:
            new_status = row_parts[3].strip()
        valid_from = cert.get('valid_from', 'Unknown') or row_parts[4].strip()
        valid_to = cert.get('valid_to', 'Unknown') or row_parts[5].strip()
        if len(row_parts) > 3:
            row_parts[3] = f" {new_status} "
        if len(row_parts) > 4:
            row_parts[4] = f" {valid_from} "
        if len(row_parts) > 5:
            row_parts[5] = f" {valid_to} "
        if len(row_parts) > 6:
            row_parts[6] = f" {cert.get('download', row_parts[6].strip())} "
        updated_lines[idx] = '|'.join(row_parts)
    return updated_lines

def update_recommended_cert(lines, certificates):
    for i, line in enumerate(lines):
        if 'Recommend Certificate' in line and i + 1 < len(lines):
            # Grab the recommended certificate name from the next line
            recommended_name = lines[i + 1].strip()
            
            # Find a matching certificate in the certificates list
            matched_cert = next((cert for cert in certificates if recommended_name in cert.get('company', '')), None)
            
            if matched_cert:
                status = matched_cert.get('status', '').lower()
                if status == 'valid':
                    lines[i + 1] = f"**{recommended_name} - ✅ Signed**"
                elif status == 'revoked':
                    lines[i + 1] = f"**{recommended_name} - ❌ Revoked**"
                else:
                    lines[i + 1] = f"**{recommended_name} - ⚠️ Unknown**"
            else:
                lines[i + 1] = f"**{recommended_name} - ⚠️ Unknown**"
                
    return lines

# ---------- Main ----------
def main():
    # find folders
    folders = get_certificate_folder_list()
    print(f"Found {len(folders)} folders to check.")

    all_entries = []
    for folder in folders:
        entry = check_one_folder(folder)
        if entry:
            all_entries.append(entry)

    # Save certificates.json
    out = {"certificates": all_entries}
    with open('certificates.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("Wrote certificates.json with", len(all_entries), "entries.")

    # Update README.md table if present
    readme_path = Path('README.md')
    if readme_path.exists():
        readme_content = readme_path.read_text(encoding='utf-8')
        certs_table, lines = parse_readme_table(readme_content)
        if certs_table:
            # Map table entries by company to updated results by matching folder name (best-effort)
            updated_certs = []
            for ct in certs_table:
                # try to find entry by company name in source
                match = next((e for e in all_entries if e.get('source') and ct['company'].lower() in e['source'].lower()), None)
                if match:
                    status = (match.get('Certificate') or {}).get('CertificateStatus') or "Unknown"
                    valid_from = (match.get('ProvisioningProfile') or {}).get('EffectiveDate') or (match.get('Certificate') or {}).get('EffectiveDate') or "Unknown"
                    valid_to = (match.get('ProvisioningProfile') or {}).get('ExpirationDate') or (match.get('Certificate') or {}).get('ExpirationDate') or "Unknown"
                    ct['status'] = status
                    ct['valid_from'] = valid_from
                    ct['valid_to'] = valid_to
                updated_certs.append(ct)
            updated_lines = update_readme_table(updated_certs, lines)
            updated_lines = update_recommended_cert(updated_lines, updated_certs)
            readme_path.write_text("\n".join(updated_lines), encoding='utf-8')
            print("README.md updated.")
        else:
            print("No table found in README.md; skipping update.")
    else:
        print("README.md not found; skipping README update.")

if __name__ == "__main__":
    main()
