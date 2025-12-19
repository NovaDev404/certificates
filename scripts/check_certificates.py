#!/usr/bin/env python3
# updated_cert_check.py
# Full updated script to prefer top-level Certificate Status (e.g. "🟢Good")
# and robustly normalise status values including emoji like "🟢Match With P12".

import re
import requests
import os
import json
from bs4 import BeautifulSoup, NavigableString, Tag
from pathlib import Path
from datetime import datetime
import sys

BASE_URL = "https://check-p12.applep12.com/"

def get_token(session):
    """Get the CSRF token from the check page."""
    r = session.get(BASE_URL, timeout=20)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    token_input = soup.find("input", {"name": "__RequestVerificationToken"})
    if not token_input:
        raise RuntimeError("Couldn't find __RequestVerificationToken on page")
    return token_input.get("value")

def submit_check(session, token, p12_path, p12_password, mp_path):
    """Submit files for checking."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": BASE_URL,
        "Origin": "https://check-p12.applep12.com",
    }

    files = [
        ("P12File", (p12_path.name, open(p12_path, "rb"), "application/x-pkcs12")),
        ("P12PassWord", (None, p12_password)),
        ("MobileProvisionFile", (mp_path.name, open(mp_path, "rb"), "application/octet-stream")),
        ("__RequestVerificationToken", (None, token)),
    ]

    r = session.post(BASE_URL, files=files, headers=headers, timeout=60)
    r.raise_for_status()
    return r.text

def split_kv(line):
    """Split on either ASCII colon ':' or full-width '：' and return (key, value)."""
    parts = re.split(r'[:：]\s*', line, maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return parts[0].strip(), ""

def clean_value(raw):
    """Clean and normalise values."""
    if raw is None:
        return ""
    v = re.sub(r'\s+', ' ', raw).strip()
    return v

def lines_from_alert_div(alert_div):
    """Extract text lines from the alert div, preserving order and br-separated blocks."""
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
                # tag may contain text and emoji spans
                txt = node.get_text(" ", strip=True)
                if txt:
                    cur.append(txt)
    if cur:
        joined = " ".join(cur).strip()
        if joined:
            lines.append(joined)
    # Normalise whitespace
    return [re.sub(r'\s+', ' ', ln).strip() for ln in lines if ln.strip()]

def parse_html(html):
    """
    Parse the HTML response from the certificate checker.
    Returns a dict containing top-level certificate status and binding certificate status, plus MP dates.
    """
    soup = BeautifulSoup(html, "html.parser")
    
    alert_div = soup.find(lambda tag: tag.name == "div" and tag.get("class") and any("alert" in c for c in tag.get("class")))
    if not alert_div:
        return {"error": "No certificate info found in response"}
    
    lines = lines_from_alert_div(alert_div)
    
    data = {
        "certificate": {},
        "mobileprovision": {},
        "binding_certificate_1": {},
    }
    
    def find_index(prefixes, start=0, end=None):
        if end is None:
            end = len(lines)
        for i in range(start, end):
            for p in prefixes:
                if lines[i].startswith(p):
                    return i
        return None

    # Find main certificate block start (CertName)
    cert_idx = find_index(["CertName:", "CertName："])
    # Find MP block start (MP Name)
    mp_idx = find_index(["MP Name:", "MP Name：", "MP Name"])
    # binding certificates start (search from mp_idx)
    binding_idx = None
    if mp_idx is not None:
        binding_idx = find_index(["Binding Certificates:", "Binding Certificates："], start=mp_idx, end=len(lines))
    
    # --- Parse top-level certificate block (between cert_idx and mp_idx) ---
    if cert_idx is not None:
        cert_block_end = mp_idx if mp_idx is not None else (binding_idx if binding_idx is not None else len(lines))
        for ln in lines[cert_idx:cert_block_end]:
            k, v = split_kv(ln)
            v = clean_value(v)
            lk = k.lower()
            if lk.startswith("certname"):
                data["certificate"]["name"] = v
            elif lk.startswith("effective date"):
                data["certificate"]["effective"] = v
            elif lk.startswith("expiration date"):
                data["certificate"]["expiration"] = v
            elif lk.startswith("certificate status"):
                data["certificate"]["status"] = v

    # --- Parse mobileprovision block (dates come from here) ---
    if mp_idx is not None:
        mp_block_end = binding_idx if binding_idx is not None else len(lines)
        for ln in lines[mp_idx:mp_block_end]:
            k, v = split_kv(ln)
            v = clean_value(v)
            lk = k.lower()
            if lk.startswith("mp name"):
                data["mobileprovision"]["name"] = v
            elif lk.startswith("effective date"):
                data["mobileprovision"]["effective"] = v
            elif lk.startswith("expiration date"):
                data["mobileprovision"]["expiration"] = v

    # --- Parse binding certificate 1 block (fallback if top-level missing) ---
    if binding_idx is not None:
        cert1_idx = find_index(["Certificate 1:", "Certificate 1：", "Certificate 1"], start=binding_idx, end=len(lines))
        if cert1_idx is not None:
            # find next certificate 2 or end
            cert2_idx = find_index(["Certificate 2:", "Certificate 2：", "Certificate 2"], start=cert1_idx+1, end=len(lines))
            end = cert2_idx if cert2_idx is not None else len(lines)
            for ln in lines[cert1_idx+1:end]:
                k, v = split_kv(ln)
                v = clean_value(v)
                lk = k.lower()
                if lk.startswith("certificate status"):
                    data["binding_certificate_1"]["status"] = v
                elif lk.startswith("certificate number"):
                    # we don't strictly need the number but keep it if present
                    if "number" not in data["binding_certificate_1"]:
                        data["binding_certificate_1"]["number"] = v

    return data

def strip_emoji_and_misc(s):
    """Remove common emoji, bullets, and extra unicode markers, keep letters/numbers and spaces."""
    if not s:
        return ""
    # Remove coloured circle emojis like 🟢 🟡 🔴 and other common single glyphs
    s = re.sub(r'[\U0001F300-\U0001F6FF\U0001F900-\U0001F9FF\U00002600-\U00002BFF]+', '', s)
    # Remove other stray symbols
    s = re.sub(r'[^\w\s\-\._/():,]', '', s)
    return s.strip()

def normalise_status(raw_status):
    """
    Turn raw status (e.g. "🟢Good", "🟢Match With P12", "Revoked") into canonical categories:
    'Valid', 'Revoked', 'Expired', or 'Unknown'. Also returns cleaned raw for debugging.
    """
    if not raw_status:
        return "Unknown", raw_status or ""
    cleaned = strip_emoji_and_misc(raw_status).lower()
    # direct keyword heuristics
    if any(k in cleaned for k in ("revok", "revoked")):
        return "Revoked", raw_status
    if any(k in cleaned for k in ("expired", "expire")):
        return "Expired", raw_status
    if any(k in cleaned for k in ("good", "valid", "active", "match", "match with p12", "provisions all devices")):
        # "match" might be binding match but still indicates the cert matches the p12; treat as valid fallback only later
        return "Valid", raw_status
    # Unknown
    return "Unknown", raw_status

def convert_to_dd_mm_yy(date_str):
    """Convert date to DD/MM/YY HH:mm format."""
    if not date_str:
        return "Unknown"
    # Remove any timezone indicators or extra text
    ds = re.sub(r'\(.*?\)', '', date_str).strip()
    ds = re.sub(r'GMT[+-]?\d{1,2}[:0-9]*', '', ds).strip()
    
    # List of possible date formats to try
    date_formats = [
        "%m/%d/%y %H:%M",    # 08/02/23 06:07
        "%d/%m/%y %H:%M",    # 02/08/23 06:07
        "%Y/%m/%d %H:%M",    # 2023/08/02 06:07
        "%Y-%m-%d %H:%M:%S", # 2023-08-02 06:07:00
        "%d %b %Y %H:%M",    # 02 Aug 2023 06:07
        "%b %d, %Y %H:%M",   # Aug 02, 2023 06:07
        "%m/%d/%Y %H:%M",    # 08/02/2023 06:07
        "%d/%m/%Y %H:%M",    # 02/08/2023 06:07
        "%Y-%m-%d %H:%M",    # 2023-08-02 06:07
    ]
    
    for fmt in date_formats:
        try:
            dt = datetime.strptime(ds, fmt)
            return dt.strftime("%d/%m/%y %H:%M")
        except ValueError:
            continue
    
    # try regex fallback
    date_patterns = [
        r'(\d{1,2})/(\d{1,2})/(\d{2,4})\s+(\d{1,2}):(\d{2})',
        r'(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})',
        r'(\d{1,2})\s+([A-Za-z]{3,})\s+(\d{4})\s+(\d{1,2}):(\d{2})'
    ]
    for pattern in date_patterns:
        match = re.search(pattern, ds)
        if match:
            try:
                groups = match.groups()
                if len(groups) >= 5:
                    # try to parse in a few ways
                    if len(groups[0]) == 4:  # starts with year
                        year, month, day, hour, minute = groups[:5]
                    else:
                        a, b, c, hour, minute = groups[:5]
                        # guess ordering - try dd/mm/yy heuristics
                        if int(a) > 12:  # dd/mm
                            day, month, year = a, b, c
                        else:
                            month, day, year = a, b, c
                    # normalize year
                    year = int(year)
                    if year < 100:
                        year = 2000 + year if year < 50 else 1900 + year
                    dt = datetime(year, int(month), int(day), int(hour), int(minute))
                    return dt.strftime("%d/%m/%y %H:%M")
            except Exception:
                pass
    return date_str

def get_certificate_status(cert_name, verbose=False):
    """Check the status of a single certificate directory."""
    cert_dir = Path(cert_name)
    
    # Find the .p12 and .mobileprovision files
    p12_files = list(cert_dir.glob("*.p12"))
    mp_files = list(cert_dir.glob("*.mobileprovision"))
    
    if not p12_files or not mp_files:
        print(f"❌ Missing files for {cert_name}")
        return None
    
    p12_path = p12_files[0]
    mp_path = mp_files[0]
    
    # Read password
    password_file = cert_dir / "password.txt"
    if password_file.exists():
        with open(password_file, 'r', encoding='utf-8') as f:
            password = f.read().strip()
    else:
        password = "nezushub.vip"
    
    try:
        with requests.Session() as session:
            token = get_token(session)
            html = submit_check(session, token, p12_path, password, mp_path)
            data = parse_html(html)
            
            # Prefer top-level certificate status, fallback to binding certificate status
            raw_top = data.get("certificate", {}).get("status", "")
            raw_binding = data.get("binding_certificate_1", {}).get("status", "")
            # normalise
            top_norm, top_raw = normalise_status(raw_top)
            bind_norm, bind_raw = normalise_status(raw_binding)
            
            chosen_status = None
            chosen_raw = ""
            # Prefer real top-level statuses that are not Unknown
            if top_norm != "Unknown":
                chosen_status = top_norm
                chosen_raw = top_raw
            elif bind_norm != "Unknown":
                chosen_status = bind_norm
                chosen_raw = bind_raw
            else:
                chosen_status = "Unknown"
                # include best raw info we have
                chosen_raw = raw_top or raw_binding or ""
            
            effective = data.get("mobileprovision", {}).get("effective", data.get("certificate", {}).get("effective", "Unknown"))
            expiration = data.get("mobileprovision", {}).get("expiration", data.get("certificate", {}).get("expiration", "Unknown"))
            
            # Convert dates
            effective = convert_to_dd_mm_yy(effective) if effective and effective != "Unknown" else "Unknown"
            expiration = convert_to_dd_mm_yy(expiration) if expiration and expiration != "Unknown" else "Unknown"
            
            # If Unknown, print debug so you can see raw values
            if chosen_status == "Unknown" or verbose:
                print(f"⚠️ Status: {chosen_status} (raw top: {raw_top!r}, raw binding: {raw_binding!r})")
            
            return {
                "status": chosen_status,
                "effective": effective,
                "expiration": expiration,
                "company": cert_name,
                "raw_status": chosen_raw
            }
            
    except Exception as e:
        print(f"❌ Error checking {cert_name}: {str(e)}")
        return None

def parse_readme_table(readme_content):
    """Parse the markdown table from README.md."""
    lines = readme_content.split('\n')
    table_start = -1
    
    # Find the table header line
    for i, line in enumerate(lines):
        if line.startswith('| Company | Type | Status |'):
            table_start = i
            break
    
    if table_start == -1:
        return [], lines
    
    certificates = []
    # Skip header and separator rows
    for i in range(table_start + 2, len(lines)):
        line = lines[i].strip()
        if not line.startswith('|') or line.startswith('|---'):
            break
        
        # Parse row
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
    """Update the README.md lines with new certificate statuses."""
    updated_lines = lines.copy()
    
    for cert in certificates:
        idx = cert['line_index']
        row_parts = updated_lines[idx].split('|')
        
        # Determine new status string
        s = cert.get('status', '').lower()
        if s == 'valid':
            new_status = '✅ Signed'
        elif s == 'revoked':
            new_status = '❌ Revoked'
        elif s == 'expired':
            new_status = '⚠️ Expired'
        else:
            # preserve existing status cell if Unknown
            new_status = row_parts[3].strip()
        
        # Update dates, use existing values if new ones are Unknown
        valid_from = cert.get('valid_from', 'Unknown')
        if valid_from == 'Unknown':
            valid_from = row_parts[4].strip()
        
        valid_to = cert.get('valid_to', 'Unknown')
        if valid_to == 'Unknown':
            valid_to = row_parts[5].strip()
        
        # Reconstruct row with proper spacing
        # row_parts structure: ['', ' Company ', ' Type ', ' Status ', ' Valid From ', ' Valid To ', ' Download ', ''] maybe
        # we will replace the 3,4,5 positions (indexing as found)
        if len(row_parts) > 3:
            row_parts[3] = f" {new_status} "
        if len(row_parts) > 4:
            row_parts[4] = f" {valid_from} "
        if len(row_parts) > 5:
            row_parts[5] = f" {valid_to} "
        if len(row_parts) > 6 and cert.get('download'):
            row_parts[6] = f" {cert.get('download')} "
        
        updated_lines[idx] = '|'.join(row_parts)
    
    return updated_lines

def update_recommended_cert(lines, certificates):
    """Update the recommended certificate section (example handles China Telecom V2)."""
    for i, line in enumerate(lines):
        if 'Recommend Certificate' in line and i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            if 'China Telecommunications Corporation V2' in next_line:
                for cert in certificates:
                    if 'China Telecommunications Corporation V2' in cert.get('company', ''):
                        status = cert.get('status', '').lower()
                        if status == 'valid':
                            lines[i + 1] = f"**China Telecommunications Corporation V2 - ✅ Signed**"
                        elif status == 'revoked':
                            lines[i + 1] = f"**China Telecommunications Corporation V2 - ❌ Revoked**"
                        else:
                            lines[i + 1] = f"**China Telecommunications Corporation V2 - ⚠️ {cert.get('status', 'Unknown')}**"
                        break
    
    return lines

def main():
    # Read README.md
    readme_path = Path('README.md')
    if not readme_path.exists():
        print("README.md not found in current directory.")
        return
    
    with open(readme_path, 'r', encoding='utf-8') as f:
        readme_content = f.read()
    
    # Parse table
    certificates, lines = parse_readme_table(readme_content)
    
    if not certificates:
        print("No certificates found in README.md")
        return
    
    print(f"Found {len(certificates)} certificates in README.md")
    
    # Check each certificate
    updated_certs = []
    for cert_info in certificates:
        company = cert_info['company']
        print(f"Checking {company}...")
        
        result = get_certificate_status(company, verbose=False)
        if result:
            # Update cert info with new status
            cert_info['status'] = result['status']
            cert_info['valid_from'] = result['effective']
            cert_info['valid_to'] = result['expiration']
            cert_info['raw_status'] = result.get('raw_status', '')
            updated_certs.append(cert_info)
            
            status_emoji = '✅' if result['status'] == 'Valid' else ('❌' if result['status'] == 'Revoked' else ('⚠️' if result['status'] == 'Expired' else '⚠️'))
            print(f"  {status_emoji} Status: {result['status']} (raw: {result.get('raw_status')})")
            print(f"  📅 Valid From: {result['effective']}")
            print(f"  📅 Valid To: {result['expiration']}")
        else:
            print(f"  ⚠️  Could not check status")
            updated_certs.append(cert_info)
    
    # Update the README content
    updated_lines = update_readme_table(updated_certs, lines)
    updated_lines = update_recommended_cert(updated_lines, updated_certs)
    
    # Write back to README.md
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write('\n'.join(updated_lines))
    
    print("\n✅ README.md updated successfully!")

if __name__ == "__main__":
    main()
