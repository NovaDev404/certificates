#!/usr/bin/env python3
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
    """Clean and normalize values."""
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
    # normalize whitespace and strip
    return [re.sub(r'\s+', ' ', ln).strip() for ln in lines if ln.strip()]

def normalize_status_text(s):
    """Normalize status text by removing emojis and punctuation, converting to lowercase."""
    if not s:
        return ""
    # remove common emoji chars and fancy bullets — keep letters/numbers/spaces
    cleaned = re.sub(r'[^\w\s]', ' ', s)  # replace punctuation/emoji with space
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned.lower()

def parse_html(html):
    """Parse the HTML response from the certificate checker and extract structured info."""
    soup = BeautifulSoup(html, "html.parser")
    
    alert_div = soup.find(lambda tag: tag.name == "div" and tag.get("class") and any("alert" in c for c in tag.get("class")))
    if not alert_div:
        return {"error": "No certificate info found in response"}
    
    lines = lines_from_alert_div(alert_div)
    
    data = {
        "certificate": {
            "raw_status": None,
            "effective": None,
            "expiration": None,
        },
        "mobileprovision": {
            "name": None,
            "raw_status": None,
            "effective": None,
            "expiration": None,
        },
        "binding_certificate_1": {
            "raw_status": None,
            "number_hex": None,
        },
        "raw_lines": lines
    }
    
    def find_index(prefixes, start=0):
        for i in range(start, len(lines)):
            for p in prefixes:
                if lines[i].startswith(p):
                    return i
        return None

    cert_idx = find_index(["CertName:", "CertName：", "CertName"])
    mp_idx = find_index(["MP Name:", "MP Name：", "MP Name", "MP Name:"])
    binding_idx = find_index(["Binding Certificates:", "Binding Certificates：", "Binding Certificates"], start=(mp_idx or 0))
    
    # Parse certificate block (top block: between cert_idx and mp_idx)
    if cert_idx is not None:
        end = mp_idx if mp_idx is not None else (binding_idx if binding_idx is not None else len(lines))
        for ln in lines[cert_idx:end]:
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
                data["certificate"]["raw_status"] = v
    
    # Parse mobileprovision block (between mp_idx and binding_idx)
    if mp_idx is not None:
        end = binding_idx if binding_idx is not None else len(lines)
        for ln in lines[mp_idx:end]:
            k, v = split_kv(ln)
            v = clean_value(v)
            lk = k.lower()
            if lk.startswith("mp name"):
                data["mobileprovision"]["name"] = v
            elif lk.startswith("effective date"):
                data["mobileprovision"]["effective"] = v
            elif lk.startswith("expiration date"):
                data["mobileprovision"]["expiration"] = v

    # Parse binding certificates block (look for Certificate 1 and its inner lines)
    if binding_idx is not None:
        cert1_idx = find_index(["Certificate 1:", "Certificate 1：", "Certificate 1"], start=binding_idx)
        if cert1_idx is not None:
            # read lines after cert1_idx until next certificate or end
            end = find_index(["Certificate 2:", "Certificate 2：", "Certificate 2"], start=cert1_idx+1) or len(lines)
            for ln in lines[cert1_idx+1:end]:
                k, v = split_kv(ln)
                v = clean_value(v)
                lk = k.lower()
                if lk.startswith("certificate status"):
                    data["binding_certificate_1"]["raw_status"] = v
                elif lk.startswith("certificate number (hex)"):
                    data["binding_certificate_1"]["number_hex"] = v

    # Additionally try to pull any inline "Certificate Status:" that might be earlier or later
    for ln in lines:
        if ln.lower().startswith("certificate status"):
            k, v = split_kv(ln)
            v = clean_value(v)
            # prefer top certificate status if not set
            if not data["certificate"].get("raw_status"):
                data["certificate"]["raw_status"] = v

    return data

def get_certificate_status(cert_name):
    """Check the status of a single certificate and compute actual effective/expiry."""
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
        with open(password_file, 'r') as f:
            password = f.read().strip()
    else:
        password = "nezushub.vip"
    
    try:
        with requests.Session() as session:
            token = get_token(session)
            html = submit_check(session, token, p12_path, password, mp_path)
            data = parse_html(html)

            # Raw strings
            cert_raw_status = data.get("certificate", {}).get("raw_status") or ""
            binding_raw_status = data.get("binding_certificate_1", {}).get("raw_status") or ""
            mp_raw_effective = data.get("mobileprovision", {}).get("effective") or ""
            mp_raw_expiration = data.get("mobileprovision", {}).get("expiration") or ""
            cert_raw_effective = data.get("certificate", {}).get("effective") or ""
            cert_raw_expiration = data.get("certificate", {}).get("expiration") or ""

            # Normalize and decide final status
            norm_cert_status = normalize_status_text(cert_raw_status)
            norm_binding_status = normalize_status_text(binding_raw_status)

            good_keywords = {"good", "valid", "active", "match", "match with p12"}
            revoked_keywords = {"revoked", "revok", "revocation", "revocation reason"}

            final_status = "Unknown"
            # prefer top certificate status (CertName block)
            if any(k in norm_cert_status for k in good_keywords):
                final_status = "Valid"
            elif any(k in norm_cert_status for k in revoked_keywords):
                final_status = "Revoked"
            else:
                # if top doesn't tell us, fall back to binding certificate status
                if any(k in norm_binding_status for k in good_keywords):
                    final_status = "Valid"
                elif any(k in norm_binding_status for k in revoked_keywords):
                    final_status = "Revoked"
                else:
                    final_status = "Unknown"

            # parse dates into datetime objects
            cert_eff_dt = cert_raw_effective
            cert_exp_dt = cert_raw_expiration
            mp_eff_dt = mp_raw_effective
            mp_exp_dt = mp_raw_expiration

            # Determine actual effective: latest of (cert eff, mp eff) if both exists
            actual_effective_dt = None
            if cert_eff_dt and mp_eff_dt:
                actual_effective_dt = max(cert_eff_dt, mp_eff_dt)
            elif mp_eff_dt:
                actual_effective_dt = mp_eff_dt
            elif cert_eff_dt:
                actual_effective_dt = cert_eff_dt

            # Determine actual expiry: earliest of (cert exp, mp exp) if both exists
            actual_expiry_dt = None
            if cert_exp_dt and mp_exp_dt:
                actual_expiry_dt = min(cert_exp_dt, mp_exp_dt)
            elif mp_exp_dt:
                actual_expiry_dt = mp_exp_dt
            elif cert_exp_dt:
                actual_expiry_dt = cert_exp_dt

            # Format dates back to strings
            effective_str = actual_effective_dt
            expiration_str = actual_expiry_dt

            # For debugging, you can print raw values:
            # print(f"RAW cert status: {cert_raw_status}, binding: {binding_raw_status}")
            # print(f"cert eff: {cert_raw_effective}, mp eff: {mp_raw_effective}")
            # print(f"cert exp: {cert_raw_expiration}, mp exp: {mp_raw_expiration}")

            return {
                "status": "Valid" if final_status == "Valid" else ("Revoked" if final_status == "Revoked" else "Unknown"),
                "effective": effective_str,
                "expiration": expiration_str,
                "company": cert_name,
                "raw": {
                    "cert_raw_status": cert_raw_status,
                    "binding_raw_status": binding_raw_status,
                    "cert_raw_effective": cert_raw_effective,
                    "cert_raw_expiration": cert_raw_expiration,
                    "mp_raw_effective": mp_raw_effective,
                    "mp_raw_expiration": mp_raw_expiration,
                    "parsed": data
                }
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
        line = lines[i].rstrip('\n')
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
        
        # Update status (preserve emoji formatting where possible)
        if cert.get('status', '').lower() == 'valid':
            new_status = '✅ Signed'
        elif cert.get('status', '').lower() == 'revoked':
            new_status = '❌ Revoked'
        elif cert.get('status', '').lower() == 'unknown':
            new_status = '⚠️ Status: Unknown'
        else:
            # Keep existing status if not determined
            new_status = row_parts[3].strip()
        
        # Update dates, use existing values if new ones are Unknown
        valid_from = cert.get('valid_from', 'Unknown')
        if not valid_from or valid_from == 'Unknown':
            valid_from = row_parts[4].strip()
        
        valid_to = cert.get('valid_to', 'Unknown')
        if not valid_to or valid_to == 'Unknown':
            valid_to = row_parts[5].strip()
        
        # Reconstruct row with proper spacing
        # row_parts indices: 0: '', 1: Company, 2: Type, 3: Status, 4: Valid From, 5: Valid To, 6: Download (if present)
        # but because we split on '|' directly, maintain consistent indices
        # set status cell (index 3)
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
    """Update the recommended certificate section if applicable."""
    for i, line in enumerate(lines):
        if 'Recommend Certificate' in line and i + 1 < len(lines):
            next_line = lines[i + 1].strip()
            # example logic: if your README expects a specific recommended cert, update its status text
            for cert in certificates:
                if 'China Telecommunications Corporation V2' in cert.get('company', ''):
                    status = cert.get('status', '').lower()
                    if status == 'valid':
                        lines[i + 1] = f"**China Telecommunications Corporation V2 - ✅ Signed**"
                    elif status == 'revoked':
                        lines[i + 1] = f"**China Telecommunications Corporation V2 - ❌ Revoked**"
                    else:
                        lines[i + 1] = f"**China Telecommunications Corporation V2 - ⚠️ Status: Unknown**"
                    break
    return lines

def main():
    # Read README.md
    with open('README.md', 'r', encoding='utf-8') as f:
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
        
        result = get_certificate_status(company)
        if result:
            # Update cert info with new status
            cert_info['status'] = result['status']
            cert_info['valid_from'] = result['effective']
            cert_info['valid_to'] = result['expiration']
            updated_certs.append(cert_info)
            
            status_emoji = '✅' if result['status'] == 'Valid' else ('❌' if result['status'] == 'Revoked' else '⚠️')
            print(f"  {status_emoji} Status: {result['status']}")
            print(f"  📅 Actual Effective: {result['effective']}")
            print(f"  📅 Actual Expiry: {result['expiration']}")
        else:
            print(f"  ⚠️  Could not check status")
            # Keep existing values
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
