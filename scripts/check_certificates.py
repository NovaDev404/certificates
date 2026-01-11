#!/usr/bin/env python3
import os
import requests
from pathlib import Path
from datetime import datetime
import re
import sys

def parse_api_date(date_str):
    """Parse dates like 'Aug 25 01:31:00 2025 GMT' robustly into a datetime.
    Returns a datetime or None if it can't parse.
    """
    if not date_str:
        return None

    # Try a regex to normalize day to zero-padded form (handles single-digit days
    # that may be represented with one space: 'Aug  5 01:31:00 2025 GMT')
    m = re.match(r'([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+GMT', date_str)
    if not m:
        return None

    month_abbr, day, timepart, year = m.groups()
    day = day.zfill(2)  # ensure two digits
    normalized = f"{month_abbr} {day} {timepart} {year} GMT"

    try:
        return datetime.strptime(normalized, "%b %d %H:%M:%S %Y GMT")
    except ValueError:
        return None

def earliest_of_strings(a_str, b_str):
    """Return the string (a_str or b_str) whose parsed datetime is earlier.
    If both parse, compare datetimes. If only one parses, prefer the parsed one.
    If neither parse, fall back to lexicographical comparison.
    If one is empty, return the other.
    """
    if not a_str and not b_str:
        return ""
    if not a_str:
        return b_str
    if not b_str:
        return a_str

    a_dt = parse_api_date(a_str)
    b_dt = parse_api_date(b_str)

    if a_dt and b_dt:
        return a_str if a_dt < b_dt else b_str
    if a_dt and not b_dt:
        return a_str
    if b_dt and not a_dt:
        return b_str

    # fallback (should be rare): lexical
    return a_str if a_str < b_str else b_str

def latest_of_strings(a_str, b_str):
    """Return the string (a_str or b_str) whose parsed datetime is later.
    Same fallback strategy as earliest_of_strings.
    """
    if not a_str and not b_str:
        return ""
    if not a_str:
        return b_str
    if not b_str:
        return a_str

    a_dt = parse_api_date(a_str)
    b_dt = parse_api_date(b_str)

    if a_dt and b_dt:
        return a_str if a_dt > b_dt else b_str
    if a_dt and not b_dt:
        return a_str
    if b_dt and not a_dt:
        return b_str

    # fallback: lexical
    return a_str if a_str > b_str else b_str

def get_certificate_status(cert_name):
    """Call your API to get certificate status and parse response."""
    cert_dir = Path(cert_name)

    # Try to find .p12 and .mobileprovision files directly in the folder
    p12_files = list(cert_dir.glob("*.p12"))
    mp_files = list(cert_dir.glob("*.mobileprovision"))

    p12_path = None
    mp_path = None
    password_file = cert_dir / "password.txt"

    # If not found at root, search one level of subfolders and treat those subfolders as the folder
    if not p12_files or not mp_files:
        # look for subdirectories
        subdirs = [d for d in cert_dir.iterdir() if d.is_dir()] if cert_dir.exists() else []
        found = False
        for sub in sorted(subdirs, key=lambda p: p.name):
            sub_p12 = list(sub.glob("*.p12"))
            sub_mp = list(sub.glob("*.mobileprovision"))
            if sub_p12 and sub_mp:
                p12_path = sub_p12[0]
                mp_path = sub_mp[0]
                # prefer password.txt inside subfolder, fall back to parent folder password.txt
                candidate_password = sub / "password.txt"
                password_file = candidate_password if candidate_password.exists() else (cert_dir / "password.txt")
                found = True
                break

        if not found:
            # if still not found, check if maybe only one type exists at root and the other in a subfolder
            # try to pair a p12 in root with mp in a subfolder, or vice versa
            if p12_files:
                # try to find mp in any subfolder
                for sub in sorted(subdirs, key=lambda p: p.name):
                    sub_mp = list(sub.glob("*.mobileprovision"))
                    if sub_mp:
                        p12_path = p12_files[0]
                        mp_path = sub_mp[0]
                        candidate_password = sub / "password.txt"
                        password_file = candidate_password if candidate_password.exists() else (cert_dir / "password.txt")
                        found = True
                        break
            if not found and mp_files:
                for sub in sorted(subdirs, key=lambda p: p.name):
                    sub_p12 = list(sub.glob("*.p12"))
                    if sub_p12:
                        p12_path = sub_p12[0]
                        mp_path = mp_files[0]
                        candidate_password = sub / "password.txt"
                        password_file = candidate_password if candidate_password.exists() else (cert_dir / "password.txt")
                        found = True
                        break

        # If we found paired files via subfolders above, continue; otherwise we'll treat as missing
        if not found and (not p12_files or not mp_files):
            print(f"❌ Missing .p12 or .mobileprovision files for {cert_name}")
            return None
    else:
        # both found at root
        p12_path = p12_files[0]
        mp_path = mp_files[0]
        password_file = cert_dir / "password.txt"

    # Read password.txt or use default
    if password_file.exists():
        try:
            with open(password_file, 'r', encoding='utf-8') as f:
                password = f.read().strip()
        except Exception:
            password = "nezushub.vip"
    else:
        password = "nezushub.vip"

    url = "https://certChecker.novadev.vip/checkCert"

    # Use context manager to ensure files are closed after request
    try:
        with open(p12_path, "rb") as p12f, open(mp_path, "rb") as mpf:
            files = {
                "p12": (p12_path.name, p12f, "application/x-pkcs12"),
                "mobileprovision": (mp_path.name, mpf, "application/octet-stream"),
            }

            data = {
                "password": password
            }

            response = requests.post(url, files=files, data=data, timeout=60)
            response.raise_for_status()
            result = response.json()
    except Exception as e:
        print(f"❌ Error checking {cert_name}: {e}")
        return None

    # Extract p12 and mobileprovision info
    p12_info = result.get("p12", {})
    mp_info = result.get("mobileprovision", {})

    # Use your logic for status emoji and status value
    status_raw = p12_info.get("Status", "") or ""
    status_normalized = status_raw.lower()

    if status_normalized == "signed" or status_normalized == "valid":
        final_status = "Valid"
    elif status_normalized == "revoked":
        final_status = "Revoked"
    else:
        final_status = "Unknown"

    # Dates: keep exactly as returned by API
    cert_effective = p12_info.get("Valid From", "")
    cert_expiration = p12_info.get("Valid To", "")

    mp_effective = mp_info.get("Valid From", "")
    mp_expiration = mp_info.get("Valid To", "")

    # Determine actual effective: latest of cert and mp if both exist
    actual_effective = latest_of_strings(cert_effective, mp_effective)

    # Determine actual expiration: earliest of cert and mp if both exist
    actual_expiration = earliest_of_strings(cert_expiration, mp_expiration)

    return {
        "status": final_status,
        "effective": actual_effective,
        "expiration": actual_expiration,
        "company": cert_name,
        "raw": result
    }

def parse_readme_table(readme_content):
    """Parse the markdown table from README.md."""
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
    """Update the README.md lines with new certificate statuses."""
    updated_lines = lines.copy()

    for cert in certificates:
        idx = cert['line_index']
        row_parts = updated_lines[idx].split('|')

        status = cert.get('status', '').lower()
        status_emoji = '✅' if status == 'valid' else ('❌' if status == 'revoked' else '⚠️')

        # Compose new status cell text with emoji and status word
        if status == 'valid':
            new_status = f"{status_emoji} Signed"
        elif status == 'revoked':
            new_status = f"{status_emoji} Revoked"
        elif status == 'unknown':
            new_status = f"{status_emoji} Status: Unknown"
        else:
            new_status = row_parts[3].strip()

        valid_from = cert.get('valid_from', '').strip() or row_parts[4].strip()
        valid_to = cert.get('valid_to', '').strip() or row_parts[5].strip()

        # Update the row parts with spaces around for neatness
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
    """Update the recommended certificate section dynamically."""
    for i, line in enumerate(lines):
        if 'Recommend Certificate' in line and i + 1 < len(lines):
            if certificates:
                cert = certificates[0]
                status = cert.get('status', '').lower()
                company_name = cert.get('company', 'Unknown Company')
                status_emoji = '✅' if status == 'valid' else ('❌' if status == 'revoked' else '⚠️')
                status_word = "Signed" if status == 'valid' else ("Revoked" if status == 'revoked' else "Unknown")
                lines[i + 1] = f"**{company_name} - {status_emoji} {status_word}**"
    return lines

def main():
    # Read README.md
    try:
        with open('README.md', 'r', encoding='utf-8') as f:
            readme_content = f.read()
    except FileNotFoundError:
        print("README.md not found")
        sys.exit(1)

    certificates, lines = parse_readme_table(readme_content)

    if not certificates:
        print("No certificates found in README.md")
        return

    print(f"Found {len(certificates)} certificates in README.md")

    updated_certs = []
    for cert_info in certificates:
        company = cert_info['company']
        print(f"Checking {company}...")

        result = get_certificate_status(company)
        if result:
            cert_info['status'] = result['status']
            cert_info['valid_from'] = result['effective']
            cert_info['valid_to'] = result['expiration']
            updated_certs.append(cert_info)

            status_emoji = '✅' if result['status'] == 'Valid' else ('❌' if result['status'] == 'Revoked' else '⚠️')
            print(f"  {status_emoji} Status: {result['status']}")
            print(f"  📅 Actual Effective: {result['effective']}")
            print(f"  📅 Actual Expiry: {result['expiration']}")
        else:
            print(f"  ⚠️ Could not check status")
            updated_certs.append(cert_info)

    updated_lines = update_readme_table(updated_certs, lines)
    updated_lines = update_recommended_cert(updated_lines, updated_certs)

    with open('README.md', 'w', encoding='utf-8') as f:
        f.write('\n'.join(updated_lines))

    print("\n✅ README.md updated successfully!")

if __name__ == "__main__":
    main()
