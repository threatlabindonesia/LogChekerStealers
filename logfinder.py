import os
import argparse
import json
import csv
from openpyxl import Workbook
from tqdm import tqdm
import re
import sys
from datetime import datetime
import fnmatch


# Memastikan output tidak tertahan
sys.stdout.reconfigure(encoding='utf-8')
sys.stdout.flush()

BANNER = r"""
   ____        __           ___      _       
  / __ \____ _/ /_____     /   |____(_)____ _
 / / / / __ `/ __/ __ \   / /| / ___/ / ___/ 
/ /_/ / /_/ / /_/ /_/ /  / ___ / /  / (__  ) 
\____/\__,_/\__/\____/  /_/  |_/_/  /_/____/  

        ⚡️ LogFinder Enhanced by Om Apip ⚡️
"""

def print_banner():
    print(BANNER)
    sys.stdout.flush()

class BannerArgumentParser(argparse.ArgumentParser):
    def print_help(self):
        print_banner()
        super().print_help()

def load_keywords_from_file(file_path):
    print(f"📖 Loading keywords from file: {file_path}")
    sys.stdout.flush()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            keywords = [line.strip().lower() for line in f if line.strip()]
        print(f"✅ Loaded {len(keywords)} keywords successfully")
        sys.stdout.flush()
        return keywords
    except Exception as e:
        print(f"❌ Error loading keywords: {e}")
        sys.stdout.flush()
        return []

import os
import re
from datetime import datetime
import sys

def extract_system_info(dir_path, cache={}):
    if dir_path in cache:
        return cache[dir_path]

    print(f"🔍 Extracting system info for folder: {dir_path}")
    sys.stdout.flush()
    system_info = {
        "device_name": "Unknown",
        "device_username": "Unknown",
        "threat_name": "Unknown",
        "install_date": "Unknown",
        "compromised_date": "Unknown"
    }
    system_files_found = False

    # Perluas pola untuk mencakup file seperti "passwords.txt"
    is_password_dir = any(
        re.search(r"(all\s*pass[\w\s_-]*\.txt$|passwords?\.txt$)", f.name, re.IGNORECASE)
        for f in os.scandir(dir_path)
        if f.is_file()
    )
    # Selalu cek dir_path terlebih dahulu, lalu cek parent hanya jika bukan direktori kata sandi
    scan_dirs = [dir_path] if is_password_dir else [dir_path, os.path.dirname(dir_path)]

    try:
        for scan_dir in scan_dirs:
            print(f"🔎 Scanning directory: {scan_dir}")
            sys.stdout.flush()
            for f in os.scandir(scan_dir):
                if f.is_file() and f.name.lower().endswith((".txt", ".log", ".json")) and re.search(r"(system|information|device|config)", f.name.lower()):
                    print(f"📄 Found potential system file: {f.name}")
                    sys.stdout.flush()
                    system_files_found = True
                    with open(f.path, 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()
                        lines = [line.strip() for line in content.split('\n') if line.strip()]

                        patterns = {
                            "device_name": re.compile(
                                r"(?:computer|computer name|machineid|device name|hostname|system summary\s*-\s*computer name)\s*[:=\-]\s*(.+)", 
                                re.IGNORECASE
                            ),
                            "device_username": re.compile(
                                r"(?:user|username|user name|device user|login|system summary\s*-\s*username)\s*[:=\-]\s*(.+)", 
                                re.IGNORECASE
                            ),
                            "install_date": re.compile(
                                r"(?:install|installed|installation|install date|installation date)\s*(?:date|time)?\s*[:=\-]\s*([\d\-:\s\.]+)", 
                                re.IGNORECASE
                            ),
                            "compromised_date": re.compile(
                                r"(?:threat|malware|stealer|infection|rat|trojan|locale date|local date|local time)\s*[:=\-]\s*([\d\-:\s\.]+)", 
                                re.IGNORECASE
                            ),
                            # Pola alternatif untuk system_info.txt dengan fleksibilitas lebih
                            "device_name_alt": re.compile(
                                r"^\s*-\s*Computer\s*Name\s*:\s*([^\r\n]+?)\s*$", 
                                re.IGNORECASE
                            ),
                            "device_username_alt": re.compile(
                                r"^\s*-\s*UserName\s*:\s*([^\r\n]+?)\s*$", 
                                re.IGNORECASE
                            ),
                            "compromised_date_alt": re.compile(
                                r"^\s*-\s*Local\s*Time\s*:\s*([\d\-:\s\.]+?)\s*$", 
                                re.IGNORECASE
                            ),
                            # Pola untuk install_date dari versi aplikasi atau OS
                            "install_date_alt": re.compile(
                                r"OS\s*:\s*[\d\.]+\s*\(Build\s*(\d+)\)", 
                                re.IGNORECASE
                            ),
                        }

                        for line in lines:
                            print(f"🔎 Processing line: {line}")  # Debugging
                            for key, pattern in patterns.items():
                                match = pattern.search(line)
                                if match:
                                    target_key = key.replace("_alt", "")
                                    system_info[target_key] = match.group(1).strip()
                                    print(f"✅ Matched {target_key}: {system_info[target_key]}")  # Debugging

                        # Deteksi threat name dari konten
                        all_content = content.lower()
                        threat_candidates = ["lumma", "redline", "stealc", "raccoon", "vidar"]
                        for malware in threat_candidates:
                            if malware in all_content:
                                system_info["threat_name"] = malware.capitalize()
                                print(f"✅ Detected threat: {system_info['threat_name']}")  # Debugging
                                break
                        # Deteksi proses mencurigakan
                        if system_info["threat_name"] == "Unknown":
                            suspicious_processes = [
                                "infatica_agent.exe", "ai.exe", "bgm.exe", "rasvc.exe", 
                                "desvchost.exe", "sxhost.exe", "sdkhost.exe", "e_yatilue.exe"
                            ]
                            for proc in suspicious_processes:
                                if proc.lower() in all_content:
                                    system_info["threat_name"] = f"Potential Malware (Process: {proc})"
                                    print(f"✅ Detected suspicious process: {proc}")  # Debugging
                                    break

                    break
            if system_files_found:
                break

        if not system_files_found:
            print(f"⚠️ No system file containing 'system', 'information', 'device', or 'config' found in {scan_dirs}")
            sys.stdout.flush()
            folder_name = os.path.basename(dir_path).lower()
            system_info["device_name"] = folder_name.split('_')[0] if '_' in folder_name else "Unknown"
            system_info["install_date"] = datetime.fromtimestamp(os.path.getctime(dir_path)).strftime("%Y-%m-%d %H:%M:%S")
            system_info["compromised_date"] = datetime.fromtimestamp(os.path.getmtime(dir_path)).strftime("%Y-%m-%d %H:%M:%S")
            for malware in ["lumma", "redline", "stealc", "raccoon", "vidar"]:
                if malware in folder_name:
                    system_info["threat_name"] = malware.capitalize()

    except Exception as e:
        print(f"⚠️ Error in system info for {dir_path}: {e}")
        sys.stdout.flush()

    cache[dir_path] = system_info
    print(f"✅ System info extracted for: {dir_path} -> {system_info}")
    sys.stdout.flush()
    return system_info

def map_filesystem(base_path):
    all_folders = []
    all_txt_files = []

    print(f"📂 Starting filesystem mapping for: {base_path}")
    sys.stdout.flush()

    start_time = datetime.now()

    # Cek di direktori utama
    if os.path.isdir(base_path):
        root_files = os.listdir(base_path)
        all_folders.append(base_path)
        for f in root_files:
            full_path = os.path.join(base_path, f)
            if os.path.isfile(full_path) and re.search(r"all\s*pass[\w\s_-]*\.txt$", f, re.IGNORECASE):
                print(f"📝 Found 'All Password(s).txt' in: {base_path} -> {f}")
                sys.stdout.flush()
                all_txt_files.append(full_path)
                print(f"✅ Mapping complete. Total folders: {len(all_folders)}, Total files: {len(all_txt_files)}")
                sys.stdout.flush()
                return all_folders, all_txt_files  # Stop jika ditemukan file prioritas

    # Tidak ditemukan di direktori utama, lanjutkan rekursif
    for root, dirs, files in os.walk(base_path, topdown=True):
        all_folders.append(root)

        # Jika di folder ini ada file "All Password*.txt", proses dan skip subfolder
        for f in files:
            if re.search(r"all\s*pass[\w\s_-]*\.txt$", f, re.IGNORECASE):
                print(f"📝 Found 'All Password(s).txt' in: {root} -> {f}")
                sys.stdout.flush()
                all_txt_files.append(os.path.join(root, f))
                dirs[:] = []  # Skip subfolder karena sudah prioritas
                break  # Cukup satu temuan prioritas

        else:
            # Jika tidak ada All Password, cari file password biasa
            for f in files:
                if "password" in f.lower() and f.lower().endswith(".txt") and not re.search(r"all\s*pass[\w\s_-]*\.txt$", f, re.IGNORECASE):
                    print(f"📝 Found 'Password' variant in: {root} -> {f}")
                    sys.stdout.flush()
                    all_txt_files.append(os.path.join(root, f))

    print(f"✅ Mapping complete. Total folders: {len(all_folders)}, Total files: {len(all_txt_files)}")
    sys.stdout.flush()
    return all_folders, all_txt_files

def search_keywords_in_txt_files(base_path, keywords):
    all_folders, all_txt_files = map_filesystem(base_path)
    print(f"📘 Total folders mapped: {len(all_folders)}\n")
    sys.stdout.flush()
    
    print(f"📑 Total password-related files to scan: {len(all_txt_files)}\n")
    print("Starting file scanning...")
    sys.stdout.flush()
    
    url_pattern = re.compile(r"URL:\s*(https?://\S+)", re.IGNORECASE)
    user_pattern = re.compile(r"(?:USER|USERNAME|Login|USR|login)\s*:\s*([^\n]+)", re.IGNORECASE)
    passwd_pattern = re.compile(r"(?:PASS|password)\s*:\s*([^\n]+)", re.IGNORECASE)
    
    results = []
    with tqdm(total=len(all_txt_files), desc="🔍 Scanning files", unit="file", mininterval=0, dynamic_ncols=True, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} files [{percentage:3.0f}%]") as pbar:
        for file_path in all_txt_files:
            print(f"🔎 Scanning file: {os.path.basename(file_path)}")
            sys.stdout.flush()
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()  # Simpan konten asli
                    content_lower = content.lower()  # Gunakan copy lowercase untuk pencocokan keyword
                    dir_path = os.path.dirname(file_path)
                    keyword = keywords[0]  # Ambil keyword pertama (misalnya polri.co.id)
                    # Pencocokan fleksibel untuk substring
                    matches = re.finditer(rf"{re.escape(keyword.replace('%', '.*'))}", content_lower)
                    has_keyword = False
                    for match in matches:
                        has_keyword = True
                        print(f"✅ Keyword '{keyword}' found in: {os.path.basename(file_path)} at position {match.start()}")
                        sys.stdout.flush()
                        lines = content.split('\n')
                        i = len(content[:match.start()].split('\n')) - 1  # Indeks baris tempat keyword ditemukan
                        credentials = {"url": "", "username": "", "password": ""}
                        # Perluas jendela pencarian ke 5 baris sebelum/sesudah
                        for j in range(max(0, i-5), min(len(lines), i+6)):
                            check_line = lines[j].strip()
                            url_match = url_pattern.search(check_line)
                            if url_match and not credentials["url"]:
                                credentials["url"] = url_match.group(1)
                            user_match = user_pattern.search(check_line)
                            if user_match and not credentials["username"]:
                                credentials["username"] = user_match.group(1)
                            passwd_match = passwd_pattern.search(check_line)
                            if passwd_match and not credentials["password"]:
                                credentials["password"] = passwd_match.group(1)
                        # Pastikan credential relevan dan simpan untuk setiap kemunculan
                        if any(credentials.values()):
                            sys_info = extract_system_info(dir_path)
                            results.append({
                                "file_path": file_path,
                                "keyword": keyword,
                                "url": credentials["url"],
                                "username": credentials["username"],
                                "password": credentials["password"],
                                **sys_info,
                                "source": os.path.basename(file_path)
                            })
                    if not has_keyword:
                        print(f"🚫 No '{keyword}' found in: {os.path.basename(file_path)}, skipping...")
                        sys.stdout.flush()
            except Exception as e:
                print(f"⚠️ Error reading {file_path}: {e}")
                sys.stdout.flush()
            pbar.update(1)
    return results

def clean_value(value):
    """Hapus karakter ilegal yang tidak didukung oleh Excel tanpa menambahkan tanda kutip depan."""
    if isinstance(value, str):
        illegal_chars = ''.join(map(chr, list(range(0, 9)) + list(range(11, 32)) + [127]))
        cleaned = value.translate(str.maketrans('', '', illegal_chars))
        return cleaned
    return value

def save_results(results, output_path):
    print(f"💾 Saving results to: {output_path}")
    sys.stdout.flush()
    ext = os.path.splitext(output_path)[1].lower()
    try:
        if ext == ".xlsx":
            wb = Workbook()
            ws = wb.active
            ws.title = "LogFinder Results"
            ws.append(["File Path", "Keyword", "URL", "Username/Email", "Password", 
                       "Device Name", "Device Username", "Threat Name", 
                       "Install Date", "Compromised Date", "Source"])
            for r in results:
                cleaned_row = [clean_value(r.get(field, "")) for field in ["file_path", "keyword", "url", "username", "password",
                                                                          "device_name", "device_username", "threat_name",
                                                                          "install_date", "compromised_date", "source"]]
                ws.append(cleaned_row)
            wb.save(output_path)
        elif ext == ".json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
        elif ext == ".csv":
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                fieldnames = results[0].keys() if results else []
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    writer.writerow({k: clean_value(v) for k, v in r.items()})
        elif ext == ".txt":
            with open(output_path, "w", encoding="utf-8") as f:
                for r in results:
                    f.write(f"File: {clean_value(r.get('file_path', ''))}\n")
                    f.write(f"Keyword: {clean_value(r.get('keyword', ''))}\n")
                    f.write(f"URL: {clean_value(r.get('url', ''))}\n")
                    f.write(f"Username: {clean_value(r.get('username', ''))}\n")
                    f.write(f"Password: {clean_value(r.get('password', ''))}\n")
                    f.write(f"Device: {clean_value(r.get('device_name', ''))} ({clean_value(r.get('device_username', ''))})\n")
                    f.write(f"Threat: {clean_value(r.get('threat_name', ''))}\n")
                    f.write(f"Install Date: {clean_value(r.get('install_date', ''))}\n")
                    f.write(f"Compromised Date: {clean_value(r.get('compromised_date', ''))}\n")
                    f.write(f"Source: {clean_value(r.get('source', ''))}\n{'-'*80}\n")
        print(f"✅ Results saved successfully to: {output_path}")
        sys.stdout.flush()
    except PermissionError:
        print(f"❌ Failed to save: File '{output_path}' is open or permission denied. Please close the file or change path.")
        sys.stdout.flush()
    except Exception as e:
        print(f"⚠️ Error saving results: {e}")
        sys.stdout.flush()

def main():
    parser = BannerArgumentParser(description="LogFinder Enhanced by Om Apip")
    parser.add_argument("-p", "--path", required=True, help="Directory path to scan")
    parser.add_argument("-k", "--keywords", nargs='+', help="Keywords to search (space separated)")
    parser.add_argument("-kf", "--keywords-file", help="File containing keywords (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output file path (.txt, .csv, .json, .xlsx)")
    args = parser.parse_args()

    print_banner()
    start_time = datetime.now()
    print(f"🕒 Process started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    sys.stdout.flush()

    if args.keywords_file:
        keywords = load_keywords_from_file(args.keywords_file)
        if not keywords:
            print("❌ Process aborted: No keywords loaded.")
            sys.stdout.flush()
            return
    elif args.keywords:
        keywords = [kw.lower() for kw in args.keywords]
        print(f"📖 Loaded {len(keywords)} keywords from CLI")
    else:
        print("❌ ERROR: Please provide keywords using -k or -kf")
        sys.stdout.flush()
        return

    print(f"📂 Scanning path: {args.path}\n")
    sys.stdout.flush()
    results = search_keywords_in_txt_files(args.path, keywords)

    if results:
        save_results(results, args.output)
    else:
        print("🚫 No results found.")
        sys.stdout.flush()

    end_time = datetime.now()
    print(f"⏱️ Process completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏳ Total time taken: {end_time - start_time}")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
