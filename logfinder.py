import os
import argparse
import json
import csv
from openpyxl import Workbook
from tqdm import tqdm

def print_banner():
    banner = r"""
   ____        __           ___      _       
  / __ \____ _/ /_____     /   |____(_)____ _
 / / / / __ `/ __/ __ \   / /| / ___/ / ___/
/ /_/ / /_/ / /_/ /_/ /  / ___ / /  / (__  ) 
\____/\__,_/\__/\____/  /_/  |_/_/  /_/____/  

        🛡️ LogFinder by Om Apip 🛡️
"""
    print(banner)

# Custom ArgumentParser to show banner on --help
class BannerArgumentParser(argparse.ArgumentParser):
    def print_help(self):
        print_banner()
        super().print_help()

def load_keywords_from_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"❌ Error loading keywords from file: {e}")
        return []

def search_keywords_in_txt_files(base_path, keywords):
    results = []
    all_txt_files = []

    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".txt"):
                all_txt_files.append(os.path.join(root, file))

    for file_path in tqdm(all_txt_files, desc="🔎 Processing files"):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for kw in keywords:
                    if kw.lower() in content.lower():
                        results.append({
                            "file_path": file_path,
                            "keyword": kw
                        })
        except Exception as e:
            print(f"[!] Skipped unreadable file: {file_path} ({e})")

    return results

def print_results(results):
    if not results:
        print("\n🚫 No matching results found.")
        return

    print("\n🔍 Found Results:")
    print("=" * 80)
    for i, r in enumerate(results, 1):
        print(f"[{i}] 📄 File   : {r['file_path']}\n    🔑 Keyword: {r['keyword']}\n" + "-" * 80)

def save_results(results, output_path):
    ext = os.path.splitext(output_path)[1].lower()

    if ext == ".txt":
        with open(output_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(f"File: {r['file_path']}\nKeyword: {r['keyword']}\n{'-'*80}\n")
    elif ext == ".csv":
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["file_path", "keyword"])
            writer.writeheader()
            writer.writerows(results)
    elif ext == ".json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
    elif ext == ".xlsx":
        wb = Workbook()
        ws = wb.active
        ws.title = "LogFinder Results"
        ws.append(["File Path", "Keyword"])
        for r in results:
            ws.append([r["file_path"], r["keyword"]])
        wb.save(output_path)
    else:
        print(f"❌ Unsupported output format: {ext}")
        return

    print(f"\n✅ Results saved to: {output_path}")

def main():
    parser = BannerArgumentParser(description="LogFinder by Om Apip")
    parser.add_argument("-p", "--path", required=True, help="Base directory path to scan")
    parser.add_argument("-k", "--keywords", nargs='+', help="Keywords to search (space separated)")
    parser.add_argument("-kf", "--keywords-file", help="File containing keywords (one per line)")
    parser.add_argument("-o", "--output", help="Output file with extension (.txt, .csv, .json, .xlsx)")
    args = parser.parse_args()

    print_banner()

    if args.keywords_file:
        keywords = load_keywords_from_file(args.keywords_file)
        print(f"📖 Loaded {len(keywords)} keywords from file: {args.keywords_file}")
    elif args.keywords:
        keywords = args.keywords
        print(f"🔑 Using keywords from command-line: {', '.join(keywords)}")
    else:
        print("❌ ERROR: Please provide keywords using -k or -kf")
        return

    print(f"📂 Scanning path: {args.path}\n")
    results = search_keywords_in_txt_files(args.path, keywords)

    if args.output:
        save_results(results, args.output)
    else:
        print_results(results)

if __name__ == "__main__":
    main()
