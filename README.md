# 🔍 LogFinder Enhanced

**LogFinder Enhanced** is a powerful Python-based tool designed for digital forensics and incident response. It automates the discovery of credentials and system information within directory structures, helping analysts extract, filter, and correlate data quickly and efficiently.

## ✨ Features

- **Credential Extraction**  
  Parses files like `passwords.txt`, `credentials.txt`, etc., to extract usernames, passwords, and URLs.

- **System Info Parsing**  
  Retrieves metadata like device name, username, threat name (e.g., Lumma, RedLine), installation date, and compromise date from files such as `system_info.txt`.

- **Keyword Filtering**  
  Filters results by specified keywords (e.g., domains like `example.com`), ensuring only relevant credentials are extracted.

- **Flexible Output Formats**  
  Supports export to `.xlsx`, `.csv`, `.json`, and `.txt`.

- **Optimized for Performance**  
  Uses parallel processing and efficient line-by-line file reading to scale across large directories.

---

## 🧰 Requirements

- Python 3.6+
- OS: Windows, Linux, or macOS
- File read/write access to target directories

### 📦 Python Dependencies

Install via:

```bash
pip install openpyxl tqdm
````

---

## 🚀 Installation

```bash
git clone https://github.com/threatlabindonesia/LogChekerStealers.git
cd LogChekerStealers
```

---

## ⚙️ Usage

### Basic Command:

```bash
python logfinder.py -p <directory_path> -k <keyword> -o <output_file>
```

### Arguments:

| Flag               | Description                                                              |
| ------------------ | ------------------------------------------------------------------------ |
| `-p`, `--path`     | Path to directory to scan *(required)*                                   |
| `-k`, `--keywords` | Keywords (e.g., `example.com`). Separate with spaces                     |
| `-kf`              | Path to keyword list file (`.txt`, one keyword per line)                 |
| `-o`, `--output`   | Output path + extension `.xlsx`, `.csv`, `.json`, or `.txt` *(required)* |

### Example:

```bash
python logfinder.py -p /data/logs -k example.com -o results.xlsx
```

### Using Keyword File:

Create `keywords.txt`:

```
example.com
test.org
```

Then run:

```bash
python logfinder.py -p /data/logs -kf keywords.txt -o results.xlsx
```

---

## 📁 Expected Directory Structure

```bash
/data/logs/
├── credentials.txt
├── system_info.txt
```

### Example File Contents:

**credentials.txt**

```
URL: https://login.example.com
USER: john_doe
PASS: securepass123
```

**system\_info.txt**

```
- Computer Name: WORKSTATION-123
- UserName: JohnDoe
- Local Time: 2025-07-27 10:15:30
```

---

## 🧪 Sample Console Output

```bash
⚡️ LogFinder Enhanced ⚡️

🕒 Process started at: 2025-07-27 10:33:00
📂 Scanning path: /data/logs
📝 Found password file: credentials.txt
✅ Keyword 'example.com' found in credentials.txt
✅ Valid URL found: https://login.example.com
📄 Found system info file: system_info.txt
✅ Device: WORKSTATION-123, User: JohnDoe, Compromise: 2025-07-27 10:15:30
💾 Saved to: results.xlsx
⏳ Time taken: 0:00:02.123456
```

---

## 📊 Sample Output (results.xlsx)

| File Path                  | Keyword     | URL                                                    | Username  | Password      | Device Name     | Device Username | Threat Name                             | Install Date | Compromised Date    | Source          |
| -------------------------- | ----------- | ------------------------------------------------------ | --------- | ------------- | --------------- | --------------- | --------------------------------------- | ------------ | ------------------- | --------------- |
| /data/logs/credentials.txt | example.com | [https://login.example.com](https://login.example.com) | john\_doe | securepass123 | WORKSTATION-123 | JohnDoe         | Potential Malware (suspicious\_app.exe) | 19043        | 2025-07-27 10:15:30 | credentials.txt |

---

## 🧾 Notes

* Only URLs matching the keyword(s) will be included.
* `system_info.txt` is expected in the same or parent directory as the password files.
* If the output file is open or locked, please close it or specify a new path.
* The tool uses ThreadPoolExecutor for concurrent processing across multiple files.

---

## 👨‍💻 Author

**Afif Hidayatullah**
Developer of cybersecurity and digital forensics tools.

* [LinkedIn](https://www.linkedin.com/in/afif-hidayatullah)

---

## ⭐️ Star This Repo!

If you find this tool useful, please consider starring ⭐ the repository on GitHub!

```
