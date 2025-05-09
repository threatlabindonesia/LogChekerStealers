# 🛡️ LogFinder by Om Apip

**LogFinder** is an open-source OSINT tool built by Om Apip to help you quickly scan `.txt` files (often from log-stealer dumps) and search for sensitive keywords such as emails, wallet addresses, credentials, or financial service references. The tool supports multi-format export: `.txt`, `.csv`, `.json`, and `.xlsx`.

---

## 🚀 Features

- ✅ Recursively scan `.txt` files in a given folder
- ✅ Accepts both inline and bulk keyword input (via file)
- ✅ Supports direct terminal output or saving to file
- ✅ Smart export in `.txt`, `.csv`, `.json`, `.xlsx`
- ✅ Built-in progress bar with clean output formatting
- ✅ Supports CLI and executable `.exe` builds for Windows

---

## 🧱 Requirements

- Python 3.7+
- Required libraries:

```bash
pip install tqdm openpyxl
````

---

## ⚙️ Installation

Clone the repo and install dependencies:

```bash
git clone https://github.com/threatlabindonesia/logcheckerstealers.git
cd logfinder
pip install -r requirements.txt
```

Or install manually:

```bash
pip install tqdm openpyxl
```

---

## 📥 Usage

```bash
python logfinder.py -p <path_to_logs> [-k keyword1 keyword2 ...] [-kf keyword_file.txt] [-o output.format]
```

### Arguments:

| Argument                   | Description                                               |
| -------------------------- | --------------------------------------------------------- |
| `-p` or `--path`           | Base directory to scan `.txt` files recursively           |
| `-k` or `--keywords`       | One or more keywords (space separated)                    |
| `-kf` or `--keywords-file` | Path to a `.txt` file with keywords (one per line)        |
| `-o` or `--output`         | Output filename with extension (.txt, .csv, .json, .xlsx) |

---

## 🧪 Example Commands

### 1️⃣ Show results in terminal only:

```bash
python logfinder.py -p ./Downloads/logs -kf keywords.txt
```

### 2️⃣ Save results to Excel:

```bash
python logfinder.py -p ./Downloads/logs -kf keywords.txt -o result.xlsx
```

### 3️⃣ Use direct inline keywords:

```bash
python logfinder.py -p ./Downloads/logs -k binance gmail paypal -o output.json
```

---

## 📝 Sample `keywords.txt`

```
binance
tokocrypto
paypal
gmail
```

---

## 📤 Output Examples

### 🖥 Terminal output (when `-o` is not used)

```
🔍 Found Results:
================================================================================
[1] 📄 File   : logs/dump1/passwords.txt
    🔑 Keyword: binance
--------------------------------------------------------------------------------
[2] 📄 File   : logs/dump2/system_info.txt
    🔑 Keyword: gmail
--------------------------------------------------------------------------------
```

### 📄 Output file examples:

#### `output.txt`

```
File: logs/dump1/passwords.txt
Keyword: binance
--------------------------------------------------------------------------------
File: logs/dump2/system_info.txt
Keyword: gmail
--------------------------------------------------------------------------------
```

#### `output.csv`

| file\_path                  | keyword |
| --------------------------- | ------- |
| logs/dump1/passwords.txt    | binance |
| logs/dump2/system\_info.txt | gmail   |

#### `output.json`

```json
[
  {
    "file_path": "logs/dump1/passwords.txt",
    "keyword": "binance"
  },
  {
    "file_path": "logs/dump2/system_info.txt",
    "keyword": "gmail"
  }
]
```

#### `output.xlsx`

| File Path                   | Keyword |
| --------------------------- | ------- |
| logs/dump1/passwords.txt    | binance |
| logs/dump2/system\_info.txt | gmail   |

---

## 💡 Tips

* Use `--help` to view all available options:

```bash
python logfinder.py --help
```

* You can combine `-k` and `-o`, or use just `-kf` for bulk keyword input.

---

## 👤 Author

**Om Apip**
Cybersecurity & Threat Intelligence Researcher
