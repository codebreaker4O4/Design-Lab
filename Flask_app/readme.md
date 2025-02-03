# 🔍 Vulnerability Scanner

A **Flask-based web application** that scans a given IP address for vulnerabilities using **Nmap** and fetches details from the **Vulners API**.

## 🚀 Features

- Scan a target IP for open ports and running services.
- Identify vulnerabilities using the **Nmap Vulners script**.
- Fetch detailed vulnerability descriptions from the **Vulners API**.
- Display results in a user-friendly **web interface**.

## 🛠️ Tech Stack

- **Backend**: Flask, Nmap, Python
- **Frontend**: HTML, CSS, JavaScript
- **API**: Vulners API

## 📦 Installation

### 1️⃣ Clone the repository

```bash
git clone https://github.com/codebreaker4O4/vulnerability-scanner.git
cd vulnerability-scanner
```

### 2️⃣ Set up a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # For macOS/Linux
venv\Scripts\activate    # For Windows
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Configure the `.env` file

Create a `.env` file in the project directory and add your **Vulners API Key**:

```
VULNERS_API_KEY=your-api-key-here
```

### 5️⃣ Run the application

```bash
python app.py
```

Open your browser and go to:  
👉 `http://127.0.0.1:5000/`

## 📌 Usage

1. Enter the **IP address** of the target system.
2. Click **Scan** to analyze open ports and services.
3. If vulnerabilities are detected, details will be displayed.

## 🛑 Known Issues

- Some vulnerabilities might not be detected if Nmap scripts fail.
- Ensure Nmap is **installed and accessible** in your system.

## 📜 License

This project is **open-source** under the MIT License.

---

💡 **Contributions are welcome!** Feel free to submit issues or pull requests. 🚀
