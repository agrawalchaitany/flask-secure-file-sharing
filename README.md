# SecureShare

**SecureShare** is a web application designed for **secure file sharing**. It offers a user-friendly interface for uploading, downloading, and managing files with **real-time updates**.

## 🚀 Features

✅ **User Authentication** – Secure login and registration.
✅ **File Upload** – Supports `.pptx`, `.docx`, and `.xlsx` formats.
✅ **File Management** – View, download, and delete files easily.
✅ **Real-Time Updates** – Live updates using Server-Sent Events (SSE).
✅ **Responsive Design** – Mobile-friendly and accessible.
✅ **Role-Based Access** – Different features for **ISOPS** and regular users.

---

## 📌 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/secureshare.git
cd secureshare
```

### 2️⃣ Create a Virtual Environment
```bash
python -m venv venv
# Activate virtual environment
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### 3️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 4️⃣ Set Up the Database
```bash
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
```

### 5️⃣ Run the Application
```bash
flask run
```

### 6️⃣ Access the Application
Open your browser and go to:
```
http://127.0.0.1:5000
```

---

## ⚙️ Configuration

- **Database Settings** – Configure in `config.py`.
- **Environment Variables** – Set:
  ```bash
  export FLASK_APP=app
  export FLASK_ENV=development
  ```
  *(For Windows, use `set` instead of `export`.)*

---

## 📖 Usage Guide

🔹 **Home** – Overview of the application.
🔹 **Files** – Manage your files.
🔹 **Upload** – Upload new files *(ISOPS users only).*
🔹 **Logout** – Securely log out.

---

## 🤝 Contributing

Want to contribute? Follow these steps:

1️⃣ **Fork the Repository**.
2️⃣ **Create a Branch**:
   ```bash
   git checkout -b feature/your-feature
   ```
3️⃣ **Commit Changes**:
   ```bash
   git commit -m "Add your feature"
   ```
4️⃣ **Push to Branch**:
   ```bash
   git push origin feature/your-feature
   ```
5️⃣ **Open a Pull Request** on GitHub.

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 📧 Contact

For questions or support, reach out to: **[agrawalchaitany@gmail.com]**

---

✨ *Feel free to customize this README with your details, repository URL, and additional instructions!*