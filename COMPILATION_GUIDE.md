# StormCracker GUI Compilation Guide

This guide provides step-by-step instructions for compiling the StormCracker GUI into a standalone executable for Linux and Windows, as well as creating the final Windows installer (`WinCracker_Setup.exe`).

## Prerequisites (Both OS)
Ensure you have the required Python packages installed:
```bash
pip install customtkinter pyinstaller
```

---

## 🚀 Automated Cloud Compilation (GitHub Actions)

This repository is equipped with a complete CI/CD pipeline. You do **not** need to compile anything manually if you don't want to!

Every time you push code to the `main` branch on GitHub:
1. GitHub Actions will automatically spin up Linux and Windows servers.
2. It will compile the Linux binaries and package them into a professional `.deb` installer.
3. It will download the Hashcat binaries, compile the Windows GUI, and package everything into `WinCracker_Setup.exe`.
4. It will instantly publish these files to the **Releases** tab on your GitHub repository.

If you wish to compile them manually, follow the steps below.

---

## 1. Manual Compiling for Linux (Kali / Ubuntu)

Because Linux natively has Hashcat available in the package manager, we do **not** need to embed a heavy Hashcat binary or Wordlist into the executable. The script is smart enough to find them dynamically on the system.

1. Open your terminal in the project directory.
2. Run the PyInstaller command to create a standalone Linux binary:
   ```bash
   pyinstaller --noconfirm --onefile --windowed win_cracker.py
   ```
3. Once finished, you will find a compiled binary named `win_cracker` inside the `dist/` directory.
4. You can rename this file to `storm_cracker_gui` and move it to `/usr/local/bin/` if you want to run it from anywhere.

---

## 2. Manual Compiling for Windows (The Setup Installer)

For Windows, we use a two-step professional deployment approach. First, we compile a lightweight GUI executable. Then, we use Inno Setup to bundle it together with the Hashcat engine and Wordlist into a proper Windows installer.

### Step 2A: Compile the Lightweight Windows GUI
*(Run this step on your Windows machine)*

1. Open a command prompt in the folder containing `win_cracker.py`.
2. Run PyInstaller **without** embedding the data files (this keeps the `.exe` blazing fast):
   ```cmd
   pyinstaller --noconfirm --onefile --windowed win_cracker.py
   ```
3. This will create a tiny `win_cracker.exe` file in the `dist\` directory.

### Step 2B: Create the Professional `WinCracker_Setup.exe` Installer
*(Run this step on your Windows machine)*

1. Download and install **Inno Setup** (it is free).
2. Gather all the required assets into your project directory. It should look exactly like this:
   - `win_cracker.py`
   - `setup.iss`
   - `dist\win_cracker.exe` (from Step 2A)
   - `hashcat.exe` (and its required folders: `OpenCL\`, `modules\`, `charsets\`)
   - `rockyou.txt`
3. Double-click the `setup.iss` file to open it in Inno Setup.
4. Click the **Compile** button (or press `Ctrl+F9`).
5. Inno Setup will instantly compress all the files and generate a beautiful `WinCracker_Setup.exe` in the `Output\` folder.

### Deployment
You can now give `WinCracker_Setup.exe` to anyone. When they double-click it, it will launch a classic installation wizard, permanently extract the engine and wordlist to `%localappdata%\WinCracker`, and put a convenient shortcut on their Desktop!
