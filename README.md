# MetaVenom-Injector

## 📌 Overview
Patches and modifications for Metasploit to enhance Android penetration testing experience.

## 🔧 Key Improvements
- **Multi-point injection** - Injects payload into ALL possible hook points (Application, Activities, Services, Receivers) instead of just one
- **Priority-based targeting** - Application → Launchable Activity → Regular Activity → Service → Receiver
- **Certificate preservation** - Extracts and maintains original APK signatures (v1, v2, v3) to avoid detection
- **Fallback methods** - Multiple injection strategies if primary entry points fail

## 💥 Dual Payload Strategy
- **apk.rb** - Injects into multiple hook points, establishing multiple concurrent sessions
- **classes.dex** - Creates a new session every 30 seconds while the app runs
- **Combined** - Overwhelming number of sessions with continuous new session generation

## 📁 Installation
Clone the repository:

```bash
git clone https://github.com/pashamasr01287654800/MetaVenom-Injector.git
cd MetaVenom-Injector
```

📁 Backup & Replace

Important: Before replacing, backup the original files:

```bash
# Backup original apk.rb
sudo cp /usr/share/metasploit-framework/lib/msf/core/payload/apk.rb /usr/share/metasploit-framework/lib/msf/core/payload/apk.rb.bak

# Backup original classes.dex
sudo cp /usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/metasploit-payloads-2.0.83/data/android/apk/classes.dex /usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/metasploit-payloads-2.0.83/data/android/apk/classes.dex.bak
```

Then replace with the new files:

```bash
# Replace apk.rb
sudo cp apk.rb /usr/share/metasploit-framework/lib/msf/core/payload/apk.rb

# Replace classes.dex
sudo cp classes.dex /usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/metasploit-payloads-2.0.83/data/android/apk/
```

To restore the original files anytime:

```bash
# Restore apk.rb
sudo cp /usr/share/metasploit-framework/lib/msf/core/payload/apk.rb.bak /usr/share/metasploit-framework/lib/msf/core/payload/apk.rb

# Restore classes.dex
sudo cp /usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/metasploit-payloads-2.0.83/data/android/apk/classes.dex.bak /usr/share/metasploit-framework/vendor/bundle/ruby/3.0.0/gems/metasploit-payloads-2.0.83/data/android/apk/classes.dex
```

🛠️ Manual Modification (Alternative Method)

If you need to manually edit classes.dex:

```bash
# Install smali/baksmali tools
apt update && apt install smali -y

# Decompile classes.dex to smali
baksmali d classes.dex -o smali_out

# Edit smali files in smali_out/ directory as needed

# Recompile back to classes.dex
smali a smali_out -o classes.dex
```

🚀 Features

· Solves connection issues in Android payloads
· Randomized package/class names for AV evasion
· Comprehensive error handling
· Compatible with latest Metasploit Framework

📦 Requirements

· apktool
· keytool (Java)
· apksigner (Android SDK)
· zipalign (Android SDK)
· smali / baksmali (for manual editing)

🔄 Status

Under active development - New features and improvements being added regularly.

🤝 Contributing

If you find this useful and want to contribute, feel free to reach out! Collaboration is welcome.

---

This module provides advanced injection capabilities compared to the original Metasploit APK payload handler.
