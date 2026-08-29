# MetaVenom-Injector
Code Reference File - Summary & Analysis

📋 General Overview

This code is a Payload Module for Metasploit Framework, designed to create backdoored APK files for Android penetration testing. It injects a malicious payload into existing Android applications.

---

🎯 Purpose of Replacement

This file will replace:

```
/usr/share/metasploit-framework/lib/msf/core/payload/apk.rb
```

Reason: Provides advanced injection capabilities compared to the original version.

---

🔑 Key Functions

1. Finding Hook Points

```ruby
def find_all_hook_points(manifest)
```

· Searches for all suitable locations to inject the payload
· Targets: Application, Activities, Services, Receivers
· New feature: Searches ALL points instead of just one

2. Multi-Injection

```ruby
hook_points.each do |point|
  inject_into_smali_file(smalifile, hookfunction)
end
```

· Original: Injects at a single entry point only
· New: Injects into ALL possible points to increase success rate

3. Priority-Based Injection

Priority Type Description
1 Application Runs first - BEST option
2 Launchable Activity Runs when app opens
3 Regular Activity Secondary option
4 Service Background service
5 Receiver Broadcast receiver

4. Certificate Extraction

```ruby
def extract_cert_data_from_apk_file(path)
```

· Extracts original APK signing certificate
· Maintains original signature to avoid detection
· Uses both keytool (v1) and apksigner (v2/v3)

---

🆚 What's Different from Original?

Feature Original Version New Version
Hook points Single entry ALL available points
Success rate Low (app-specific) High (redundant injection)
Method entry detection Basic Multiple fallback methods
Error handling Limited Comprehensive

---

📁 Modified Source Files

The code modifies these smali files after decompilation:

· smali/com/metasploit/stage/*.smali → Renamed and moved to target package
· AndroidManifest.xml → Permissions and components added
· All smali files containing hook points → Injected with payload call

---

🔧 Dependencies Required

```bash
apktool          # Decompile/Recompile APK
keytool          # Certificate handling (Java)
apksigner        # APK signing (Android SDK)
zipalign         # APK alignment (Android SDK)
java             # Runtime environment
```

---

⚠️ Important Notes

1. Original certificate data is preserved - Makes the backdoored APK appear legitimately signed
2. Injects into EVERY possible component - Ensures payload executes regardless of how app starts
3. Randomized package/class names - Avoids detection by signature-based antivirus
4. Fallback injection methods - If standard entry point not found, tries alternatives

---

📊 Injection Process Flow

```
Original APK → Decompile → Find Hook Points → 
Inject into ALL points → Recompile → Align → 
Sign (preserve original cert) → Backdoored APK
```
