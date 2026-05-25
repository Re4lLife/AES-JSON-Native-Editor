# AES JSON Native Editor - Burp Suite Extension

**AES JSON Native Editor** is a Burp Suite extension written in Python that seamlessly intercepts, decrypts, and re-encrypts AES-encrypted JSON payloads on the fly. 

When testing mobile applications or APIs that implement client-side payload encryption, manually decrypting and encrypting payloads for every request and response is tedious. This extension integrates directly into Burp Suite's HTTP Message Editor, providing a native, editable view of the plaintext JSON while handling the cryptographic heavy lifting in the background.

## 🚀 Features
* **Global Configuration Tab:** Easily configure your AES Key, IV, and target parameters from a dedicated top-level tab ("*AES Config*").
* **Targeted or Global Decryption:** Specify exact JSON keys to decrypt (comma-separated) or leave the parameter field blank to recursively attempt decryption on all values.
* **Auto-Encoding Detection:** Automatically detects and decodes Base64 payloads before decryption, and re-encodes them appropriately during encryption.
* **Seamless Editing:** Modifying the JSON in the "*Decrypted JSON*" tab automatically re-encrypts and updates the original raw HTTP request/response.
* **Algorithm:** Standardized for `AES/CBC/PKCS5Padding`.

---

## 🛠 Workflow: How It Works

1. **Configure the Extension:** Once loaded, navigate to the *AES Config* tab at the top of Burp Suite.
2. **Input Keys:** Enter your AES Key and IV in Hexadecimal format.
3. **Set Parameters:** If only specific JSON keys are encrypted (e.g., `{"data": "<encrypted_string>"}`), enter `data` in the parameters field. If multiple keys are encrypted, separate them with commas (e.g., `data, payload, token`). Leave it blank to decrypt everything.
4. **View Traffic:** Send traffic through Burp Proxy or Repeater. If a supported JSON payload is detected, a new **Decrypted JSON** tab will appear in the HTTP Message Editor.
5. **Edit & Send:** Modify the plaintext JSON directly in the "Decrypted JSON" tab. Once you switch tabs or send the request, the extension automatically re-encrypts your modified data, applies Base64 encoding (if it was originally Base64), and rebuilds the HTTP message.

---

## 📦 Prerequisites

Because this extension is written in Python, Burp Suite requires **Jython** to translate the Python code into Java bytecode.

1. Download the **Jython Standalone JAR** file.
   * **Download Link:** [Jython Standalone 2.7.3 (Maven Central)](https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar)
   * *Alternative:* Visit the [official Jython downloads page](https://www.jython.org/download) and ensure you download the **Standalone** version.
2. Save the `.jar` file to an easily accessible location on your machine.

---

## 📥 Installation

### Step 1: Link Jython to Burp Suite
1. Open Burp Suite.
2. Navigate to **Extensions** -> **Extension Settings** (in older versions: **Extender** -> **Options**).
3. Scroll down to the **Python Environment** section.
4. Under **Location of Jython standalone JAR file**, click **Select file...**
5. Locate and select the `jython-standalone-2.7.3.jar` file you downloaded earlier.

### Step 2: Install the Extension
1. Download or clone this repository to get the `AES-JSON-Editor.py` script.
2. In Burp Suite, navigate to **Extensions** -> **Installed** (in older versions: **Extender** -> **Extensions**).
3. Click the **Add** button.
4. In the "Load Burp Extension" dialog:
   * Set **Extension type** to **Python**.
   * Click **Select file...** and choose the `AES-JSON-Editor.py` file.
5. Click **Next**. You should see a blank "Output" tab or a success message, indicating the extension loaded correctly.
6. Look at the top bar of Burp Suite; you will now see the *AES Config* tab ready for use!