from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab, ITab
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from java.util import Base64
from java.lang import String
from javax.swing import JPanel, JLabel, JTextField, JButton, BorderFactory
from java.awt import BorderLayout, GridLayout
import json
import re

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AES JSON Native Editor")
        
        self.is_running = True
        self.setup_ui()
        
        callbacks.addSuiteTab(self)
        callbacks.registerMessageEditorTabFactory(self)

    def setup_ui(self):
        self.panel = JPanel(BorderLayout(10, 10))
        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        config_panel = JPanel(GridLayout(5, 2, 10, 10))
        
        config_panel.add(JLabel("AES Key (Hex):"))
        self.key_field = JTextField("")
        config_panel.add(self.key_field)
        
        config_panel.add(JLabel("AES IV (Hex):"))
        self.iv_field = JTextField("")
        config_panel.add(self.iv_field)
        
        config_panel.add(JLabel("Target JSON Keys (comma-separated). Leave blank to decrypt all keys:"))
        self.params_field = JTextField("")
        config_panel.add(self.params_field)
        
        config_panel.add(JLabel("Algorithm:"))
        config_panel.add(JLabel("AES/CBC/PKCS5Padding"))
        
        self.btn_toggle = JButton("Stop Extension", actionPerformed=self.toggle_state)
        config_panel.add(self.btn_toggle)
        config_panel.add(JLabel("")) 
        
        self.panel.add(config_panel, BorderLayout.NORTH)

    def toggle_state(self, event):
        self.is_running = not self.is_running
        if self.is_running:
            self.btn_toggle.setText("Stop Extension")
        else:
            self.btn_toggle.setText("Start Extension")

    def getTabCaption(self):
        return "AES Config"

    def getUiComponent(self):
        return self.panel

    def createNewInstance(self, controller, editable):
        return AESEditorTab(self, controller, editable)

class AESEditorTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)
        self._currentMessage = None
        self._isRequest = False
        self._decrypted_state = {}

    def getTabCaption(self):
        return "Decrypted JSON"

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        if not self._extender.is_running: return False
        if not content: return False
        try:
            analyzed = self._helpers.analyzeRequest(content) if isRequest else self._helpers.analyzeResponse(content)
            body = self._helpers.bytesToString(content[analyzed.getBodyOffset():]).strip()
            return body.startswith('{') or body.startswith('[')
        except:
            return False

    def try_decrypt(self, val):
        try:
            key = bytearray.fromhex(self._extender.key_field.getText().strip())
            iv = bytearray.fromhex(self._extender.iv_field.getText().strip())
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))

            was_b64 = False
            raw_bytes = None
            
            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', val) and len(val) % 4 == 0:
                try:
                    raw_bytes = Base64.getDecoder().decode(val)
                    was_b64 = True
                except:
                    pass
            
            if not raw_bytes:
                raw_bytes = String(val).getBytes("ISO-8859-1")
                
            pt_bytes = cipher.doFinal(raw_bytes)
            dec_text = String(pt_bytes, "UTF-8").toString()
            
            try:
                return json.loads(dec_text), was_b64
            except:
                return dec_text, was_b64
        except Exception:
            return val, False

    def try_encrypt(self, val, use_b64):
        try:
            key = bytearray.fromhex(self._extender.key_field.getText().strip())
            iv = bytearray.fromhex(self._extender.iv_field.getText().strip())
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))

            if isinstance(val, (dict, list)):
                val = json.dumps(val, separators=(',', ':'))

            ct_bytes = cipher.doFinal(String(val).getBytes("UTF-8"))
            if use_b64:
                return Base64.getEncoder().encodeToString(ct_bytes)
            else:
                return String(ct_bytes, "ISO-8859-1").toString()
        except Exception:
            return val

    def process_json_decrypt(self, data, target_keys, path=""):
        if isinstance(data, dict):
            for k, v in data.items():
                current_path = path + "." + k if path else k
                if isinstance(v, (str, unicode)):
                    if not target_keys or k in target_keys:
                        dec_val, was_b64 = self.try_decrypt(v)
                        if dec_val != v:
                            data[k] = dec_val
                            self._decrypted_state[current_path] = was_b64
                elif isinstance(v, (dict, list)):
                    data[k] = self.process_json_decrypt(v, target_keys, current_path)
        elif isinstance(data, list):
            for i, v in enumerate(data):
                current_path = path + "[" + str(i) + "]"
                if isinstance(v, (str, unicode)):
                    if not target_keys:
                        dec_val, was_b64 = self.try_decrypt(v)
                        if dec_val != v:
                            data[i] = dec_val
                            self._decrypted_state[current_path] = was_b64
                elif isinstance(v, (dict, list)):
                    data[i] = self.process_json_decrypt(v, target_keys, current_path)
        return data

    def process_json_encrypt(self, data, path=""):
        if isinstance(data, dict):
            for k, v in data.items():
                current_path = path + "." + k if path else k
                if current_path in self._decrypted_state:
                    data[k] = self.try_encrypt(v, self._decrypted_state[current_path])
                elif isinstance(v, (dict, list)):
                    data[k] = self.process_json_encrypt(v, current_path)
        elif isinstance(data, list):
            for i, v in enumerate(data):
                current_path = path + "[" + str(i) + "]"
                if current_path in self._decrypted_state:
                    data[i] = self.try_encrypt(v, self._decrypted_state[current_path])
                elif isinstance(v, (dict, list)):
                    data[i] = self.process_json_encrypt(v, current_path)
        return data

    def setMessage(self, content, isRequest):
        self._currentMessage = content
        self._isRequest = isRequest
        self._decrypted_state = {}
        
        if not content:
            self._txtInput.setText(None)
            return

        try:
            analyzed = self._helpers.analyzeRequest(content) if isRequest else self._helpers.analyzeResponse(content)
            body = self._helpers.bytesToString(content[analyzed.getBodyOffset():])
            
            if isRequest and '{"data":"{' in body:
                body = body.replace('{"data":"{', '{"data":"\\"{').replace('}"}', '\\"}"}')
            
            j = json.loads(body)
            params_str = self._extender.params_field.getText().strip()
            target_keys = [p.strip() for p in params_str.split(',')] if params_str else []
            
            decrypted_json = self.process_json_decrypt(j, target_keys)
            dec_text = json.dumps(decrypted_json, indent=4)
            self._txtInput.setText(self._helpers.stringToBytes(dec_text))
            
        except Exception as e:
            try:
                self._txtInput.setText(self._helpers.stringToBytes(body))
            except:
                self._txtInput.setText(content)

    def getMessage(self):
        if not self._txtInput.isTextModified():
            return self._currentMessage

        try:
            analyzed = self._helpers.analyzeRequest(self._currentMessage) if self._isRequest else self._helpers.analyzeResponse(self._currentMessage)
            
            mod_text = self._helpers.bytesToString(self._txtInput.getText())
            j = json.loads(mod_text)
            
            encrypted_json = self.process_json_encrypt(j)
            new_body = json.dumps(encrypted_json, separators=(',', ':'))
            
            if self._isRequest:
                new_body = new_body.replace('/', '\\/')
            else:
                new_body = new_body.replace('\\"', '"')

            return self._currentMessage[:analyzed.getBodyOffset()] + self._helpers.stringToBytes(new_body)
        except Exception:
            return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()