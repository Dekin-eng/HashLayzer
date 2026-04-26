"""
HASHLAYZER - File Hash Calculator
Tool for malware hash identification
Version: Demo
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import os
import threading
import json
from datetime import datetime
import platform

# ============================================================================
# VIRUSTOTAL API CONFIGURATION
# ============================================================================

CONFIG_FILE = "hashlayzer_config.json"

def load_api_key():
    """Load API key from config file"""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                return config.get('virustotal_api_key', '')
    except:
        pass
    return ""

def save_api_key(api_key):
    """Save API key to config file"""
    try:
        config = {'virustotal_api_key': api_key}
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except:
        return False

# Try to import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ============================================================================
# MAIN APPLICATION
# ============================================================================

class HashLayzer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HashLayzer - File Hash Calculator")
        self.root.geometry("1100x750")
        self.root.minsize(1000, 650)
        
        # Light theme colors
        self.colors = {
            'bg': '#f5f5f5',
            'bg2': '#ffffff',
            'bg3': '#fafafa',
            'bg4': '#f0f0f0',
            'border': '#e0e0e0',
            'text': '#333333',
            'text2': '#666666',
            'text3': '#999999',
            'accent': '#2c7da0',
            'success': '#2e7d32',
            'danger': '#c62828',
            'warning': '#ed6c02',
            'info': '#0288d1'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Known malware database (local fallback)
        self.malware_db = self._load_malware_db()
        
        # VirusTotal API
        self.vt_api_key = load_api_key()
        self.vt_available = bool(self.vt_api_key) and REQUESTS_AVAILABLE
        
        self._setup_ui()
        
        # Show API status
        if not REQUESTS_AVAILABLE:
            self.status_label.config(text="Warning: requests library not installed. Run: pip install requests")
        elif not self.vt_available:
            self.status_label.config(text="VirusTotal API not configured. Add your API key above.")
    
    def _load_malware_db(self):
        """Load known malware hashes"""
        return {
            '44d88612fea8a8f36de82e1278abb02f': 'EICAR Test Virus',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 'Empty File',
        }
    
    def _setup_ui(self):
        # Header
        self._create_header()
        
        # Main container
        main = tk.Frame(self.root, bg=self.colors['bg'])
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # File selection section
        self._create_file_section(main)
        
        # API Status section
        self._create_api_section(main)
        
        # Results section
        self._create_results_section(main)
        
        # Status bar
        self._create_status_bar()
    
    def _create_header(self):
        """Create application header"""
        header = tk.Frame(self.root, bg=self.colors['bg2'], height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        title_frame = tk.Frame(header, bg=self.colors['bg2'])
        title_frame.pack(side=tk.LEFT, padx=25)
        
        tk.Label(title_frame, text="HashLayzer", font=('Segoe UI', 18, 'bold'),
                bg=self.colors['bg2'], fg=self.colors['accent']).pack(side=tk.LEFT)
        
        tk.Label(title_frame, text="File Hash Calculator", font=('Segoe UI', 9),
                bg=self.colors['bg2'], fg=self.colors['text2']).pack(side=tk.LEFT, padx=10)
        
        # VirusTotal badge
        vt_frame = tk.Frame(header, bg=self.colors['bg2'])
        vt_frame.pack(side=tk.RIGHT, padx=20)
        
        if self.vt_available:
            vt_status = "✓"
            vt_color = self.colors['success']
            vt_text = "VirusTotal Connected"
        else:
            vt_status = "⚠"
            vt_color = self.colors['warning']
            vt_text = "VirusTotal Not Configured"
        
        tk.Label(vt_frame, text=f"{vt_status} {vt_text}", font=('Segoe UI', 9, 'bold'),
                bg=self.colors['bg2'], fg=vt_color).pack(side=tk.LEFT)
        
        # Demo version badge
        demo_badge = tk.Frame(header, bg=self.colors['bg2'])
        demo_badge.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(demo_badge, text="DEMO VERSION", font=('Segoe UI', 9, 'bold'),
                bg=self.colors['bg2'], fg=self.colors['warning']).pack(side=tk.LEFT)
    
    def _create_api_section(self, parent):
        """VirusTotal API configuration section"""
        api_frame = tk.LabelFrame(parent, text="VirusTotal Integration", bg=self.colors['bg2'],
                                   fg=self.colors['text'], font=('Segoe UI', 9, 'bold'),
                                   relief=tk.GROOVE, bd=1)
        api_frame.pack(fill=tk.X, pady=(0, 15))
        
        inner = tk.Frame(api_frame, bg=self.colors['bg2'])
        inner.pack(padx=15, pady=10, fill=tk.X)
        
        tk.Label(inner, text="API Key:", bg=self.colors['bg2'], fg=self.colors['text'],
                font=('Segoe UI', 9)).pack(side=tk.LEFT)
        
        self.api_key_var = tk.StringVar(value=self.vt_api_key)
        self.api_entry = tk.Entry(inner, textvariable=self.api_key_var, bg=self.colors['bg3'],
                                   fg=self.colors['text'], font=('Segoe UI', 9), relief=tk.FLAT,
                                   width=40, show="*")
        self.api_entry.pack(side=tk.LEFT, padx=(10, 10), fill=tk.X, expand=True)
        
        save_btn = tk.Button(inner, text="Save Key", command=self._save_api_key,
                             bg=self.colors['accent'], fg='white', font=('Segoe UI', 8),
                             padx=10, pady=3, cursor='hand2', relief=tk.FLAT)
        save_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        test_btn = tk.Button(inner, text="Test Connection", command=self._test_api,
                             bg=self.colors['bg3'], fg=self.colors['text'], font=('Segoe UI', 8),
                             padx=10, pady=3, cursor='hand2', relief=tk.FLAT,
                             bd=1, highlightbackground=self.colors['border'])
        test_btn.pack(side=tk.LEFT)
        
        # API Info
        info_label = tk.Label(inner, text="Get free API key: virustotal.com", 
                              bg=self.colors['bg2'], fg=self.colors['text2'],
                              font=('Segoe UI', 8, 'italic'))
        info_label.pack(side=tk.RIGHT)
    
    def _save_api_key(self):
        """Save API key to config"""
        api_key = self.api_key_var.get().strip()
        if api_key:
            if save_api_key(api_key):
                self.vt_api_key = api_key
                self.vt_available = True
                messagebox.showinfo("Success", "VirusTotal API key saved successfully!")
                self.status_label.config(text="VirusTotal API configured")
                self._update_header_badge()
            else:
                messagebox.showerror("Error", "Failed to save API key")
        else:
            messagebox.showwarning("No Key", "Please enter a valid API key")
    
    def _update_header_badge(self):
        """Update the header badge after API key saved"""
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Frame) and widget.winfo_height() == 60:
                for child in widget.winfo_children():
                    if isinstance(child, tk.Frame) and child.winfo_width() > 100:
                        for subchild in child.winfo_children():
                            subchild.destroy()
                        tk.Label(child, text="✓ VirusTotal Connected", font=('Segoe UI', 9, 'bold'),
                                bg=self.colors['bg2'], fg=self.colors['success']).pack(side=tk.LEFT)
    
    def _test_api(self):
        """Test VirusTotal API connection"""
        if not REQUESTS_AVAILABLE:
            messagebox.showerror("Error", "requests library not installed.\nRun: pip install requests")
            return
        
        api_key = self.api_key_var.get().strip()
        if not api_key:
            messagebox.showwarning("No API Key", "Please enter an API key first")
            return
        
        self.status_label.config(text="Testing VirusTotal API connection...")
        
        def test():
            try:
                test_hash = "44d88612fea8a8f36de82e1278abb02f"
                url = f"https://www.virustotal.com/api/v3/files/{test_hash}"
                headers = {"x-apikey": api_key}
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    self.root.after(0, lambda: messagebox.showinfo("Success", "VirusTotal API connected successfully!"))
                    self.root.after(0, lambda: self.status_label.config(text="API test successful"))
                elif response.status_code == 401:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Invalid API key"))
                    self.root.after(0, lambda: self.status_label.config(text="Invalid API key"))
                else:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"API error: {response.status_code}"))
                    self.root.after(0, lambda: self.status_label.config(text=f"API error: {response.status_code}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Connection failed: {str(e)}"))
                self.root.after(0, lambda: self.status_label.config(text="Connection failed"))
        
        threading.Thread(target=test, daemon=True).start()
    
    def _create_file_section(self, parent):
        """File selection area"""
        file_frame = tk.LabelFrame(parent, text="File Selection", bg=self.colors['bg2'],
                                    fg=self.colors['text'], font=('Segoe UI', 10, 'bold'),
                                    relief=tk.GROOVE, bd=1)
        file_frame.pack(fill=tk.X, pady=(0, 15))
        
        inner = tk.Frame(file_frame, bg=self.colors['bg2'])
        inner.pack(padx=15, pady=15, fill=tk.X)
        
        tk.Label(inner, text="File Path:", bg=self.colors['bg2'], fg=self.colors['text'],
                font=('Segoe UI', 9)).pack(side=tk.LEFT)
        
        self.file_path = tk.StringVar()
        file_entry = tk.Entry(inner, textvariable=self.file_path, bg=self.colors['bg3'],
                              fg=self.colors['text'], font=('Segoe UI', 9), relief=tk.FLAT,
                              bd=1, highlightthickness=1, highlightcolor=self.colors['accent'],
                              highlightbackground=self.colors['border'])
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))
        
        browse_btn = tk.Button(inner, text="Browse", command=self._browse_file,
                               bg=self.colors['accent'], fg='white', font=('Segoe UI', 9),
                               padx=15, pady=4, cursor='hand2', relief=tk.FLAT)
        browse_btn.pack(side=tk.RIGHT)
        
        # Action buttons
        btn_frame = tk.Frame(file_frame, bg=self.colors['bg2'])
        btn_frame.pack(padx=15, pady=(0, 15), fill=tk.X)
        
        self.analyze_btn = tk.Button(btn_frame, text="Analyze File", command=self._analyze_file,
                                     bg=self.colors['success'], fg='white', font=('Segoe UI', 9, 'bold'),
                                     padx=25, pady=6, cursor='hand2', relief=tk.FLAT)
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.vt_check = tk.BooleanVar(value=True)
        vt_checkbox = tk.Checkbutton(btn_frame, text="Check VirusTotal", variable=self.vt_check,
                                      bg=self.colors['bg2'], fg=self.colors['text'],
                                      font=('Segoe UI', 9), cursor='hand2',
                                      selectcolor=self.colors['bg3'])
        vt_checkbox.pack(side=tk.LEFT, padx=(0, 10))
        
        self.copy_btn = tk.Button(btn_frame, text="Copy Hashes", command=self._copy_hashes,
                                  bg=self.colors['bg3'], fg=self.colors['text'], font=('Segoe UI', 9),
                                  padx=20, pady=6, cursor='hand2', relief=tk.FLAT,
                                  bd=1, highlightbackground=self.colors['border'])
        self.copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_btn = tk.Button(btn_frame, text="Clear", command=self._clear_results,
                                   bg=self.colors['bg3'], fg=self.colors['text'], font=('Segoe UI', 9),
                                   padx=20, pady=6, cursor='hand2', relief=tk.FLAT,
                                   bd=1, highlightbackground=self.colors['border'])
        self.clear_btn.pack(side=tk.LEFT)
    
    def _create_results_section(self, parent):
        """Results display area"""
        results_frame = tk.LabelFrame(parent, text="Analysis Results", bg=self.colors['bg2'],
                                       fg=self.colors['text'], font=('Segoe UI', 10, 'bold'),
                                       relief=tk.GROOVE, bd=1)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        notebook = ttk.Notebook(results_frame)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure notebook style
        style = ttk.Style()
        style.configure("TNotebook", background=self.colors['bg2'])
        style.configure("TNotebook.Tab", background=self.colors['bg3'], foreground=self.colors['text'])
        style.map("TNotebook.Tab", background=[("selected", self.colors['accent'])])
        
        # Tab 1: Hash Results
        hash_tab = tk.Frame(notebook, bg=self.colors['bg2'])
        notebook.add(hash_tab, text="Hash Values")
        
        self.results_text = tk.Text(hash_tab, bg=self.colors['bg3'], fg=self.colors['text'],
                                     font=('Consolas', 11), relief=tk.FLAT, wrap=tk.WORD,
                                     padx=10, pady=10, insertbackground=self.colors['text'])
        scroll = tk.Scrollbar(hash_tab, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scroll.set)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Tab 2: File Information
        info_tab = tk.Frame(notebook, bg=self.colors['bg2'])
        notebook.add(info_tab, text="File Information")
        
        self.info_text = tk.Text(info_tab, bg=self.colors['bg3'], fg=self.colors['text'],
                                  font=('Consolas', 11), relief=tk.FLAT, wrap=tk.WORD,
                                  padx=10, pady=10, insertbackground=self.colors['text'])
        info_scroll = tk.Scrollbar(info_tab, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scroll.set)
        self.info_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        info_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Tab 3: Local Threat Intel
        local_tab = tk.Frame(notebook, bg=self.colors['bg2'])
        notebook.add(local_tab, text="Local Intel")
        
        self.threat_text = tk.Text(local_tab, bg=self.colors['bg3'], fg=self.colors['text'],
                                    font=('Consolas', 11), relief=tk.FLAT, wrap=tk.WORD,
                                    padx=10, pady=10, insertbackground=self.colors['text'])
        threat_scroll = tk.Scrollbar(local_tab, orient=tk.VERTICAL, command=self.threat_text.yview)
        self.threat_text.configure(yscrollcommand=threat_scroll.set)
        self.threat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        threat_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Tab 4: VirusTotal Results
        vt_tab = tk.Frame(notebook, bg=self.colors['bg2'])
        notebook.add(vt_tab, text="VirusTotal")
        
        self.vt_text = tk.Text(vt_tab, bg=self.colors['bg3'], fg=self.colors['text'],
                                font=('Consolas', 11), relief=tk.FLAT, wrap=tk.WORD,
                                padx=10, pady=10, insertbackground=self.colors['text'])
        vt_scroll = tk.Scrollbar(vt_tab, orient=tk.VERTICAL, command=self.vt_text.yview)
        self.vt_text.configure(yscrollcommand=vt_scroll.set)
        self.vt_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vt_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initial info
        self._show_initial_info()
    
    def _show_initial_info(self):
        """Show initial information in tabs"""
        # Hash tab
        self.results_text.insert(tk.END, "Select a file and click 'Analyze File' to view hash values.\n\n")
        self.results_text.insert(tk.END, "Supported hash algorithms:\n")
        self.results_text.insert(tk.END, "• MD5 (128-bit)\n")
        self.results_text.insert(tk.END, "• SHA-1 (160-bit)\n")
        self.results_text.insert(tk.END, "• SHA-256 (256-bit)\n")
        self.results_text.insert(tk.END, "• SHA-512 (512-bit)\n")
        self.results_text.config(state=tk.DISABLED)
        
        # Info tab
        self.info_text.insert(tk.END, "File information will appear here after analysis.\n\n")
        self.info_text.insert(tk.END, "Information displayed:\n")
        self.info_text.insert(tk.END, "• File name and path\n")
        self.info_text.insert(tk.END, "• File size\n")
        self.info_text.insert(tk.END, "• File type/extension\n")
        self.info_text.insert(tk.END, "• Creation and modification dates\n")
        self.info_text.config(state=tk.DISABLED)
        
        # Local Intel tab
        self.threat_text.insert(tk.END, "Local threat intelligence results will appear here.\n\n")
        self.threat_text.insert(tk.END, "Checks performed:\n")
        self.threat_text.insert(tk.END, "• Known malware hash database\n")
        self.threat_text.insert(tk.END, "• Suspicious file indicators\n")
        self.threat_text.insert(tk.END, "• Risk assessment\n")
        self.threat_text.config(state=tk.DISABLED)
        
        # VirusTotal tab
        self.vt_text.insert(tk.END, "VirusTotal results will appear here if API is configured.\n\n")
        self.vt_text.insert(tk.END, "What VirusTotal provides:\n")
        self.vt_text.insert(tk.END, "• Detection by 70+ antivirus engines\n")
        self.vt_text.insert(tk.END, "• File reputation score\n")
        self.vt_text.insert(tk.END, "• Community comments\n")
        self.vt_text.insert(tk.END, "• Detailed malware classification\n\n")
        
        if not self.vt_available:
            self.vt_text.insert(tk.END, "⚠️ VirusTotal API not configured.\n")
            self.vt_text.insert(tk.END, "Please add your API key in the settings section above.")
        
        self.vt_text.config(state=tk.DISABLED)
    
    def _create_status_bar(self):
        """Status bar at bottom"""
        status_bar = tk.Frame(self.root, bg=self.colors['bg2'], height=28)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        status_bar.pack_propagate(False)
        
        self.status_label = tk.Label(status_bar, text="Ready", anchor=tk.W,
                                     bg=self.colors['bg2'], fg=self.colors['text2'],
                                     font=('Segoe UI', 8))
        self.status_label.pack(side=tk.LEFT, padx=15)
        
        sys_label = tk.Label(status_bar, text=f"Python {platform.python_version()} | HashLayzer Demo",
                             bg=self.colors['bg2'], fg=self.colors['text2'], font=('Segoe UI', 8))
        sys_label.pack(side=tk.RIGHT, padx=15)
    
    def _browse_file(self):
        """Open file dialog"""
        file_path = filedialog.askopenfilename(
            title="Select File for Analysis",
            filetypes=[
                ("All Files", "*.*"),
                ("Executable Files", "*.exe *.dll *.sys"),
                ("Archive Files", "*.zip *.rar *.7z"),
                ("Document Files", "*.pdf *.doc *.docx *.xls *.xlsx")
            ]
        )
        if file_path:
            self.file_path.set(file_path)
    
    def _calculate_hashes(self, file_path):
        """Calculate all cryptographic hashes"""
        hashes = {}
        
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    sha512.update(chunk)
            
            hashes['MD5'] = md5.hexdigest()
            hashes['SHA-1'] = sha1.hexdigest()
            hashes['SHA-256'] = sha256.hexdigest()
            hashes['SHA-512'] = sha512.hexdigest()
            
        except Exception as e:
            return None, str(e)
        
        return hashes, None
    
    def _get_file_info(self, file_path):
        """Extract file metadata"""
        info = {}
        
        try:
            info['name'] = os.path.basename(file_path)
            info['path'] = file_path
            
            size = os.path.getsize(file_path)
            if size < 1024:
                info['size'] = f"{size} bytes"
            elif size < 1024 * 1024:
                info['size'] = f"{size / 1024:.2f} KB"
            else:
                info['size'] = f"{size / (1024 * 1024):.2f} MB"
            
            _, ext = os.path.splitext(file_path)
            info['type'] = ext.upper() if ext else "No extension"
            
            info['created'] = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            info['modified'] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def _check_local_threat(self, hashes, file_info):
        """Analyze threat level using local database"""
        threat = {
            'level': 'safe',
            'matches': [],
            'recommendation': ''
        }
        
        # Check local malware database
        for hash_type, hash_value in hashes.items():
            if hash_value in self.malware_db:
                threat['level'] = 'malicious'
                threat['matches'].append(f"{hash_type}: {self.malware_db[hash_value]}")
        
        # Check for empty file
        if file_info.get('size') == "0 bytes":
            threat['level'] = 'warning'
            threat['matches'].append("File is empty")
        
        # Check for suspicious extensions
        suspicious_extensions = ['.EXE', '.DLL', '.SCR', '.BAT', '.PS1', '.VBS', '.JS']
        if file_info.get('type') in suspicious_extensions and threat['level'] == 'safe':
            threat['level'] = 'caution'
            threat['matches'].append(f"Executable file type: {file_info.get('type')}")
        
        # Set recommendation
        if threat['level'] == 'malicious':
            threat['recommendation'] = "DO NOT EXECUTE - Known malware detected. Delete immediately."
        elif threat['level'] == 'warning':
            threat['recommendation'] = "Empty or corrupted file - Investigate further."
        elif threat['level'] == 'caution':
            threat['recommendation'] = "Executable file - Verify source before running."
        else:
            threat['recommendation'] = "No threats detected - File appears safe."
        
        return threat
    
    def _query_virustotal(self, hash_value):
        """Query VirusTotal API for hash"""
        if not REQUESTS_AVAILABLE:
            return None, "requests library not installed"
        
        if not self.vt_api_key:
            return None, "API key not configured"
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                return data, None
            elif response.status_code == 404:
                return None, "File not found in VirusTotal database"
            elif response.status_code == 401:
                return None, "Invalid API key"
            else:
                return None, f"API error: {response.status_code}"
        except requests.exceptions.Timeout:
            return None, "Connection timeout"
        except Exception as e:
            return None, f"Connection error: {str(e)}"
    
    def _format_vt_results(self, data):
        """Format VirusTotal results for display"""
        if not data:
            return "No results available"
        
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            results = []
            
            results.append("=" * 60)
            results.append("VIRUSTOTAL ANALYSIS REPORT")
            results.append("=" * 60)
            results.append("")
            
            # Detection summary
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            undetected = stats.get('undetected', 0)
            harmless = stats.get('harmless', 0)
            total = malicious + suspicious + undetected + harmless
            
            results.append(f"Detection Summary:")
            results.append(f"  Total Engines:  {total}")
            results.append(f"  Malicious:      {malicious}")
            results.append(f"  Suspicious:     {suspicious}")
            results.append(f"  Undetected:     {undetected}")
            results.append(f"  Harmless:       {harmless}")
            results.append("")
            
            # Threat level
            if malicious > 0:
                results.append(f"⚠️ VERDICT: MALICIOUS - {malicious} antivirus engines detected threats")
                if malicious >= 10:
                    results.append("   High confidence - This file is almost certainly malware")
                elif malicious >= 3:
                    results.append("   Medium confidence - Exercise extreme caution")
                else:
                    results.append("   Low confidence - Further investigation recommended")
            else:
                results.append(f"✅ VERDICT: CLEAN - No detections from {total} engines")
                results.append("   File appears safe based on VirusTotal analysis")
            
            results.append("")
            results.append("-" * 60)
            
            # Additional info
            names = attributes.get('names', [])
            if names:
                results.append(f"File Names: {', '.join(names[:3])}")
            
            type_desc = attributes.get('type_description', 'N/A')
            results.append(f"File Type: {type_desc}")
            
            results.append("")
            results.append("=" * 60)
            results.append("Note: VirusTotal aggregates 70+ antivirus engines")
            results.append("Visit virustotal.com for complete report")
            
            return "\n".join(results)
            
        except Exception as e:
            return f"Error parsing VirusTotal results: {str(e)}"
    
    def _analyze_file(self):
        """Main analysis function"""
        file_path = self.file_path.get().strip()
        
        if not file_path:
            messagebox.showwarning("No File", "Please select a file to analyze")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("File Not Found", f"The specified file does not exist:\n{file_path}")
            return
        
        # Disable buttons during analysis
        self.analyze_btn.config(state=tk.DISABLED)
        self.status_label.config(text=f"Analyzing: {os.path.basename(file_path)}...")
        
        # Clear previous results
        self._clear_results()
        
        # Run analysis in thread
        threading.Thread(target=self._analysis_thread, args=(file_path,), daemon=True).start()
    
    def _analysis_thread(self, file_path):
        """Threaded analysis"""
        # Calculate hashes
        hashes, error = self._calculate_hashes(file_path)
        
        if error:
            self.root.after(0, lambda: self._show_error(error))
            return
        
        # Get file info
        file_info = self._get_file_info(file_path)
        
        # Check local threat
        local_threat = self._check_local_threat(hashes, file_info)
        
        # Query VirusTotal if enabled
        vt_result = None
        vt_error = None
        
        if self.vt_check.get():
            self.root.after(0, lambda: self.status_label.config(text="Querying VirusTotal..."))
            vt_result, vt_error = self._query_virustotal(hashes['MD5'])
        
        # Update UI
        self.root.after(0, lambda: self._update_results(hashes, file_info, local_threat, vt_result, vt_error))
        self.root.after(0, lambda: self.status_label.config(text=f"Analysis complete: {os.path.basename(file_path)}"))
        self.root.after(0, lambda: self.analyze_btn.config(state=tk.NORMAL))
    
    def _update_results(self, hashes, file_info, local_threat, vt_result, vt_error):
        """Update all result tabs"""
        # Update Hash tab
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        self.results_text.insert(tk.END, "=" * 60 + "\n")
        self.results_text.insert(tk.END, "CRYPTOGRAPHIC HASHES\n")
        self.results_text.insert(tk.END, "=" * 60 + "\n\n")
        
        for hash_type, hash_value in hashes.items():
            self.results_text.insert(tk.END, f"{hash_type}:\n")
            self.results_text.insert(tk.END, f"  {hash_value}\n\n")
        
        self.results_text.insert(tk.END, "=" * 60 + "\n")
        self.results_text.insert(tk.END, "Verification: These hashes are unique to this file\n")
        self.results_text.insert(tk.END, "Any modification will change the hash values\n")
        
        self.results_text.config(state=tk.DISABLED)
        
        # Update Info tab
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        
        self.info_text.insert(tk.END, "=" * 60 + "\n")
        self.info_text.insert(tk.END, "FILE METADATA\n")
        self.info_text.insert(tk.END, "=" * 60 + "\n\n")
        
        self.info_text.insert(tk.END, f"File Name:     {file_info.get('name', 'N/A')}\n")
        self.info_text.insert(tk.END, f"File Size:     {file_info.get('size', 'N/A')}\n")
        self.info_text.insert(tk.END, f"File Type:     {file_info.get('type', 'N/A')}\n")
        self.info_text.insert(tk.END, f"Created:       {file_info.get('created', 'N/A')}\n")
        self.info_text.insert(tk.END, f"Modified:      {file_info.get('modified', 'N/A')}\n")
        self.info_text.insert(tk.END, f"Full Path:     {file_info.get('path', 'N/A')}\n")
        
        self.info_text.config(state=tk.DISABLED)
        
        # Update Local Threat tab
        self.threat_text.config(state=tk.NORMAL)
        self.threat_text.delete(1.0, tk.END)
        
        self.threat_text.insert(tk.END, "=" * 60 + "\n")
        self.threat_text.insert(tk.END, "LOCAL THREAT ASSESSMENT\n")
        self.threat_text.insert(tk.END, "=" * 60 + "\n\n")
        
        if local_threat['level'] == 'malicious':
            status = "🔴 MALICIOUS - Known threat detected"
        elif local_threat['level'] == 'warning':
            status = "🟡 WARNING - Suspicious indicators found"
        elif local_threat['level'] == 'caution':
            status = "🟠 CAUTION - Executable file type"
        else:
            status = "🟢 SAFE - No threats detected"
        
        self.threat_text.insert(tk.END, f"Status: {status}\n\n")
        
        if local_threat['matches']:
            self.threat_text.insert(tk.END, "Findings:\n")
            self.threat_text.insert(tk.END, "-" * 40 + "\n")
            for match in local_threat['matches']:
                self.threat_text.insert(tk.END, f"  • {match}\n")
            self.threat_text.insert(tk.END, "\n")
        
        self.threat_text.insert(tk.END, "Recommendation:\n")
        self.threat_text.insert(tk.END, "-" * 40 + "\n")
        self.threat_text.insert(tk.END, f"  {local_threat['recommendation']}\n\n")
        
        self.threat_text.config(state=tk.DISABLED)
        
        # Update VirusTotal tab
        self.vt_text.config(state=tk.NORMAL)
        self.vt_text.delete(1.0, tk.END)
        
        if vt_error:
            self.vt_text.insert(tk.END, f"⚠️ VirusTotal Error: {vt_error}\n\n")
            self.vt_text.insert(tk.END, "Troubleshooting:\n")
            self.vt_text.insert(tk.END, "1. Verify your API key is valid\n")
            self.vt_text.insert(tk.END, "2. Check your internet connection\n")
            self.vt_text.insert(tk.END, "3. Free API key: 4 requests/minute limit\n")
        elif vt_result:
            formatted = self._format_vt_results(vt_result)
            self.vt_text.insert(tk.END, formatted)
        else:
            self.vt_text.insert(tk.END, "No VirusTotal results available.\n\n")
            self.vt_text.insert(tk.END, "Possible reasons:\n")
            self.vt_text.insert(tk.END, "• 'Check VirusTotal' checkbox is off\n")
            self.vt_text.insert(tk.END, "• API not configured\n")
            self.vt_text.insert(tk.END, "• Hash not found in VirusTotal database\n")
            self.vt_text.insert(tk.END, "• API rate limit exceeded (4/min)\n")
        
        self.vt_text.config(state=tk.DISABLED)
    
    def _show_error(self, error):
        """Display error message"""
        messagebox.showerror("Analysis Error", f"Failed to analyze file:\n{error}")
        self.status_label.config(text="Error analyzing file")
        self.analyze_btn.config(state=tk.NORMAL)
    
    def _copy_hashes(self):
        """Copy hash values to clipboard"""
        text = self.results_text.get(1.0, tk.END).strip()
        if text and "Select a file" not in text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_label.config(text="Hashes copied to clipboard")
            self.root.after(2000, lambda: self.status_label.config(text="Ready"))
        else:
            messagebox.showinfo("No Data", "No hash results to copy. Please analyze a file first.")
    
    def _clear_results(self):
        """Clear all results"""
        # Reset all tabs
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Select a file and click 'Analyze File' to view hash values.\n\n")
        self.results_text.insert(tk.END, "Supported hash algorithms:\n")
        self.results_text.insert(tk.END, "• MD5 (128-bit)\n")
        self.results_text.insert(tk.END, "• SHA-1 (160-bit)\n")
        self.results_text.insert(tk.END, "• SHA-256 (256-bit)\n")
        self.results_text.insert(tk.END, "• SHA-512 (512-bit)\n")
        self.results_text.config(state=tk.DISABLED)
        
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, "File information will appear here after analysis.\n\n")
        self.info_text.insert(tk.END, "Information displayed:\n")
        self.info_text.insert(tk.END, "• File name and path\n")
        self.info_text.insert(tk.END, "• File size\n")
        self.info_text.insert(tk.END, "• File type/extension\n")
        self.info_text.insert(tk.END, "• Creation and modification dates\n")
        self.info_text.config(state=tk.DISABLED)
        
        self.threat_text.config(state=tk.NORMAL)
        self.threat_text.delete(1.0, tk.END)
        self.threat_text.insert(tk.END, "Local threat intelligence results will appear here.\n\n")
        self.threat_text.insert(tk.END, "Checks performed:\n")
        self.threat_text.insert(tk.END, "• Known malware hash database\n")
        self.threat_text.insert(tk.END, "• Suspicious file indicators\n")
        self.threat_text.insert(tk.END, "• Risk assessment\n")
        self.threat_text.config(state=tk.DISABLED)
        
        self.vt_text.config(state=tk.NORMAL)
        self.vt_text.delete(1.0, tk.END)
        self.vt_text.insert(tk.END, "VirusTotal results will appear here if API is configured.\n\n")
        self.vt_text.insert(tk.END, "Make sure 'Check VirusTotal' is selected before analyzing.\n")
        self.vt_text.config(state=tk.DISABLED)
        
        self.status_label.config(text="Ready")
    
    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     HASHLAYZER - Demo Version                               ║
║     File Hash Calculator                                    ║
║     ✓ Light Theme | ✓ VirusTotal API Ready                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Check for requests library
    if not REQUESTS_AVAILABLE:
        print("⚠️  Installing required library: requests")
        os.system("pip install requests")
        import requests
    
    app = HashLayzer()
    app.run()