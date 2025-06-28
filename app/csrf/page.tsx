// File: /app/csrf/page.tsx
export default function CSRFPage() {
  return (
    <div className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">
        CSRF (Cross-Site Request Forgery) Comprehensive Guide
      </h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is CSRF?</h2>
        <p className="leading-relaxed">
          Cross-Site Request Forgery (CSRF) is an attack that tricks authenticated users into submitting unwanted requests to a web application where they are currently logged in.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">CSRF Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Unauthorized account changes</li>
            <li>Financial transactions (transfers, purchases)</li>
            <li>Data modification or deletion</li>
            <li>Account takeover</li>
            <li>Privilege escalation</li>
          </ul>
        </div>
      </section>





      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>





        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic CSRF</h3>
          <p className="mb-3">
            Basic Cross-Site Request Forgery (CSRF) occurs when an attacker tricks a logged-in user into submitting a forged request to a web application. Since the browser includes credentials (like cookies) automatically, the action is performed without the user’s consent—often via hidden forms or auto-loaded resources.
          </p>
          
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Simple Auto-Submitting Form:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit()</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">This auto-submits a POST request to transfer funds when the victim visits the malicious page</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Image Tag GET Exploit:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<img src="https://example.com/delete?id=123" />`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">A simple GET request sent via image loading can trigger unintended state changes</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Exploitation Vectors:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Hidden forms:</strong> Auto-submitted with JavaScript or meta refresh
                </li>
                <li>
                  <strong>GET requests:</strong> Using image, iframe, or script tags
                </li>
                <li>
                  <strong>Misconfigured CORS:</strong> Allows JavaScript-based CSRF with credentials
                </li>
                <li>
                  <strong>Third-party embedding:</strong> Abuse of unsecured endpoints in embedded content
                </li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Malicious email or blog post containing the auto-submitting form</li>
                <li>Injected ads or scripts on compromised websites</li>
                <li>Clickjacking combined with invisible CSRF triggers</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. GET-based CSRF</h3>
          <p className="mb-3">
            GET-based CSRF exploits web applications that perform sensitive state-changing actions using HTTP GET requests.
            Since browsers automatically include cookies with all requests, even a simple link or image load can trigger
            dangerous actions without user consent.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Classic Exploit Example:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<img src="https://vulnerable-site.com/deleteAccount?user=123" />`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Automatically fires a GET request to a destructive endpoint when the image is loaded
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Malicious Link Example:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<a href="https://vulnerable-site.com/upgradeRole?user=attacker&role=admin">
  Click here for a free gift!
</a>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Social engineering trick to entice the victim into clicking a URL that elevates attacker’s privileges
              </p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Exploitation Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Auto-loaded images:</strong> Simple, stealthy delivery via <code>{`<img>`}</code> tags
                </li>
                <li>
                  <strong>Invisible iframes:</strong> Triggers GET requests without user visibility
                </li>
                <li>
                  <strong>Clickable bait:</strong> Disguised malicious links or buttons
                </li>
                <li>
                  <strong>Injected HTML:</strong> In forums, comments, or ad platforms
                </li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Phishing emails containing malicious images or links</li>
                <li>Cross-posted content on social media</li>
                <li>Compromised websites injecting hostile content</li>
                <li>Browser redirects or meta-refresh tags</li>
              </ul>
            </div>
          </div>
        </article>






        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. JSON-based CSRF</h3>
          <p className="mb-3">
            JSON-based CSRF targets APIs that accept JSON payloads via authenticated sessions, often over POST, PUT, or DELETE requests. Unlike basic CSRF, this attack typically requires bypassing protections like `Content-Type` validation, `CORS` policies, or CSRF tokens.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Exploit Attempt via JavaScript:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<script>
fetch("https://api.victim.com/change-email", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    email: "attacker@example.com"
  })
});
</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Sends an authenticated JSON request using cookies from the victim’s browser</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Bypass Vectors:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Open CORS policies:</strong> Misconfigured Access-Control-Allow-Origin headers
                </li>
                <li>
                  <strong>Lack of CSRF tokens:</strong> APIs without token-based verification
                </li>
                <li>
                  <strong>Missing SameSite flags:</strong> Allows cookie leakage with cross-site requests
                </li>
                <li>
                  <strong>Content-Type misconfigurations:</strong> Accepts `application/json` from third-party origins
                </li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Compromised scripts injecting fetch() calls</li>
                <li>Malicious browser extensions or bookmarklets</li>
                <li>Social engineering targeting developers/admins</li>
                <li>Cross-site widget or iframe injection in trusted apps</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Login CSRF</h3>
          <p className="mb-3">
            Login CSRF (Cross-Site Request Forgery during authentication) forces a user to log in as another account controlled by the attacker. This can lead to privilege confusion, data exfiltration, or unauthorized access, especially if the app uses session-based authentication without strong CSRF protections.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Exploit Example:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<form action="https://target.com/login" method="POST">
  <input type="hidden" name="username" value="attacker@example.com">
  <input type="hidden" name="password" value="attackerPassword123">
</form>
<script>document.forms[0].submit()</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Forces the victim to log in as the attacker's account, overwriting their own session</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Impact Scenarios:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>
                  <strong>Session fixation:</strong> Victim is logged in under attacker’s account and data
                </li>
                <li>
                  <strong>Silent surveillance:</strong> Attacker monitors activity or harvests sensitive data
                </li>
                <li>
                  <strong>Misleading audit trails:</strong> Logs show attacker’s identity for victim's actions
                </li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Malicious blog posts or comments with hidden login forms</li>
                <li>Ad networks injecting silent auto-login scripts</li>
                <li>Browser-based social engineering on forums or chat apps</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Prevention Tips:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-400">
                <li>Implement CSRF tokens in all login forms</li>
                <li>Use `SameSite=Strict` cookies to block cross-site credential sharing</li>
                <li>Use two-factor authentication to bind sessions to trusted identity</li>
                <li>Do not auto-login users purely based on a POST request</li>
              </ul>
            </div>
          </div>
        </article>




        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. POST-based CSRF</h3>
          <p className="mb-3">
            POST-based CSRF targets endpoints that change state or sensitive data using HTTP POST requests. These attacks often involve silently submitting forged forms using the victim’s session cookies, bypassing user intention and sometimes lacking token-based validation.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Basic Exploit Example:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="5000">
</form>
<script>document.forms[0].submit()</script>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Auto-submits a POST request to transfer funds without user interaction</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Targets:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li><strong>Banking portals:</strong> Money transfers or account updates</li>
                <li><strong>Admin panels:</strong> Role changes or user deletions</li>
                <li><strong>Profile updates:</strong> Email or password changes</li>
                <li><strong>Settings APIs:</strong> Enabling/disabling features</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Malicious websites embedding hidden forms</li>
                <li>HTML emails with auto-submitting content</li>
                <li>Compromised forums or ad injections</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-400">
                <li>Include CSRF tokens in all POST forms</li>
                <li>Enforce origin and referer header validation</li>
                <li>Set `SameSite=Strict` or `Lax` for session cookies</li>
                <li>Use CAPTCHAs to prevent silent submissions</li>
              </ul>
            </div>
          </div>
        </article>






        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">CSRF Tools & Automation</h3>

          <h4 className="font-medium mb-1 mt-3">Discovery & Scanning</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>Burp Suite Scanner – Identifies CSRF vulnerabilities via passive and active checks</li>
            <li>OWASP ZAP – Includes CSRF detection capabilities through automated scanning</li>
            <li>CSRF Tester – Lightweight tool to test form-based CSRF issues manually</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation & PoC Generation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>Burp Suite CSRF PoC Generator – Automatically creates proof-of-concept HTML forms</li>
            <li>XSS Hunter – Used for stealing CSRF tokens via stored or reflected XSS</li>
            <li>Custom JavaScript payloads – Tailored payloads for crafting targeted CSRF attacks</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Analysis & Reporting</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>Browser Developer Tools – Inspect token placement, cookie flags, and form behavior</li>
            <li>Token Analysis Scripts – Evaluate token strength, predictability, and regeneration</li>
            <li>Request Analyzers – Review and replay CSRF-protected requests for weaknesses</li>
          </ul>
        </article>

      </section>













      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Anti-CSRF Tokens</h3>
          
          <h4 className="font-medium mb-1 mt-3">Synchronizer Token Pattern</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Node.js example
const csrf = require('csurf');
app.use(csrf());
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Double Submit Cookie</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Set cookie and form field with same random value
Set-Cookie: CSRF-TOKEN=abc123;
<input type="hidden" name="csrf_token" value="abc123">`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Cookie Protections</h3>
          
          <h4 className="font-medium mb-1 mt-3">SameSite Attribute</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Set-Cookie: session=abc123; SameSite=Lax; Secure`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Cookie Prefixes</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Set-Cookie: __Secure-session=abc123; Secure; HttpOnly`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Additional Protections</h3>
          
          <h4 className="font-medium mb-1 mt-3">Custom Headers</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Require custom header for API requests
if (request.headers['X-Requested-With'] !== 'XMLHttpRequest') {
  return response.status(403).send('Forbidden');
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Referer Validation</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Check request origin
if (!request.headers.referer.startsWith('https://yourdomain.com')) {
  return response.status(403).send('Forbidden');
}`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Framework Protections</h3>
          
          <h4 className="font-medium mb-1 mt-3">Django CSRF Middleware</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    ...
]

# Template
<form method="post">{% csrf_token %}</form>`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Spring Security</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. Monitoring & Response</h3>
          
          <h4 className="font-medium mb-1 mt-3">Detection</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Missing CSRF tokens</li>
            <li>Invalid token submissions</li>
            <li>Referer header anomalies</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Logging</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Failed CSRF validations</li>
            <li>Sensitive action attempts</li>
            <li>Origin header mismatches</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Response</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Session invalidation</li>
            <li>User notification</li>
            <li>Forensic analysis</li>
          </ul>
        </article>
      </section>




      <div className="mb-12  p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">CSRF Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Implement anti-CSRF tokens for state-changing requests</li>
          <li>Set SameSite cookie attribute (Strict or Lax)</li>
          <li>Validate Referer headers for sensitive actions</li>
          <li>Require re-authentication for critical operations</li>
          <li>Use framework-provided CSRF protections</li>
          <li>Monitor for failed CSRF validations</li>
          <li>Educate developers about CSRF risks</li>
          <li>Regularly test your defenses</li>
        </ul>
      </div>



      <section className="mb-12">
        <h2 className="text-3xl font-semibold mb-4">Additional Resources & References</h2>
        <div className="space-y-6">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Learning Resources</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://owasp.org/www-community/attacks/csrf" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP CSRF — Comprehensive documentation
                </a>
              </li>
              <li>
                <a href="https://portswigger.net/web-security/csrf" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PortSwigger Academy — CSRF labs
                </a>
              </li>
              <li>
                <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PayloadsAllTheThings — CSRF cheatsheet
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Burp Suite — CSRF PoC generator
                </a>
              </li>
              <li>
                <a href="https://www.zaproxy.org/" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP ZAP — CSRF scanner
                </a>
              </li>
              <li>
                <a href="https://github.com/0xInfection/XSRFProbe" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  XSRFProbe — Advanced CSRF testing
                </a>
              </li>
            </ul>
          </div>
        </div>


      </section>






    </div>
  );
}
