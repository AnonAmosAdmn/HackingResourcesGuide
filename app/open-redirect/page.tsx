// File: /app/open-redirect/page.tsx
export default function OpenRedirectPage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">
        Open Redirect
      </h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is Open Redirect?</h2>
        <p className="leading-relaxed">
          Open Redirect is a web application vulnerability where an attacker tricks the application
          into redirecting users to a malicious or untrusted external site by manipulating URL
          parameters or links.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">Open Redirect Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Phishing attacks and credential theft</li>
            <li>Malware distribution</li>
            <li>Session hijacking</li>
            <li>Bypass of security controls</li>
            <li>Loss of user trust</li>
            <li>SEO spam and blacklisting</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Identification Techniques</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">Common Parameters</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`redirect
url
next
return
destination
r
forward
go
checkout
continue`}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-1">Testing Methodology</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Fuzz all parameters with external domains</li>
                <li>Check both GET and POST requests</li>
                <li>Test all authentication flows</li>
                <li>Examine JavaScript redirects</li>
              </ul>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Advanced Exploitation</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">OAuth/SSO Abuse</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`https://oauth-provider.com/auth?
  client_id=123&
  redirect_uri=https://attacker.com/callback`}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-1">DOM-Based Redirects</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`window.location.href = new URLSearchParams(
  window.location.search
).get('redirect');`}
              </pre>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Bypass Techniques</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">Encoding Variations</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Double encoding
%252F%252Fevil.com

// UTF-8 encoding
%C2%A0evil.com

// HTML entities
&amp;#x2F;&amp;#x2F;evil.com`}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-1">Protocol Tricks</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Missing protocol
//evil.com/path

// JavaScript protocol
javascript:alert(1)

// Data URI
data:text/html,<script>alert(1)</script>`}
              </pre>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Real-World Attack Chains</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">Phishing Campaign</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. Victim receives: https://trusted.com/login?redirect=phish.com
2. Trusted site redirects to phishing page
3. Phishing page steals credentials`}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-1">CSRF Exploitation</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="amount" value="1000">
  <input type="hidden" name="to" value="attacker">
</form>
<script>document.forms[0].submit()</script>`}
              </pre>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400"> Tools & Automation</h3>
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Discovery Tools</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Burp Suite Scanner</li>
                <li>OWASP ZAP</li>
                <li>Param Miner</li>
                <li>Arjun</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-1">Exploitation Tools</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Phishing frameworks</li>
                <li>Redirector services</li>
                <li>Custom scripts</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-1">Analysis Tools</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Browser developer tools</li>
                <li>Redirect tracing tools</li>
                <li>Network analyzers</li>
              </ul>
            </div>
          </div>
        </article>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Secure Redirect Handling</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">Whitelist Implementation</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Python example
ALLOWED_DOMAINS = ['example.com', 'trusted.org']

def safe_redirect(url):
    domain = urlparse(url).netloc
    if domain not in ALLOWED_DOMAINS:
        return "/"  # Default safe location
    return url`}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-1">Relative URLs Only</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Only allow paths, not full URLs
function validateRedirect(path) {
    return path.startsWith('/') ? path : '/';
}`}
              </pre>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Framework Protections</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">Django Safe Redirect</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`from django.utils.http import is_safe_url

redirect_to = request.GET.get('next')
if not is_safe_url(redirect_to, allowed_hosts=request.get_host()):
    redirect_to = '/'`}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-1">Spring Security</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`@Controller
public class RedirectController {
    public String redirect(@RequestParam String url) {
        // Validate URL against whitelist
        if (!SecurityUtils.isSafe(url)) {
            return "redirect:/";
        }
        return "redirect:" + url;
    }
}`}
              </pre>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Security Headers</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">Content Security Policy</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Content-Security-Policy: default-src 'self';
  form-action 'self';
  frame-ancestors 'none'`}
              </pre>
            </div>
            <div>
              <h4 className="font-medium mb-1">Referrer Policy</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Referrer-Policy: strict-origin-when-cross-origin`}
              </pre>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg mb-6">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Monitoring & Detection</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium mb-1">Anomaly Detection</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Unusual redirect patterns</li>
                <li>Suspicious domains in logs</li>
                <li>Spike in redirect usage</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-1">WAF Rules</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Block known malicious domains</li>
                <li>Detect encoding bypass attempts</li>
                <li>Rate limit redirect endpoints</li>
              </ul>
            </div>
          </div>
        </article>

        <article className="bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. User Protection Measures</h3>
          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Visual Indicators</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Clear external link warnings</li>
                <li>Domain highlighting</li>
                <li>Security badges</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-1">Confirmation Steps</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Redirect confirmation pages</li>
                <li>Countdown timers</li>
                <li>Manual user approval</li>
              </ul>
            </div>
            <div>
              <h4 className="font-medium mb-1">Education</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Security awareness training</li>
                <li>Phishing simulations</li>
                <li>Reporting mechanisms</li>
              </ul>
            </div>
          </div>
        </article>
      </section>




      <div className="mb-12 p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">Open Redirect Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Implement strict whitelist-based redirect validation</li>
          <li>Prefer relative URLs over absolute URLs</li>
          <li>Use framework-provided safe redirect functions</li>
          <li>Add security headers (CSP, Referrer-Policy)</li>
          <li>Monitor for suspicious redirect patterns</li>
          <li>Educate users about external link risks</li>
          <li>Regularly audit all redirect functionality</li>
          <li>Implement WAF rules for common bypass techniques</li>
        </ul>
      </div>


      
      <section className="mb-12">
        <h2 className="text-3xl font-semibold mb-4">Additional Resources & References</h2>
        <div className="space-y-6">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Learning Resources</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PayloadsAllTheThings — Open redirect cheatsheet
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://github.com/PortSwigger/param-miner" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Param Miner — Burp extension for parameter discovery
                </a>
              </li>
              <li>
                <a href="https://github.com/s0md3v/Arjun" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Arjun — HTTP parameter discovery suite
                </a>
              </li>
              <li>
                <a href="https://github.com/kleiton0x00/ppmap" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  ppmap — Open redirect scanner
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

    </main>
  );
}
