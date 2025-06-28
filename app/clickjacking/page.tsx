// File: /app/clickjacking/page.tsx
export default function ClickjackingPage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">
        Clickjacking (UI Redress Attack)
      </h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is Clickjacking?</h2>
        <p className="leading-relaxed">
          Clickjacking is a malicious technique where an attacker tricks a user into clicking something different from what the user perceives, 
          potentially revealing confidential information or taking control of their computer.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">Clickjacking Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Unauthorized actions performed by users</li>
            <li>Account hijacking</li>
            <li>Financial fraud</li>
            <li>Data theft</li>
            <li>Malware installation</li>
            <li>Social media manipulation</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic Clickjacking Attacks</h3>
          
          <h4 className="font-medium mb-1 mt-3">Transparent Overlay</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<iframe src="https://vulnerable-site.com" style="opacity:0.5;position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
<button style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);z-index:1;">
  Click Me (Innocent Button)
</button>`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Cursorjacking</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<style>
  #fake-cursor { position: absolute; pointer-events: none; }
</style>
<img id="fake-cursor" src="cursor.png">
<script>
  document.addEventListener('mousemove', e => {
    document.getElementById('fake-cursor').style.left = (e.pageX + 15) + 'px';
    document.getElementById('fake-cursor').style.top = (e.pageY + 15) + 'px';
  });
</script>`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Advanced Techniques</h3>
          
          <h4 className="font-medium mb-1 mt-3">Drag-and-Drop Attacks</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<div style="position:absolute;width:100%;height:100%;" 
     ondragover="event.preventDefault()" 
     ondrop="maliciousAction()">
  <iframe src="https://vulnerable-site.com/drag-sensitive-area" 
          style="opacity:0;width:100%;height:100%;"></iframe>
</div>`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Touchjacking (Mobile)</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`<div style="position:fixed;top:0;left:0;width:100%;height:100%;">
  <iframe src="https://mobile-app.com" style="width:100%;height:100%;"></iframe>
  <div style="position:absolute;top:200px;left:100px;width:200px;height:50px;"></div>
</div>`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Real-World Attack Scenarios</h3>
          
          <h4 className="font-medium mb-1 mt-3">Social Media Likejacking</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. Attacker creates fake "Like" button over real content
2. User clicks what appears to be a news article
3. Actually likes/lends credibility to malicious page`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Bank Transfer Hijacking</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. User logs into online banking
2. Visits malicious site with invisible banking iframe
3. Clicks on "Show funny cat" button that aligns with transfer button`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Tools & Automation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Testing Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Suite Clickbandit</li>
            <li>OWASP Zap</li>
            <li>ClickjackingTest</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation Frameworks</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>BeEF (Browser Exploitation Framework)</li>
            <li>Social Engineering Toolkit (SET)</li>
            <li>Custom iframe generators</li>
          </ul>
        </article>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Frame Busting Techniques</h3>
          
          <h4 className="font-medium mb-1 mt-3">JavaScript Frame Busting</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`if (top != self) {
  top.location = self.location;
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">X-Frame-Options Header</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// HTTP Header
X-Frame-Options: DENY
// or
X-Frame-Options: SAMEORIGIN`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Content Security Policy</h3>
          
          <h4 className="font-medium mb-1 mt-3">CSP Frame Ancestors</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Content-Security-Policy: frame-ancestors 'none';
// or
Content-Security-Policy: frame-ancestors 'self';`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Reporting CSP Violations</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Content-Security-Policy: frame-ancestors 'none'; report-uri /csp-violation-report`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Additional Protections</h3>
          
          <h4 className="font-medium mb-1 mt-3">Visual Confirmation</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Add CAPTCHA or confirmation dialogs for sensitive actions
function confirmAction() {
  return confirm("Are you sure you want to perform this action?");
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Session Timeouts</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Short session timeout for sensitive applications
session.setMaxInactiveInterval(300); // 5 minutes`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Framework Protections</h3>
          
          <h4 className="font-medium mb-1 mt-3">Django Protection</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# settings.py
MIDDLEWARE = [
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ...
]`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Spring Security</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers()
            .frameOptions()
            .sameOrigin();
    }
}`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. Monitoring & Detection</h3>
          
          <h4 className="font-medium mb-1 mt-3">Detection Methods</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Frame busting script failures</li>
            <li>Unexpected referrer headers</li>
            <li>Multiple rapid clicks from same user</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Response Actions</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Force re-authentication</li>
            <li>Temporary account lock</li>
            <li>User notification</li>
          </ul>
        </article>
      </section>





      <div className="mb-12 p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">Clickjacking Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Implement X-Frame-Options header (DENY or SAMEORIGIN)</li>
          <li>Use Content-Security-Policy frame-ancestors directive</li>
          <li>Add frame-busting JavaScript as secondary defense</li>
          <li>Require confirmation for sensitive actions</li>
          <li>Educate users about potential clickjacking risks</li>
          <li>Regularly test your defenses against clickjacking</li>
          <li>Monitor for frame-busting script failures</li>
          <li>Implement short session timeouts for sensitive applications</li>
        </ul>
      </div>






      <section className="mb-12">
        <h2 className="text-3xl font-semibold mb-4">Additional Resources & References</h2>
        <div className="space-y-6">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Learning Resources</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://owasp.org/www-community/attacks/Clickjacking" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP Clickjacking — Comprehensive documentation
                </a>
              </li>
              <li>
                <a href="https://portswigger.net/web-security/clickjacking" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PortSwigger Academy — Clickjacking labs
                </a>
              </li>
              <li>
                <a href="https://cure53.de/fp170.pdf" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Cure53 — Clickjacking research paper
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://portswigger.net/burp/documentation/desktop/tools/clickbandit" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Burp Suite Clickbandit — Proof-of-concept generator
                </a>
              </li>
              <li>
                <a href="https://github.com/lnxg33k/clickjacking" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Clickjacking Tester — Automated detection
                </a>
              </li>
              <li>
                <a href="https://github.com/beefproject/beef" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  BeEF — Browser exploitation framework
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

    </main>
  );
}
