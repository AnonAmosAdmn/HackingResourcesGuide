// File: /app/idor/page.tsx
export default function IDORPage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">
        IDOR (Insecure Direct Object Reference) Comprehensive Guide
      </h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is IDOR?</h2>
        <p className="leading-relaxed">
          Insecure Direct Object Reference (IDOR) occurs when an application provides direct access to objects based on user-supplied input without proper authorization checks.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">1. IDOR Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Unauthorized data access (PII, financial records, etc.)</li>
            <li>Data modification or deletion</li>
            <li>Account takeover</li>
            <li>Privilege escalation</li>
            <li>Compliance violations</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>


        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-600">1. Basic IDOR</h3>
          <p className="mb-3">
            Basic Insecure Direct Object Reference (IDOR) vulnerabilities occur when an application exposes a direct reference to an internal object, such as a file, database record, or user account, without enforcing proper authorization checks.
            Attackers can manipulate these references to access or modify data they shouldn’t be able to.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example URL Manipulation:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`GET /documents/1001
// Attacker changes URL to access another user's document:
GET /documents/1002`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">By modifying the document ID, the attacker can access unauthorized content.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common Attack Vectors:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
                <li>Predictable or sequential object IDs</li>
                <li>Insufficient authorization checks on object access</li>
                <li>Direct references exposed in URLs, forms, or APIs</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-400">
                <li>Implement strict authorization checks on every object access</li>
                <li>Use indirect references or mapping (e.g., UUIDs, tokens)</li>
                <li>Avoid predictable IDs and enforce access control by user role</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-600">2. Horizontal IDOR</h3>
          <p className="mb-3">
            Horizontal IDOR occurs when a user is able to access or manipulate data belonging to another user with the same privilege level by modifying object references like user IDs. This allows attackers to bypass authorization by impersonating peers.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Scenario:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`GET /profile/view?user_id=1001
// Attacker changes user_id to view another user's profile:
GET /profile/view?user_id=1002`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">By changing the user ID parameter, the attacker accesses another user’s private information.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common Indicators:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
                <li>URLs or APIs exposing user-identifiers in parameters</li>
                <li>Lack of verification that the requested resource belongs to the authenticated user</li>
                <li>Similar privilege levels for both attacker and victim accounts</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Prevention Measures:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-400">
                <li>Always verify resource ownership before granting access</li>
                <li>Use session-based identity checks rather than user-supplied parameters</li>
                <li>Implement role-based access controls (RBAC) to restrict data visibility</li>
              </ul>
            </div>
          </div>
        </article>




        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-600">3. Vertical IDOR</h3>
          <p className="mb-3">
            Vertical IDOR happens when a lower-privileged user gains access to resources or functionality meant only for higher-privileged roles (e.g., admin-only pages or actions) by manipulating direct object references without proper authorization checks.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Scenario:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`POST /admin/deleteUser
{
  "userId": 123
}  // submitted by a regular user`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                A non-admin user is able to perform an admin-only action by directly calling privileged endpoints.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common Indicators:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
                <li>Privileged functions accessible without role checks</li>
                <li>Endpoints accepting object references without verifying user privilege</li>
                <li>Role escalation possible by changing IDs or parameters</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-400">
                <li>Enforce strict role-based access control (RBAC) on all endpoints</li>
                <li>Validate user privileges before processing sensitive requests</li>
                <li>Use separate APIs or endpoints for admin-level functions</li>
                <li>Audit logs and alerts on privilege escalation attempts</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-600">4. Indirect IDOR</h3>
          <p className="mb-3">
            Indirect IDOR occurs when applications use indirect references—like tokens, hashes, or UUIDs—instead of direct object IDs, but these references are predictable, guessable, or insufficiently protected, allowing attackers to bypass authorization controls.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Scenario:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`GET /files/download?token=abc123def456
// Attacker guesses or enumerates tokens:
GET /files/download?token=abc123def457`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                Although the app uses tokens to obscure real IDs, predictable tokens can still be exploited to access unauthorized resources.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common Signs:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
                <li>Use of opaque or indirect references without proper validation</li>
                <li>Weak or guessable token generation schemes</li>
                <li>Lack of authorization checks tied to the actual user or session</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Prevention Strategies:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-400">
                <li>Use strong, cryptographically secure random tokens</li>
                <li>Validate authorization on every request regardless of token</li>
                <li>Implement token expiration and revocation mechanisms</li>
                <li>Consider user-specific tokens or session binding</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-600">5. Mass Assignment</h3>
          <p className="mb-3">
            Mass Assignment vulnerabilities occur when an application blindly binds user-controlled input (such as JSON or form data) to internal objects without filtering or validating which fields can be modified. This allows attackers to overwrite sensitive or protected properties, like roles or permissions.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Exploit:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`PATCH /user/profile
{
  "username": "attacker",
  "role": "admin"  // unauthorized field modification
}`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                The attacker modifies the user role by including protected fields in the request payload that the backend mistakenly trusts.
              </p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Common Causes:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
                <li>Automatic binding of all request parameters to model objects</li>
                <li>Lack of input validation or whitelist filtering</li>
                <li>Exposing sensitive fields to client input unintentionally</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1 text-gray-400">
                <li>Whitelist allowed fields for binding explicitly</li>
                <li>Use dedicated DTOs (Data Transfer Objects) or input models</li>
                <li>Implement strict server-side validation and authorization</li>
                <li>Avoid exposing sensitive fields in client-side forms or APIs</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-600">IDOR Tools & Automation</h3>

          <h4 className="font-medium mb-1 mt-3">Discovery & Scanning</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Suite (with active scanning and parameter manipulation)</li>
            <li>OWASP ZAP (automated scanning with custom IDOR detection rules)</li>
            <li>ffuf and wfuzz (for brute forcing object IDs and endpoints)</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation & Payload Generation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Intruder (custom payloads to test object reference enumeration)</li>
            <li>Param Miner (detects hidden parameters and IDOR vectors)</li>
            <li>Custom scripts for mass assignment and role escalation payloads</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Post-Exploitation & Analysis</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Collaborator (to detect OOB data leaks)</li>
            <li>Manual access pattern analysis and response comparison</li>
            <li>Logging tools (Splunk, ELK) to monitor unauthorized access attempts</li>
          </ul>
        </article>




      </section>










      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Secure Access Control</h3>
          
          <h4 className="font-medium mb-1 mt-3">Authorization Checks</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Node.js example
function getDocument(req, res) {
  const docId = req.params.id;
  const doc = db.getDocument(docId);
  
  // Verify ownership
  if (doc.owner !== req.user.id) {
    return res.status(403).send('Forbidden');
  }
  res.json(doc);
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Role-Based Access</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Python Django example
@permission_required('app.view_sensitive_data')
def view_data(request, data_id):
    data = get_object_or_404(Data, pk=data_id)
    return render(request, 'data.html', {'data': data})`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Indirect References</h3>
          
          <h4 className="font-medium mb-1 mt-3">UUID Implementation</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Java example
public String generateSecureReference() {
    return UUID.randomUUID().toString();
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Mapping Tables</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Database schema
CREATE TABLE document_access (
    public_id VARCHAR(36) PRIMARY KEY,
    internal_id INT NOT NULL,
    user_id INT NOT NULL
);`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Monitoring & Detection</h3>
          
          <h4 className="font-medium mb-1 mt-3">Anomaly Detection</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Unusual access patterns</li>
            <li>Multiple failed authorization checks</li>
            <li>Rapid sequential ID access</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">WAF Rules</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Block suspicious parameter patterns</li>
            <li>Rate limit sensitive endpoints</li>
            <li>Detect mass enumeration attempts</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Secure Development</h3>
          
          <h4 className="font-medium mb-1 mt-3">Framework Features</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Djangos permission_required</li>
            <li>Spring Security annotations</li>
            <li>Ruby on Rails Pundit</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Code Review</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Static analysis tools</li>
            <li>Manual authorization checks</li>
            <li>Peer review sessions</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. Defense in Depth</h3>
          
          <h4 className="font-medium mb-1 mt-3">Database Layer</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Row-level security</li>
            <li>View-based access</li>
            <li>Stored procedures</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Application Layer</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Middleware authorization</li>
            <li>DTO validation</li>
            <li>Input sanitization</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Presentation Layer</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Token-based references</li>
            <li>Obfuscated identifiers</li>
            <li>Limited data exposure</li>
          </ul>
        </article>
      </section>



      <div className="mb-12 p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">IDOR Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Implement proper authorization checks for all object accesses</li>
          <li>Use indirect references (UUIDs, mapping tables)</li>
          <li>Apply principle of least privilege</li>
          <li>Log and monitor access to sensitive objects</li>
          <li>Conduct regular security audits and code reviews</li>
          <li>Implement rate limiting on sensitive endpoints</li>
          <li>Use framework-provided security features</li>
          <li>Educate developers about IDOR risks</li>
        </ul>
      </div>


      <section className="mb-12">
        <h2 className="text-3xl font-semibold mb-4">Additional Resources & References</h2>
        <div className="space-y-6">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Learning Resources</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP IDOR — Comprehensive documentation
                </a>
              </li>
              <li>
                <a href="https://portswigger.net/web-security/access-control/idor" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PortSwigger Academy — IDOR labs
                </a>
              </li>
              <li>
                <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PayloadsAllTheThings — IDOR cheatsheet
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://portswigger.net/burp" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Burp Suite — Web vulnerability scanner
                </a>
              </li>
              <li>
                <a href="https://github.com/knownsec/pocsuite3" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Pocsuite3 — Vulnerability testing framework
                </a>
              </li>
              <li>
                <a href="https://github.com/s0md3v/Arjun" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Arjun — Parameter discovery tool
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

    </main>
  );
}
