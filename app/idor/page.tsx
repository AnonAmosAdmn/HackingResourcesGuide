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
          <h3 className="text-lg font-semibold mb-2 text-orange-300">IDOR Impact Severity:</h3>
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
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Identification Techniques</h3>
          
          <h4 className="font-medium mb-1 mt-3">Common Parameters</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`user_id
account_id
order_id
document_id
file_id
transaction_id
invoice_number`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Testing Methodology</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Increment numeric IDs (1001 → 1002)</li>
            <li>Try predictable patterns (INV-100 → INV-101)</li>
            <li>Test UUIDs from other accounts</li>
            <li>Check both GET and POST requests</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Advanced Exploitation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Mass Data Extraction</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Automated script example
for id in {1000..2000}; do
  curl "https://example.com/api/user/$id/profile" >> data.txt
done`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Chained Vulnerabilities</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. Find IDOR in profile endpoint
2. Extract API keys from profiles
3. Use keys to access admin endpoints`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Bypass Techniques</h3>
          
          <h4 className="font-medium mb-1 mt-3">Parameter Tampering</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Change parameter names
user_id → account_id
id → uid

# Add parameters
?user_id=1001&debug=true`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">HTTP Method Switching</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`GET /api/user/1001 → POST /api/user
GET /file?id=123 → HEAD /file/123`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Real-World Attack Scenarios</h3>
          
          <h4 className="font-medium mb-1 mt-3">Healthcare Data Leak</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. Find patient_id parameter
2. Increment to access other records
3. Extract sensitive medical data`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">E-commerce Fraud</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`1. Find order_id parameter
2. Modify to access other orders
3. Extract payment details`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. Tools & Automation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Discovery Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Suite Scanner</li>
            <li>OWASP ZAP</li>
            <li>Param Miner</li>
            <li>Arjun</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Intruder</li>
            <li>Postman/Insomnia</li>
            <li>Custom Python scripts</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Analysis Tools</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>jq for JSON processing</li>
            <li>Browser developer tools</li>
            <li>Network analyzers</li>
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

      <div className="p-4 bg-gray-800 rounded-lg border-l-4 border-pink-500">
        <h3 className="text-lg font-semibold mb-2 text-pink-400">IDOR Mitigation Checklist</h3>
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
    </main>
  );
}
