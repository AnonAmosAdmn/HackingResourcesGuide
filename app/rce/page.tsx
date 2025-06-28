// File: /app/rce-safe/page.tsx
export default function RCESafePage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">
        Remote Code Execution (RCE) Security Guide
      </h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">Understanding RCE</h2>
        <p className="leading-relaxed">
          Remote Code Execution vulnerabilities allow attackers to execute arbitrary commands on a target system.
          This guide focuses on understanding and preventing these vulnerabilities without providing executable examples.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">Theoretical Impact:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>System compromise</li>
            <li>Data exposure</li>
            <li>Service disruption</li>
            <li>Lateral movement</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Attack Vectors (Offensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Common Vulnerability Patterns</h3>
          
          <h4 className="font-medium mb-1 mt-3">Unsanitized Input</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Example of vulnerable pattern (do not use)
// Unsafe user input concatenation
system("ping " + userInput);`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Dangerous Functions</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Functions often involved in RCE vulnerabilities
eval(), exec(), system(), passthru()
Runtime.getRuntime().exec()
Process.Start()`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Vulnerability Categories</h3>
          
          <h4 className="font-medium mb-1 mt-3">Injection Flaws</h4>
          <div className="bg-gray-700 p-3 rounded">
            <p>When user input is interpreted as code or commands</p>
          </div>

          <h4 className="font-medium mb-1 mt-3">Deserialization Issues</h4>
          <div className="bg-gray-700 p-3 rounded">
            <p>When untrusted data is deserialized without proper validation</p>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Security Research Resources</h3>
          
          <h4 className="font-medium mb-1 mt-3">Academic Papers</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>MITRE CWE-78: OS Command Injection</li>
            <li>OWASP Top 10 A03: Injection</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Testing Methodologies</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Static code analysis</li>
            <li>Input validation testing</li>
            <li>Sandboxed environments</li>
          </ul>
        </article>
      </section>


      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Input Validation & Sanitization</h3>
          
          <h4 className="font-medium mb-1 mt-3">Command Injection Prevention</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Safe command execution in Node.js
const { exec } = require('child_process');
const userInput = sanitize(req.query.input);
exec(`ping -c 4 ${userInput}`, (error, stdout, stderr) => {
  // Handle output
});`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Parameterized Queries</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Python SQL with parameters
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Secure Coding Practices</h3>
          
          <h4 className="font-medium mb-1 mt-3">Safe Deserialization</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Java safe deserialization
ObjectInputStream ois = new ObjectInputStream(input) {
  @Override
  protected Class<?> resolveClass(ObjectStreamClass desc) 
    throws IOException, ClassNotFoundException {
    if (!desc.getName().equals("safe.package.TrustedClass")) {
      throw new InvalidClassException("Unauthorized deserialization");
    }
    return super.resolveClass(desc);
  }
};`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Template Engine Security</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Django template autoescape
from django.utils.html import escape
user_content = escape(untrusted_input)`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. System Hardening</h3>
          
          <h4 className="font-medium mb-1 mt-3">Memory Protections</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>DEP (Data Execution Prevention)</li>
            <li>ASLR (Address Space Layout Randomization)</li>
            <li>Stack canaries</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Least Privilege</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Run services with minimal permissions</li>
            <li>Use containers with restricted capabilities</li>
            <li>Implement proper sandboxing</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Monitoring & Detection</h3>
          
          <h4 className="font-medium mb-1 mt-3">SIEM Rules</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Detect suspicious process execution</li>
            <li>Alert on shell spawning patterns</li>
            <li>Monitor for unusual network connections</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Endpoint Protection</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Behavioral analysis of processes</li>
            <li>Memory protection modules</li>
            <li>Exploit prevention techniques</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. Patch Management</h3>
          
          <h4 className="font-medium mb-1 mt-3">Vulnerability Scanning</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Regular dependency scanning (OWASP DC)</li>
            <li>Static and dynamic code analysis</li>
            <li>Binary hardening checks</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Patch Prioritization</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>CVSS scoring for RCE vulnerabilities</li>
            <li>Zero-day mitigation strategies</li>
            <li>Emergency patch procedures</li>
          </ul>
        </article>
      </section>

      <div className="mb-12 p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">RCE Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Implement strict input validation</li>
          <li>Use safe APIs for command execution</li>
          <li>Apply proper output encoding</li>
          <li>Enable memory protection mechanisms</li>
          <li>Keep all components patched</li>
          <li>Monitor for suspicious execution patterns</li>
          <li>Conduct regular security testing</li>
        </ul>
      </div>

      <section className="mb-12">
        <h2 className="text-3xl font-semibold mb-4">Additional Resources & References</h2>
        <div className="space-y-6">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Learning Resources</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://owasp.org/www-community/attacks/Code_Injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP Code Injection — Comprehensive documentation
                </a>
              </li>
              <li>
                <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PayloadsAllTheThings RCE — Cheat sheet
                </a>
              </li>
              <li>
                <a href="https://book.hacktricks.xyz/pentesting-web/command-injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  HackTricks RCE Techniques
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://www.metasploit.com/" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Metasploit Framework — Exploitation toolkit
                </a>
              </li>
              <li>
                <a href="https://github.com/frohoff/ysoserial" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  ysoserial — Java deserialization payloads
                </a>
              </li>
              <li>
                <a href="https://revshells.com/" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  Reverse Shell Generator — Interactive payload creator
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>
    </main>
  );
}
