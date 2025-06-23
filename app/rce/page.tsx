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
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Defensive Strategies</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Secure Coding Practices</h3>
          
          <h4 className="font-medium mb-1 mt-3">Input Validation</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Safe input handling example
if (isValidInput(userInput)) {
  safeProcess(userInput);
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Parameterized Commands</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Safe command execution pattern
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "4", validatedInput);
Process p = pb.start();`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. System Hardening</h3>
          
          <h4 className="font-medium mb-1 mt-3">Least Privilege</h4>
          <div className="bg-gray-700 p-3 rounded">
            <p>Run services with minimal required permissions</p>
          </div>

          <h4 className="font-medium mb-1 mt-3">Function Restrictions</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# PHP disable_functions example
disable_functions = exec,passthru,shell_exec,system`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Monitoring & Detection</h3>
          
          <h4 className="font-medium mb-1 mt-3">Anomaly Detection</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Unexpected process execution</li>
            <li>Unusual command patterns</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Log Analysis</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Command execution auditing</li>
            <li>Failed execution attempts</li>
          </ul>
        </article>
      </section>

      <section className="mb-12">
        <h2 className="text-3xl font-semibold mb-4">Educational Resources</h2>
        <div className="space-y-6">
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Learning Materials</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://owasp.org/www-community/attacks/Command_Injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP Command Injection Documentation
                </a>
              </li>
              <li>
                <a href="https://cwe.mitre.org/data/definitions/94.html" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  MITRE CWE-94: Code Injection
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Standards</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP Command Injection Defense
                </a>
              </li>
              <li>
                <a href="https://www.nist.gov/cyberframework" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  NIST Cybersecurity Framework
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

      <div className="p-4 bg-gray-800 rounded-lg border-l-4 border-purple-500">
        <h3 className="text-lg font-semibold mb-2 text-purple-400">Security Best Practices</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Never execute unsanitized user input</li>
          <li>Use safe API alternatives to system commands</li>
          <li>Implement proper input validation</li>
          <li>Regularly audit code for dangerous functions</li>
          <li>Maintain updated security patches</li>
          <li>Conduct security training for developers</li>
        </ul>
      </div>

      <div className="mt-8 p-4 bg-red-900 rounded-lg">
        <h3 className="text-lg font-semibold mb-2 text-red-300">Legal Notice</h3>
        <p className="text-sm">
          This content is provided for educational purposes only. Never test security vulnerabilities 
          against systems without explicit permission. Unauthorized testing may violate laws.
        </p>
      </div>
    </main>
  );
}