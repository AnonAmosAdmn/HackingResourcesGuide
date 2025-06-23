// File: /app/lfi-rfi-safe/page.tsx
export default function LfiRfiSafePage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">
        LFI/RFI Security Awareness Guide
      </h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">Understanding File Inclusion Vulnerabilities</h2>
        <p className="leading-relaxed">
          File Inclusion vulnerabilities occur when applications improperly include files without proper validation.
          This guide explains the risks and defenses without providing executable exploit content.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">Potential Impacts:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Sensitive data exposure</li>
            <li>Application source code disclosure</li>
            <li>System information leakage</li>
            <li>Possible remote code execution</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Vulnerability Patterns (Offensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Common Vulnerability Types</h3>
          
          <h4 className="font-medium mb-1 mt-3">Basic Inclusion Patterns</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Example of vulnerable pattern (do not use)
$page = $_GET['page'];
include($page . '.php');`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Dangerous PHP Functions</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`include(), include_once()
require(), require_once()
fopen(), file_get_contents()`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Security Research Concepts</h3>
          
          <h4 className="font-medium mb-1 mt-3">Path Traversal</h4>
          <div className="bg-gray-700 p-3 rounded">
            <p>Attempting to access files outside web root using ../ sequences</p>
          </div>

          <h4 className="font-medium mb-1 mt-3">Wrapper Techniques</h4>
          <div className="bg-gray-700 p-3 rounded">
            <p>Using protocol wrappers to manipulate file handling (php://, data://)</p>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Academic Resources</h3>
          
          <h4 className="font-medium mb-1 mt-3">Reference Materials</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>MITRE CWE-98: PHP File Inclusion</li>
            <li>OWASP Top 10 A05: Security Misconfiguration</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Testing Methodologies</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Static code analysis</li>
            <li>Input validation testing</li>
            <li>Controlled environment testing</li>
          </ul>
        </article>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Protection Strategies</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Secure Coding Practices</h3>
          
          <h4 className="font-medium mb-1 mt-3">Whitelist Approach</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Safe file inclusion example
$allowed = ['home', 'about', 'contact'];
if (in_array($_GET['page'], $allowed)) {
    include($_GET['page'] . '.php');
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Basename Protection</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`$file = basename($_GET['file']);
include('/templates/' . $file);`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Server Configuration</h3>
          
          <h4 className="font-medium mb-1 mt-3">PHP Hardening</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`; php.ini security settings
allow_url_fopen = Off
allow_url_include = Off
open_basedir = /var/www/html/`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Web Server Restrictions</h4>
          <div className="bg-gray-700 p-3 rounded">
            <p>Configure server to prevent access outside web root</p>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Monitoring & Detection</h3>
          
          <h4 className="font-medium mb-1 mt-3">Attack Indicators</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Multiple ../ sequences in requests</li>
            <li>Attempts to access known sensitive files</li>
            <li>PHP wrapper usage attempts</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Response Actions</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Log and block suspicious requests</li>
            <li>Review application logs</li>
            <li>Update input validation rules</li>
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
                <a href="https://owasp.org/www-community/attacks/File_Inclusion" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP File Inclusion Documentation
                </a>
              </li>
              <li>
                <a href="https://cwe.mitre.org/data/definitions/98.html" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  MITRE CWE-98: PHP File Inclusion
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Defensive Guides</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP File Upload Security
                </a>
              </li>
              <li>
                <a href="https://www.php.net/manual/en/security.filesystem.php" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PHP Filesystem Security
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

      <div className="p-4 bg-gray-800 rounded-lg border-l-4 border-purple-500">
        <h3 className="text-lg font-semibold mb-2 text-purple-400">Security Best Practices</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Never include files based on unvalidated user input</li>
          <li>Use whitelists for allowed files/paths</li>
          <li>Disable dangerous PHP functions and features</li>
          <li>Configure open_basedir restrictions</li>
          <li>Regularly audit file inclusion patterns</li>
          <li>Implement proper file permissions</li>
        </ul>
      </div>

      <div className="mt-8 p-4 bg-red-900 rounded-lg">
        <h3 className="text-lg font-semibold mb-2 text-red-300">Legal Notice</h3>
        <p className="text-sm">
          This content is provided for educational purposes only to help secure applications.
          Never test vulnerabilities against systems without explicit permission.
          Unauthorized testing may violate laws and regulations.
        </p>
      </div>
    </main>
  );
}