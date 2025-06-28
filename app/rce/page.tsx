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
        </p>
      </section>
    </div>
  );
}
