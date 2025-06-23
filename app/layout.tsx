import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import NavBar from "@/components/NavBar"; // Adjust the import path as needed

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Hacker Resource Guide",
  description: 'Study all types of vulnerabilities and hacking techniques',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased`}>
        <div className="min-h-screen flex flex-col">
          <NavBar />
          <main className="flex-1">
            {children}
          </main>
          <div className="mt-8 p-4 bg-red-900 rounded-lg">
            <h3 className="text-lg font-semibold mb-2 text-red-300">Legal Notice</h3>
            <p className="text-sm">
              This content is provided for educational purposes only. Never test security vulnerabilities 
              against systems without explicit permission. Unauthorized testing may violate laws.
            </p>
          </div>
        </div>
      </body>
    </html>
  );
}
