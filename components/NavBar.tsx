'use client'; // Add this at the top to make it a Client Component

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const NavBar = () => {
  const pathname = usePathname();
  
  const navItems = [
    { name: 'Home', path: '/' },
    { name: 'SQL Injection', path: '/sql-injection' },
    { name: 'XSS', path: '/xss' },
    { name: 'CSRF', path: '/csrf' },
    { name: 'RCE', path: '/rce' },
    { name: 'LFI', path: '/file-inclusion' },
    { name: 'IDOR', path: '/idor' },
    { name: 'SSRF', path: '/ssrf' },
    { name: 'Clickjacking', path: '/clickjacking' },
    { name: 'Open Redirect', path: '/open-redirect' },
  ];

  return (
    <nav className="bg-gray-800 text-white shadow-lg">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex justify-between h-16">
          <div className="flex items-center">
            <Link href="/" className="text-xl font-semibold hover:text-purple-300">
              Hacker Resource Guide
            </Link>
          </div>
          <div className="hidden md:flex items-center space-x-1 overflow-x-auto">
            {navItems.map((item) => (
              <Link 
                key={item.path} 
                href={item.path}
                className={`px-3 py-2 rounded-md text-sm font-medium whitespace-nowrap ${
                  pathname === item.path 
                    ? 'bg-purple-900 text-white' 
                    : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                }`}
              >
                {item.name}
              </Link>
            ))}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default NavBar;