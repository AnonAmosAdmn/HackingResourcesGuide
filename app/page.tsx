import React from 'react';
import Head from 'next/head';
import Link from 'next/link';

const vulnerabilities = [
  {
    name: 'SQL Injection',
    path: '/sql-injection',
    image: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI2NCIgaGVpZ2h0PSI2NCIgdmlld0JveD0iMCAwIDY0IDY0Ij48cmVjdCB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIGZpbGw9IiNmZjY2NjYiIHJ4PSI4IiByeT0iOCIvPjx0ZXh0IHg9IjUwJSIgeT0iNTAlIiBkb21pbmFudC1iYXNlbGluZT0ibWlkZGxlIiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmb250LWZhbWlseT0ibW9ub3NwYWNlIiBmb250LXdlaWdodD0iYm9sZCIgZm9udC1zaXplPSIyNCIgZmlsbD0iI2ZmZiI+U1FMPC90ZXh0Pjwvc3ZnPg=='
  },
  {
    name: 'XSS (Cross-Site Scripting)',
    path: '/xss',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjZmY4ODAwIi8+PHRleHQgeD0iMTIiIHk9IjE1IiBmb250LXNpemU9IjEwIiBmb250LWZhbWlseT0iQXJpYWwiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZpbGw9IndoaXRlIj5YU1M8L3RleHQ+PC9zdmc+'
  },
  {
    name: 'CSRF (Cross-Site Request Forgery)',
    path: '/csrf',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjYjBkMmZmIi8+PHRleHQgeD0iMTIiIHk9IjE1IiBmb250LXNpemU9IjgiIGZvbnQtZmFtaWx5PSJBcmlhbCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiPkNTUkY8L3RleHQ+PC9zdmc+'
  },

  {
    name: 'RCE (Remote Code Execution)',
    path: '/rce',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjMDA5OTAwIi8+PHRleHQgeD0iMTIiIHk9IjE1IiBmb250LXNpemU9IjgiIGZvbnQtZmFtaWx5PSJBcmlhbCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiPlJDRTwvdGV4dD48L3N2Zz4='
  },

  {
    name: 'LFI (Local File Inclusion)',
    path: '/file-inclusion',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjOGU0NGFkIi8+PHRleHQgeD0iMTIiIHk9IjE1IiBmb250LXNpemU9IjgiIGZvbnQtZmFtaWx5PSJBcmlhbCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiPkxGSTwvdGV4dD48L3N2Zz4='
  },

  {
    name: 'IDOR (Insecure Direct Object Reference)',
    path: '/idor',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjZTYwMDgwIi8+PHRleHQgeD0iMTIiIHk9IjE1IiBmb250LXNpemU9IjgiIGZvbnQtZmFtaWx5PSJBcmlhbCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiPklET1I8L3RleHQ+PC9zdmc+'
  },

  {
    name: 'SSRF (Server-Side Request Forgery)',
    path: '/ssrf',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PHJlY3Qgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjZmY4ODAwIi8+PHRleHQgeD0iMTIiIHk9IjE1IiBmb250LXNpemU9IjgiIGZvbnQtZmFtaWx5PSJBcmlhbCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiPlNTUkY8L3RleHQ+PC9zdmc+'
  },


  {
    name: 'Clickjacking',
    path: '/clickjacking',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIGZpbGw9IiMwMGFhMDAiLz48dGV4dCB4PSIxMiIgeT0iMTAiIGZvbnQtc2l6ZT0iOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiPkNsaWNrPC90ZXh0Pjx0ZXh0IHg9IjEyIiB5PSIyMCIgZm9udC1zaXplPSI4IiB0ZXh0LWFuY2hvcj0ibWlkZGxlIiBmaWxsPSJ3aGl0ZSI+amFja2luZzwvdGV4dD48L3N2Zz4='
  },


  {
    name: 'Open Redirect',
    path: '/open-redirect',
    image: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cmVjdCB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIGZpbGw9IiNmZjAwMDAiLz48dGV4dCB4PSIxMiIgeT0iMTAiIGZvbnQtc2l6ZT0iOCIgdGV4dC1hbmNob3I9Im1pZGRsZSIgZmlsbD0id2hpdGUiPk9wZW48L3RleHQ+PHRleHQgeD0iMTIiIHk9IjIwIiBmb250LXNpemU9IjgiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGZpbGw9IndoaXRlIj5SZWRpcmVjdDwvdGV4dD48L3N2Zz4='
  },

];



export default function Home() {
  return (
    <>
      <Head>
        <title>Hacker Resource Guide – Vulnerability Index</title>
      </Head>
      <main className="p-8 max-w-5xl mx-auto text-center">
        <h1 className="text-4xl font-bold mb-6 text-purple-600">Hacker Resource Guide</h1>
        <div className="grid grid-cols-1 md:grid-cols-1 gap-6">
          {vulnerabilities.map((v) => (
            <Link href={v.path} key={v.path} className="group">
              <div
                tabIndex={0}
                role="link"
                className="bg-gray-100 hover:bg-purple-100 transition rounded-lg shadow p-4 flex items-start gap-4 text-left cursor-pointer"
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  width={48}
                  height={48}
                  src={v.image}
                  alt={`${v.name} icon`}
                  className="w-12 h-12 object-contain bg-white rounded border border-black/10 shadow-sm"
                />
                <div>
                  <h2 className="text-xl font-semibold text-purple-800 group-hover:underline">{v.name}</h2>
                </div>
              </div>
            </Link>
          ))}
        </div>
      </main>
    </>
  );
}
