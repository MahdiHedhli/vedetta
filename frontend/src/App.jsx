import { useState, useEffect } from 'react';

export default function App() {
  const [status, setStatus] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch('/api/v1/status')
      .then((res) => res.json())
      .then(setStatus)
      .catch((err) => setError(err.message));
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center font-bold text-sm">
              V
            </div>
            <h1 className="text-xl font-semibold tracking-tight">Vedetta</h1>
            <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">
              v0.1.0-dev
            </span>
          </div>
          <div className="flex items-center gap-2">
            {status ? (
              <span className="flex items-center gap-1.5 text-sm text-green-400">
                <span className="w-2 h-2 bg-green-400 rounded-full" />
                Connected
              </span>
            ) : error ? (
              <span className="flex items-center gap-1.5 text-sm text-red-400">
                <span className="w-2 h-2 bg-red-400 rounded-full" />
                Disconnected
              </span>
            ) : (
              <span className="text-sm text-gray-500">Connecting...</span>
            )}
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Stats row */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          {[
            { label: 'Devices', value: '—', sub: 'Awaiting scan' },
            { label: 'Events (24h)', value: '—', sub: 'No data yet' },
            { label: 'Threats', value: '0', sub: 'All clear' },
            { label: 'DNS Queries', value: '—', sub: 'Pi-hole not connected' },
          ].map((stat) => (
            <div
              key={stat.label}
              className="bg-gray-900 border border-gray-800 rounded-lg p-4"
            >
              <p className="text-sm text-gray-400">{stat.label}</p>
              <p className="text-2xl font-semibold mt-1">{stat.value}</p>
              <p className="text-xs text-gray-500 mt-1">{stat.sub}</p>
            </div>
          ))}
        </div>

        {/* Empty state */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <div className="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg
              className="w-8 h-8 text-gray-500"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
              />
            </svg>
          </div>
          <h2 className="text-lg font-medium text-gray-300">
            Welcome to Vedetta
          </h2>
          <p className="text-gray-500 mt-2 max-w-md mx-auto">
            Your network watchtower is ready. Connect Pi-hole and run your first
            network scan to start monitoring.
          </p>
          <div className="mt-6 flex justify-center gap-3">
            <button className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
              Run Network Scan
            </button>
            <button className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
              Connect Pi-hole
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}
