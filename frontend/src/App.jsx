import { useState, useEffect, useCallback } from 'react';

// Time ago helper
function timeAgo(dateStr) {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// Check if device was first seen within last 24h
function isNewDevice(firstSeen) {
  return Date.now() - new Date(firstSeen).getTime() < 24 * 60 * 60 * 1000;
}

export default function App() {
  const [status, setStatus] = useState(null);
  const [devices, setDevices] = useState([]);
  const [scanStatus, setScanStatus] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('dashboard'); // dashboard | devices
  const [scanning, setScanning] = useState(false);

  const fetchStatus = useCallback(() => {
    fetch('/api/v1/status')
      .then((r) => r.json())
      .then((data) => {
        setStatus(data);
        setScanStatus(data.scan);
      })
      .catch((e) => setError(e.message));
  }, []);

  const fetchDevices = useCallback(() => {
    fetch('/api/v1/devices')
      .then((r) => r.json())
      .then((data) => setDevices(data.devices || []))
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchDevices();
    const interval = setInterval(() => {
      fetchStatus();
      fetchDevices();
    }, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, [fetchStatus, fetchDevices]);

  const triggerScan = () => {
    setScanning(true);
    fetch('/api/v1/scan', { method: 'POST' })
      .then((r) => r.json())
      .then(() => {
        // Poll faster while scanning
        const poll = setInterval(() => {
          fetchStatus();
          fetchDevices();
          fetch('/api/v1/scan/status')
            .then((r) => r.json())
            .then((s) => {
              if (!s.running) {
                setScanning(false);
                clearInterval(poll);
              }
            });
        }, 2000);
      })
      .catch(() => setScanning(false));
  };

  const newDeviceCount = devices.filter((d) => isNewDevice(d.first_seen)).length;

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
          <div className="flex items-center gap-4">
            <nav className="flex gap-1">
              {['dashboard', 'devices'].map((v) => (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                    view === v
                      ? 'bg-gray-800 text-white'
                      : 'text-gray-400 hover:text-gray-200'
                  }`}
                >
                  {v.charAt(0).toUpperCase() + v.slice(1)}
                  {v === 'devices' && newDeviceCount > 0 && (
                    <span className="ml-1.5 bg-amber-500 text-black text-xs font-bold px-1.5 py-0.5 rounded-full">
                      {newDeviceCount}
                    </span>
                  )}
                </button>
              ))}
            </nav>
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

      <main className="max-w-7xl mx-auto px-6 py-8">
        {view === 'dashboard' ? (
          <DashboardView
            devices={devices}
            scanStatus={scanStatus}
            newDeviceCount={newDeviceCount}
            scanning={scanning}
            onScan={triggerScan}
            onViewDevices={() => setView('devices')}
          />
        ) : (
          <DevicesView
            devices={devices}
            scanning={scanning}
            onScan={triggerScan}
            scanStatus={scanStatus}
          />
        )}
      </main>
    </div>
  );
}

function DashboardView({ devices, scanStatus, newDeviceCount, scanning, onScan, onViewDevices }) {
  return (
    <>
      {/* Stats row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Devices"
          value={devices.length || '—'}
          sub={
            devices.length > 0
              ? `${newDeviceCount} new (24h)`
              : 'Awaiting scan'
          }
          highlight={newDeviceCount > 0}
        />
        <StatCard label="Events (24h)" value="—" sub="No data yet" />
        <StatCard label="Threats" value="0" sub="All clear" />
        <StatCard label="DNS Queries" value="—" sub="Pi-hole not connected" />
      </div>

      {/* New device alert banner */}
      {newDeviceCount > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-amber-500/20 rounded-full flex items-center justify-center">
              <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <div>
              <p className="text-amber-200 font-medium">
                {newDeviceCount} new device{newDeviceCount > 1 ? 's' : ''} detected
              </p>
              <p className="text-amber-200/60 text-sm">
                First seen on your network in the last 24 hours
              </p>
            </div>
          </div>
          <button
            onClick={onViewDevices}
            className="bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            View Devices
          </button>
        </div>
      )}

      {/* Empty / action state */}
      {devices.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <div className="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <h2 className="text-lg font-medium text-gray-300">Welcome to Vedetta</h2>
          <p className="text-gray-500 mt-2 max-w-md mx-auto">
            Your network watchtower is ready. Run a network scan to discover devices on your network.
          </p>
          <div className="mt-6 flex justify-center gap-3">
            <button
              onClick={onScan}
              disabled={scanning}
              className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:text-blue-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              {scanning && <Spinner />}
              {scanning ? 'Scanning...' : 'Run Network Scan'}
            </button>
          </div>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-medium">Recent Devices</h2>
            <button
              onClick={onViewDevices}
              className="text-sm text-blue-400 hover:text-blue-300"
            >
              View all →
            </button>
          </div>
          <DeviceTable devices={devices.slice(0, 5)} compact />
        </div>
      )}
    </>
  );
}

function DevicesView({ devices, scanning, onScan, scanStatus }) {
  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold">Device Inventory</h2>
          <p className="text-gray-400 text-sm mt-1">
            {devices.length} device{devices.length !== 1 ? 's' : ''} discovered
            {scanStatus?.last_scan && (
              <> · Last scan {timeAgo(scanStatus.last_scan)}</>
            )}
          </p>
        </div>
        <button
          onClick={onScan}
          disabled={scanning}
          className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:text-blue-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
        >
          {scanning && <Spinner />}
          {scanning ? 'Scanning...' : 'Scan Now'}
        </button>
      </div>

      {devices.length > 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <DeviceTable devices={devices} />
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <p className="text-gray-500">No devices found yet. Run a scan to discover your network.</p>
        </div>
      )}
    </>
  );
}

function DeviceTable({ devices, compact = false }) {
  return (
    <table className="w-full">
      <thead>
        <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800">
          <th className="px-4 py-3">Status</th>
          <th className="px-4 py-3">IP Address</th>
          <th className="px-4 py-3">Hostname</th>
          <th className="px-4 py-3">Vendor</th>
          <th className="px-4 py-3">MAC</th>
          {!compact && <th className="px-4 py-3">Ports</th>}
          <th className="px-4 py-3">First Seen</th>
          <th className="px-4 py-3">Last Seen</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((device) => {
          const isNew = isNewDevice(device.first_seen);
          return (
            <tr
              key={device.device_id}
              className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors"
            >
              <td className="px-4 py-3">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 bg-green-400 rounded-full" />
                  {isNew && (
                    <span className="bg-amber-500 text-black text-xs font-bold px-1.5 py-0.5 rounded">
                      NEW
                    </span>
                  )}
                </div>
              </td>
              <td className="px-4 py-3 font-mono text-sm">{device.ip_address}</td>
              <td className="px-4 py-3 text-sm">
                {device.hostname || <span className="text-gray-600">—</span>}
              </td>
              <td className="px-4 py-3 text-sm text-gray-400">{device.vendor || '—'}</td>
              <td className="px-4 py-3 font-mono text-xs text-gray-500">{device.mac_address}</td>
              {!compact && (
                <td className="px-4 py-3 text-sm">
                  {device.open_ports && device.open_ports.length > 0 ? (
                    <div className="flex gap-1 flex-wrap">
                      {device.open_ports.map((p) => (
                        <span key={p} className="bg-gray-800 text-gray-300 text-xs px-1.5 py-0.5 rounded">
                          {p}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-gray-600">—</span>
                  )}
                </td>
              )}
              <td className="px-4 py-3 text-sm text-gray-400">{timeAgo(device.first_seen)}</td>
              <td className="px-4 py-3 text-sm text-gray-400">{timeAgo(device.last_seen)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function StatCard({ label, value, sub, highlight = false }) {
  return (
    <div className={`bg-gray-900 border rounded-lg p-4 ${highlight ? 'border-amber-500/40' : 'border-gray-800'}`}>
      <p className="text-sm text-gray-400">{label}</p>
      <p className="text-2xl font-semibold mt-1">{value}</p>
      <p className={`text-xs mt-1 ${highlight ? 'text-amber-400' : 'text-gray-500'}`}>{sub}</p>
    </div>
  );
}

function Spinner() {
  return (
    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}
