import { useState, useEffect, useCallback } from 'react';

function timeAgo(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (d.getFullYear() < 2000) return '—'; // Go zero-time guard
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  if (seconds < 0) return 'just now';
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function isNewDevice(firstSeen) {
  return Date.now() - new Date(firstSeen).getTime() < 24 * 60 * 60 * 1000;
}

const SEGMENT_COLORS = {
  default: 'bg-blue-500/20 text-blue-300',
  iot: 'bg-purple-500/20 text-purple-300',
  guest: 'bg-green-500/20 text-green-300',
};

export default function App() {
  const [status, setStatus] = useState(null);
  const [devices, setDevices] = useState([]);
  const [targets, setTargets] = useState([]);
  const [sensors, setSensors] = useState([]);
  const [scanStatus, setScanStatus] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('dashboard');
  const [scanning, setScanning] = useState(false);
  const [showSetup, setShowSetup] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [defaultCIDR, setDefaultCIDR] = useState('');

  const fetchStatus = useCallback(() => {
    fetch('/api/v1/status')
      .then((r) => r.json())
      .then((data) => {
        setStatus(data);
        setScanStatus(data.scan);
        if (data.default_cidr) setDefaultCIDR(data.default_cidr);
      })
      .catch((e) => setError(e.message));
  }, []);

  const fetchDevices = useCallback(() => {
    fetch('/api/v1/devices')
      .then((r) => r.json())
      .then((data) => setDevices(data.devices || []))
      .catch(() => {});
  }, []);

  const fetchTargets = useCallback(() => {
    fetch('/api/v1/scan/targets')
      .then((r) => r.json())
      .then((data) => setTargets(data.targets || []))
      .catch(() => {});
  }, []);

  const fetchSensors = useCallback(() => {
    fetch('/api/v1/sensor/list')
      .then((r) => r.json())
      .then((data) => setSensors(data.sensors || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchDevices();
    fetchTargets();
    fetchSensors();

    // Show setup guide if no sensors connected and no devices found
    Promise.all([
      fetch('/api/v1/sensor/list').then((r) => r.json()),
      fetch('/api/v1/devices').then((r) => r.json()),
    ]).then(([sensorData, deviceData]) => {
      const hasSensors = sensorData.sensors && sensorData.sensors.length > 0;
      const hasDevices = deviceData.devices && deviceData.devices.length > 0;
      if (!hasSensors && !hasDevices) {
        setShowSetup(true);
      }
    }).catch(() => {});

    const interval = setInterval(() => {
      fetchStatus();
      fetchDevices();
      fetchSensors();
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchDevices, fetchTargets, fetchSensors]);

  const triggerScan = () => {
    setScanning(true);
    fetch('/api/v1/scan', { method: 'POST' })
      .then((r) => r.json())
      .then(() => {
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

  const triggerTargetScan = (targetId) => {
    setScanning(true);
    fetch(`/api/v1/scan/targets/${targetId}/scan`, { method: 'POST' })
      .then(() => {
        const poll = setInterval(() => {
          fetchStatus();
          fetchDevices();
          fetchTargets();
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
      {/* Sensor setup guide */}
      {showSetup && (
        <SensorSetupDialog onDismiss={() => setShowSetup(false)} />
      )}

      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center font-bold text-sm">V</div>
            <h1 className="text-xl font-semibold tracking-tight">Vedetta</h1>
            <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">v0.1.0-dev</span>
          </div>
          <div className="flex items-center gap-4">
            <nav className="flex gap-1">
              {['dashboard', 'devices', 'sensors', 'scan targets'].map((v) => (
                <button
                  key={v}
                  onClick={() => setView(v)}
                  className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                    view === v ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-gray-200'
                  }`}
                >
                  {v.charAt(0).toUpperCase() + v.slice(1)}
                  {v === 'devices' && newDeviceCount > 0 && (
                    <span className="ml-1.5 bg-amber-500 text-black text-xs font-bold px-1.5 py-0.5 rounded-full">
                      {newDeviceCount}
                    </span>
                  )}
                  {v === 'sensors' && sensors.length > 0 && (
                    <span className="ml-1.5 bg-green-500/20 text-green-300 text-xs font-bold px-1.5 py-0.5 rounded-full">
                      {sensors.length}
                    </span>
                  )}
                </button>
              ))}
            </nav>
            {status ? (
              <span className="flex items-center gap-1.5 text-sm text-green-400">
                <span className="w-2 h-2 bg-green-400 rounded-full" />
                Core Online
              </span>
            ) : error ? (
              <span className="flex items-center gap-1.5 text-sm text-red-400">
                <span className="w-2 h-2 bg-red-400 rounded-full" />
                Disconnected
              </span>
            ) : (
              <span className="text-sm text-gray-500">Connecting...</span>
            )}

            {/* Hamburger menu */}
            <div className="relative">
              <button
                onClick={() => setShowMenu(!showMenu)}
                className="p-1.5 rounded hover:bg-gray-800 transition-colors text-gray-400 hover:text-white"
                aria-label="Menu"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              </button>
              {showMenu && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setShowMenu(false)} />
                  <div className="absolute right-0 mt-2 w-48 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 py-1">
                    <button
                      onClick={() => { setView('logs'); setShowMenu(false); }}
                      className={`w-full text-left px-4 py-2.5 text-sm flex items-center gap-3 transition-colors ${view === 'logs' ? 'bg-gray-800 text-white' : 'text-gray-300 hover:bg-gray-800 hover:text-white'}`}
                    >
                      <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                      Activity Log
                    </button>
                    <button
                      onClick={() => { setView('settings'); setShowMenu(false); }}
                      className={`w-full text-left px-4 py-2.5 text-sm flex items-center gap-3 transition-colors ${view === 'settings' ? 'bg-gray-800 text-white' : 'text-gray-300 hover:bg-gray-800 hover:text-white'}`}
                    >
                      <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                      Settings
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        {view === 'dashboard' ? (
          <DashboardView
            devices={devices} scanStatus={scanStatus} newDeviceCount={newDeviceCount}
            scanning={scanning} onScan={triggerScan} onViewDevices={() => setView('devices')}
            defaultCIDR={defaultCIDR} targets={targets} sensors={sensors}
          />
        ) : view === 'devices' ? (
          <DevicesView devices={devices} scanning={scanning} onScan={triggerScan} scanStatus={scanStatus} />
        ) : view === 'sensors' ? (
          <SensorsView sensors={sensors} onSetup={() => setShowSetup(true)} onRefreshSensors={fetchSensors} />
        ) : view === 'logs' ? (
          <LogsView />
        ) : view === 'settings' ? (
          <SettingsView />
        ) : (
          <ScanTargetsView
            targets={targets} defaultCIDR={defaultCIDR} scanning={scanning}
            onRefresh={fetchTargets} onScanTarget={triggerTargetScan}
          />
        )}
      </main>
    </div>
  );
}

// --- Sensor Setup Dialog ---

function SensorSetupDialog({ onDismiss }) {
  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-lg w-full p-6">
        <h2 className="text-lg font-semibold mb-2">Connect a Sensor</h2>
        <p className="text-gray-400 text-sm mb-5">
          Vedetta uses lightweight sensors that run on your host to discover devices on your network. Install the sensor on any machine connected to your LAN.
        </p>

        <div className="bg-gray-800 rounded-lg p-4 mb-4">
          <p className="text-xs text-gray-400 mb-2 font-medium">Quick start (macOS / Linux):</p>
          <code className="text-sm text-green-400 font-mono block whitespace-pre-wrap">
{`cd sensor && go build -o vedetta-sensor ./cmd/vedetta-sensor
sudo ./vedetta-sensor --core http://localhost:8080`}
          </code>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 mb-4">
          <p className="text-xs text-gray-400 mb-2 font-medium">Options:</p>
          <div className="text-sm text-gray-300 font-mono space-y-1">
            <p><span className="text-blue-400">--cidr</span> 10.0.0.0/24 <span className="text-gray-500"># scan specific subnet</span></p>
            <p><span className="text-blue-400">--interval</span> 5m <span className="text-gray-500"># scan frequency</span></p>
            <p><span className="text-blue-400">--ports</span> <span className="text-gray-500"># include port scan</span></p>
            <p><span className="text-blue-400">--primary</span> <span className="text-gray-500"># register as primary sensor</span></p>
            <p><span className="text-blue-400">--once</span> <span className="text-gray-500"># single scan, then exit</span></p>
          </div>
        </div>

        <p className="text-gray-500 text-xs mb-4">
          The sensor auto-detects your subnet and pushes discovered devices to Core. Run <code className="text-gray-400">sudo</code> for ARP-based discovery (recommended).
        </p>

        <button
          onClick={onDismiss}
          className="w-full bg-blue-600 hover:bg-blue-500 text-white py-2.5 rounded-lg text-sm font-medium transition-colors"
        >
          Got it
        </button>
      </div>
    </div>
  );
}

// --- Sensors View ---

function SensorsView({ sensors, onSetup, onRefreshSensors }) {
  const setPrimary = (sensorId) => {
    fetch(`/api/v1/sensor/${encodeURIComponent(sensorId)}/primary`, { method: 'PUT' })
      .then(() => onRefreshSensors && onRefreshSensors())
      .catch(() => {});
  };

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold">Sensors</h2>
        <button
          onClick={onSetup}
          className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
        >
          + Add Sensor
        </button>
      </div>

      {sensors.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <div className="w-12 h-12 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-6 h-6 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
            </svg>
          </div>
          <p className="text-gray-400 text-sm mb-1">No sensors connected</p>
          <p className="text-gray-500 text-xs">Install vedetta-sensor on a host to start discovering devices</p>
        </div>
      ) : (
        <div className="space-y-3">
          {sensors.map((s) => (
            <div key={s.sensor_id} className={`bg-gray-900 border rounded-lg p-4 ${s.is_primary ? 'border-blue-500/40' : 'border-gray-800'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`w-2.5 h-2.5 rounded-full ${s.status === 'online' ? 'bg-green-400' : 'bg-gray-600'}`} />
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium">{s.hostname}</p>
                      {s.is_primary && (
                        <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">primary</span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500">{s.sensor_id}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm font-mono text-gray-300">{s.cidr}</p>
                  <p className="text-xs text-gray-500">{s.os}/{s.arch} &middot; v{s.version}</p>
                </div>
              </div>
              <div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-800">
                <div className="flex gap-4 text-xs text-gray-500">
                  <span>First seen: {timeAgo(s.first_seen)}</span>
                  <span>Last report: {timeAgo(s.last_seen)}</span>
                </div>
                {!s.is_primary && (
                  <button
                    onClick={() => setPrimary(s.sensor_id)}
                    className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                  >
                    Make Primary
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

// --- Dashboard ---

function DashboardView({ devices, scanStatus, newDeviceCount, scanning, onScan, onViewDevices, defaultCIDR, targets, sensors }) {
  const segmentCounts = {};
  devices.forEach((d) => {
    segmentCounts[d.segment] = (segmentCounts[d.segment] || 0) + 1;
  });

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Devices" value={devices.length || '—'} sub={devices.length > 0 ? `${newDeviceCount} new (24h)` : 'Awaiting sensor data'} highlight={newDeviceCount > 0} />
        <StatCard label="Sensors" value={sensors.length || '0'} sub={sensors.length > 0 ? `${sensors.filter(s => s.status === 'online').length} online` : 'None connected'} highlight={sensors.length === 0} />
        <StatCard label="Threats" value="0" sub="All clear" />
        <StatCard label="DNS Queries" value="—" sub="Pi-hole not connected" />
      </div>

      {newDeviceCount > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-8 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-amber-500/20 rounded-full flex items-center justify-center">
              <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
            </div>
            <div>
              <p className="text-amber-200 font-medium">{newDeviceCount} new device{newDeviceCount > 1 ? 's' : ''} detected</p>
              <p className="text-amber-200/60 text-sm">First seen in the last 24 hours</p>
            </div>
          </div>
          <button onClick={onViewDevices} className="bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
            View Devices
          </button>
        </div>
      )}

      {devices.length === 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <div className="w-16 h-16 bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <h2 className="text-lg font-medium text-gray-300">Welcome to Vedetta</h2>
          <p className="text-gray-500 mt-2 max-w-md mx-auto">Your network watchtower is ready. Run a scan to discover devices.</p>
          <div className="mt-6">
            <button onClick={onScan} disabled={scanning} className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:text-blue-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 mx-auto">
              {scanning && <Spinner />}
              {scanning ? 'Scanning...' : 'Run Network Scan'}
            </button>
          </div>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-medium">Recent Devices</h2>
            <button onClick={onViewDevices} className="text-sm text-blue-400 hover:text-blue-300">View all →</button>
          </div>
          <DeviceTable devices={devices.slice(0, 5)} compact />
        </div>
      )}
    </>
  );
}

// --- Devices ---

function DevicesView({ devices, scanning, onScan, scanStatus }) {
  const [segmentFilter, setSegmentFilter] = useState('all');

  const segments = ['all', ...new Set(devices.map((d) => d.segment).filter(Boolean))];
  const filtered = segmentFilter === 'all' ? devices : devices.filter((d) => d.segment === segmentFilter);

  const exportCSV = () => {
    const headers = ['Status', 'IP Address', 'Hostname', 'Vendor', 'Segment', 'MAC Address', 'Open Ports', 'First Seen', 'Last Seen'];
    const rows = filtered.map((d) => [
      d.is_online ? 'Online' : 'Offline',
      d.ip_address || '',
      d.hostname || '',
      d.vendor || '',
      d.segment || '',
      d.mac_address || '',
      (d.open_ports && d.open_ports.length > 0) ? d.open_ports.map((p) => `${p.port}/${p.protocol}`).join('; ') : '',
      d.first_seen ? new Date(d.first_seen).toISOString() : '',
      d.last_seen ? new Date(d.last_seen).toISOString() : '',
    ]);
    const csvContent = [headers, ...rows]
      .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      .join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const seg = segmentFilter !== 'all' ? `-${segmentFilter}` : '';
    a.download = `vedetta-devices${seg}-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold">Device Inventory</h2>
          <p className="text-gray-400 text-sm mt-1">
            {devices.length} device{devices.length !== 1 ? 's' : ''} discovered
            {scanStatus?.last_scan && <> · Last scan {timeAgo(scanStatus.last_scan)}</>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {filtered.length > 0 && (
            <button onClick={exportCSV} className="bg-gray-700 hover:bg-gray-600 text-gray-200 px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              Export CSV
            </button>
          )}
          <button onClick={onScan} disabled={scanning} className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:text-blue-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
            {scanning && <Spinner />}
            {scanning ? 'Scanning...' : 'Scan All Networks'}
          </button>
        </div>
      </div>

      {/* Segment filter */}
      {segments.length > 2 && (
        <div className="flex gap-2 mb-4">
          {segments.map((seg) => (
            <button
              key={seg}
              onClick={() => setSegmentFilter(seg)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                segmentFilter === seg ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'
              }`}
            >
              {seg === 'all' ? 'All' : seg.charAt(0).toUpperCase() + seg.slice(1)}
              {seg !== 'all' && ` (${devices.filter((d) => d.segment === seg).length})`}
            </button>
          ))}
        </div>
      )}

      {filtered.length > 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <DeviceTable devices={filtered} />
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <p className="text-gray-500">No devices found. Run a scan to discover your network.</p>
        </div>
      )}
    </>
  );
}

// --- Scan Targets ---

function ScanTargetsView({ targets, defaultCIDR, scanning, onRefresh, onScanTarget }) {
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('');
  const [segment, setSegment] = useState('iot');
  const [scanPorts, setScanPorts] = useState(false);

  const addTarget = () => {
    if (!name || !cidr) return;
    fetch('/api/v1/scan/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, cidr, segment, scan_ports: scanPorts }),
    }).then(() => {
      setShowAdd(false);
      setName('');
      setCidr('');
      onRefresh();
    });
  };

  const deleteTarget = (id) => {
    fetch(`/api/v1/scan/targets/${id}`, { method: 'DELETE' }).then(onRefresh);
  };

  const toggleTarget = (id, enabled) => {
    fetch(`/api/v1/scan/targets/${id}/toggle`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    }).then(onRefresh);
  };

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold">Scan Targets</h2>
          <p className="text-gray-400 text-sm mt-1">
            Manage which networks Vedetta scans. The primary subnet is auto-scanned on a schedule. Custom targets are included in every scan cycle.
          </p>
        </div>
        <button onClick={() => setShowAdd(true)} className="bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          Add Network
        </button>
      </div>

      {/* Primary subnet card */}
      <div className="bg-gray-900 border border-blue-500/30 rounded-lg p-4 mb-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Primary Network</span>
              <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">auto-scan</span>
            </div>
            <p className="font-mono text-sm text-gray-400 mt-1">{defaultCIDR || 'Not configured'}</p>
          </div>
          <span className="text-xs text-gray-600">via sensor</span>
        </div>
      </div>

      {/* Custom targets */}
      {targets.length > 0 ? (
        <div className="space-y-2 mb-6">
          {targets.map((t) => (
            <div key={t.target_id} className={`bg-gray-900 border rounded-lg p-4 ${t.enabled ? 'border-gray-800' : 'border-gray-800/50 opacity-60'}`}>
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{t.name}</span>
                    <SegmentBadge segment={t.segment} />
                    {t.scan_ports && <span className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">ports</span>}
                  </div>
                  <p className="font-mono text-sm text-gray-400 mt-1">{t.cidr}</p>
                  {t.last_scan && <p className="text-xs text-gray-500 mt-1">Last scan: {timeAgo(t.last_scan)}</p>}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onScanTarget(t.target_id)}
                    disabled={scanning}
                    className="text-sm text-blue-400 hover:text-blue-300 disabled:text-gray-600"
                  >
                    Scan
                  </button>
                  <button
                    onClick={() => toggleTarget(t.target_id, !t.enabled)}
                    className={`text-sm ${t.enabled ? 'text-amber-400 hover:text-amber-300' : 'text-green-400 hover:text-green-300'}`}
                  >
                    {t.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button onClick={() => deleteTarget(t.target_id)} className="text-sm text-red-400 hover:text-red-300">
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center mb-6">
          <p className="text-gray-500">No custom scan targets. Add networks like your IoT VLAN or guest WiFi.</p>
        </div>
      )}

      {/* Add target form */}
      {showAdd && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-md w-full p-6">
            <h3 className="text-lg font-semibold mb-4">Add Scan Target</h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Name</label>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="IoT Network"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">CIDR</label>
                <input type="text" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.0.50.0/24"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Segment</label>
                <select value={segment} onChange={(e) => setSegment(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue-500">
                  <option value="default">Default</option>
                  <option value="iot">IoT</option>
                  <option value="guest">Guest</option>
                </select>
              </div>
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={scanPorts} onChange={(e) => setScanPorts(e.target.checked)}
                  className="rounded border-gray-600" />
                Scan top 100 ports
              </label>
            </div>

            {/* L2 limitation note */}
            <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 mt-4">
              <div className="flex gap-2">
                <svg className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                  <p className="text-xs text-blue-300">
                    Network discovery works best with a sensor running on each network segment. Remote subnets scanned without a local sensor will have limited fingerprinting (no MAC address or vendor identification).
                  </p>
                  <a
                    href="https://github.com/vedetta-network/vedetta/wiki/Deploying-Sensors"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-blue-400 hover:text-blue-300 mt-1 inline-block"
                  >
                    Learn how to deploy a sensor →
                  </a>
                </div>
              </div>
            </div>

            <div className="flex gap-2 mt-4">
              <button onClick={addTarget} disabled={!name || !cidr}
                className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                Add Target
              </button>
              <button onClick={() => setShowAdd(false)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm font-medium transition-colors">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// --- Activity Log ---

function LogsView() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('all');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchLogs = useCallback(() => {
    fetch('/api/v1/logs?limit=200')
      .then((r) => r.json())
      .then((data) => setLogs(data.logs || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchLogs();
    if (!autoRefresh) return;
    const interval = setInterval(fetchLogs, 3000);
    return () => clearInterval(interval);
  }, [fetchLogs, autoRefresh]);

  const categories = ['all', ...new Set(logs.map((l) => l.category).filter(Boolean))];
  const filtered = filter === 'all' ? logs : logs.filter((l) => l.category === filter);

  const levelColor = (level) => {
    if (level === 'error') return 'text-red-400';
    if (level === 'warn') return 'text-amber-400';
    return 'text-gray-400';
  };

  const categoryColor = (cat) => {
    const colors = {
      sensor: 'bg-green-500/20 text-green-300',
      scan: 'bg-blue-500/20 text-blue-300',
      device: 'bg-purple-500/20 text-purple-300',
      system: 'bg-gray-500/20 text-gray-300',
      ingest: 'bg-amber-500/20 text-amber-300',
    };
    return colors[cat] || 'bg-gray-700 text-gray-300';
  };

  const formatTime = (ts) => {
    if (!ts) return '';
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-semibold">Activity Log</h2>
          <p className="text-gray-400 text-sm mt-1">
            Real-time activity from Core, sensors, and scans
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-gray-400">
            <input
              type="checkbox" checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded border-gray-600"
            />
            Auto-refresh
          </label>
          <button onClick={fetchLogs} className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-1.5 rounded-lg text-sm transition-colors">
            Refresh
          </button>
        </div>
      </div>

      {categories.length > 2 && (
        <div className="flex gap-2 mb-4">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                filter === cat ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'
              }`}
            >
              {cat === 'all' ? 'All' : cat.charAt(0).toUpperCase() + cat.slice(1)}
            </button>
          ))}
        </div>
      )}

      {filtered.length > 0 ? (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="divide-y divide-gray-800/50">
            {filtered.map((entry, i) => (
              <div key={i} className="px-4 py-2.5 flex items-start gap-3 hover:bg-gray-800/30 transition-colors">
                <span className="font-mono text-xs text-gray-600 mt-0.5 shrink-0 w-16">{formatTime(entry.timestamp)}</span>
                <span className={`text-xs font-medium px-2 py-0.5 rounded shrink-0 ${categoryColor(entry.category)}`}>
                  {entry.category}
                </span>
                <span className={`text-sm ${levelColor(entry.level)}`}>{entry.message}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <p className="text-gray-500">No activity logged yet. Trigger a scan or connect a sensor to see events here.</p>
        </div>
      )}
    </>
  );
}

// --- Settings (placeholder) ---

function SettingsView() {
  return (
    <>
      <div className="mb-6">
        <h2 className="text-2xl font-semibold">Settings</h2>
        <p className="text-gray-400 text-sm mt-1">Configure Vedetta Core preferences</p>
      </div>

      <div className="space-y-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-medium mb-1">Data Retention</h3>
          <p className="text-xs text-gray-500 mb-3">How long to keep event and device history</p>
          <div className="flex items-center gap-3">
            <input type="number" defaultValue={90} className="w-20 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-center focus:outline-none focus:border-blue-500" />
            <span className="text-sm text-gray-400">days</span>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-medium mb-1">Scan Schedule</h3>
          <p className="text-xs text-gray-500 mb-3">Default interval for automatic sensor scans</p>
          <div className="flex items-center gap-3">
            <select defaultValue="5m" className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-blue-500">
              <option value="1m">Every 1 minute</option>
              <option value="5m">Every 5 minutes</option>
              <option value="15m">Every 15 minutes</option>
              <option value="30m">Every 30 minutes</option>
              <option value="1h">Every hour</option>
            </select>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-medium mb-1">Threat Intelligence</h3>
          <p className="text-xs text-gray-500 mb-3">Automatic feed updates from community threat lists</p>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-green-400 rounded-full" />
            <span className="text-sm text-gray-300">Active</span>
            <span className="text-xs text-gray-500 ml-2">Next update in ~23h</span>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-medium mb-1">Telemetry</h3>
          <p className="text-xs text-gray-500 mb-3">Opt-in anonymous telemetry to help improve Vedetta</p>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 bg-gray-500 rounded-full" />
            <span className="text-sm text-gray-400">Disabled</span>
          </div>
        </div>

        <p className="text-xs text-gray-600 text-center pt-2">
          Settings are read-only placeholders in v0.1.0-dev. Configuration changes coming soon.
        </p>
      </div>
    </>
  );
}

// --- Shared Components ---

function DeviceTable({ devices, compact = false }) {
  return (
    <table className="w-full">
      <thead>
        <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800">
          <th className="px-4 py-3">Status</th>
          <th className="px-4 py-3">IP Address</th>
          <th className="px-4 py-3">Hostname</th>
          <th className="px-4 py-3">Vendor</th>
          <th className="px-4 py-3">Segment</th>
          {!compact && <th className="px-4 py-3">MAC</th>}
          {!compact && <th className="px-4 py-3">Ports</th>}
          <th className="px-4 py-3">First Seen</th>
          <th className="px-4 py-3">Last Seen</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((device) => (
          <tr key={device.device_id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors">
            <td className="px-4 py-3">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-green-400 rounded-full" />
                {isNewDevice(device.first_seen) && (
                  <span className="bg-amber-500 text-black text-xs font-bold px-1.5 py-0.5 rounded">NEW</span>
                )}
              </div>
            </td>
            <td className="px-4 py-3 font-mono text-sm">{device.ip_address}</td>
            <td className="px-4 py-3 text-sm">{device.hostname || <span className="text-gray-600">—</span>}</td>
            <td className="px-4 py-3 text-sm text-gray-400">{device.vendor || '—'}</td>
            <td className="px-4 py-3"><SegmentBadge segment={device.segment} /></td>
            {!compact && <td className="px-4 py-3 font-mono text-xs text-gray-500">{device.mac_address}</td>}
            {!compact && (
              <td className="px-4 py-3 text-sm">
                {device.open_ports && device.open_ports.length > 0 ? (
                  <div className="flex gap-1 flex-wrap">
                    {device.open_ports.map((p) => (
                      <span key={p} className="bg-gray-800 text-gray-300 text-xs px-1.5 py-0.5 rounded">{p}</span>
                    ))}
                  </div>
                ) : <span className="text-gray-600">—</span>}
              </td>
            )}
            <td className="px-4 py-3 text-sm text-gray-400">{timeAgo(device.first_seen)}</td>
            <td className="px-4 py-3 text-sm text-gray-400">{timeAgo(device.last_seen)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SegmentBadge({ segment }) {
  const colors = SEGMENT_COLORS[segment] || 'bg-gray-700 text-gray-300';
  return (
    <span className={`text-xs font-medium px-2 py-0.5 rounded ${colors}`}>
      {segment}
    </span>
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
