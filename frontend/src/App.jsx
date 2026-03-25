import { useState, useEffect, useCallback } from 'react';

function timeAgo(dateStr) {
  if (!dateStr) return '—';
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
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
  const [scanStatus, setScanStatus] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('dashboard');
  const [scanning, setScanning] = useState(false);
  const [showSubnetDialog, setShowSubnetDialog] = useState(false);
  const [detectedSubnets, setDetectedSubnets] = useState([]);
  const [defaultCIDR, setDefaultCIDR] = useState('');
  const [cidrConfirmed, setCidrConfirmed] = useState(false);

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

  useEffect(() => {
    fetchStatus();
    fetchDevices();
    fetchTargets();

    // Show subnet confirmation on first visit if no devices yet
    fetch('/api/v1/scan/subnets')
      .then((r) => r.json())
      .then((data) => {
        setDetectedSubnets(data.subnets || []);
        // Auto-show dialog if this looks like first run
        fetch('/api/v1/devices')
          .then((r) => r.json())
          .then((d) => {
            if (!d.devices || d.devices.length === 0) {
              setShowSubnetDialog(true);
            } else {
              setCidrConfirmed(true);
            }
          });
      });

    const interval = setInterval(() => {
      fetchStatus();
      fetchDevices();
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchDevices, fetchTargets]);

  const confirmCIDR = (cidr) => {
    fetch('/api/v1/scan/cidr', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cidr }),
    }).then(() => {
      setDefaultCIDR(cidr);
      setCidrConfirmed(true);
      setShowSubnetDialog(false);
      triggerScan();
    });
  };

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
      {/* Subnet confirmation dialog */}
      {showSubnetDialog && (
        <SubnetDialog
          subnets={detectedSubnets}
          defaultCIDR={defaultCIDR}
          onConfirm={confirmCIDR}
          onDismiss={() => { setShowSubnetDialog(false); setCidrConfirmed(true); }}
        />
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
              {['dashboard', 'devices', 'scan targets'].map((v) => (
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
            devices={devices} scanStatus={scanStatus} newDeviceCount={newDeviceCount}
            scanning={scanning} onScan={triggerScan} onViewDevices={() => setView('devices')}
            defaultCIDR={defaultCIDR} targets={targets}
          />
        ) : view === 'devices' ? (
          <DevicesView devices={devices} scanning={scanning} onScan={triggerScan} scanStatus={scanStatus} />
        ) : (
          <ScanTargetsView
            targets={targets} defaultCIDR={defaultCIDR} scanning={scanning}
            onRefresh={fetchTargets} onScanTarget={triggerTargetScan}
            onChangeSubnet={() => setShowSubnetDialog(true)}
          />
        )}
      </main>
    </div>
  );
}

// --- Subnet Confirmation Dialog ---

function SubnetDialog({ subnets, defaultCIDR, onConfirm, onDismiss }) {
  const [customCIDR, setCustomCIDR] = useState('');

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-lg w-full p-6">
        <h2 className="text-lg font-semibold mb-2">Confirm Your Network</h2>
        <p className="text-gray-400 text-sm mb-4">
          Vedetta detected the following subnets. Select which one is your primary LAN so we can scan the right network.
        </p>

        <div className="space-y-2 mb-4">
          {subnets.map((s) => (
            <button
              key={s.cidr}
              onClick={() => onConfirm(s.cidr)}
              className={`w-full text-left px-4 py-3 rounded-lg border transition-colors ${
                s.is_default
                  ? 'border-blue-500 bg-blue-500/10 hover:bg-blue-500/20'
                  : 'border-gray-700 hover:bg-gray-800'
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-mono text-sm">{s.cidr}</span>
                  <span className="text-gray-500 text-xs ml-2">({s.interface})</span>
                </div>
                {s.is_default && (
                  <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded">recommended</span>
                )}
              </div>
              <p className="text-gray-500 text-xs mt-1">IP: {s.ip_address}</p>
            </button>
          ))}
        </div>

        <div className="border-t border-gray-800 pt-4">
          <p className="text-gray-500 text-xs mb-2">Or enter a custom CIDR:</p>
          <div className="flex gap-2">
            <input
              type="text"
              value={customCIDR}
              onChange={(e) => setCustomCIDR(e.target.value)}
              placeholder="e.g. 10.0.0.0/24"
              className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={() => customCIDR && onConfirm(customCIDR)}
              disabled={!customCIDR}
              className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              Use
            </button>
          </div>
        </div>

        <button
          onClick={onDismiss}
          className="mt-4 w-full text-center text-gray-500 hover:text-gray-300 text-sm"
        >
          Skip for now
        </button>
      </div>
    </div>
  );
}

// --- Dashboard ---

function DashboardView({ devices, scanStatus, newDeviceCount, scanning, onScan, onViewDevices, defaultCIDR, targets }) {
  const segmentCounts = {};
  devices.forEach((d) => {
    segmentCounts[d.segment] = (segmentCounts[d.segment] || 0) + 1;
  });

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Devices" value={devices.length || '—'} sub={devices.length > 0 ? `${newDeviceCount} new (24h)` : 'Awaiting scan'} highlight={newDeviceCount > 0} />
        <StatCard label="Networks" value={(targets.length + 1) || '1'} sub={defaultCIDR ? `Primary: ${defaultCIDR}` : 'Not configured'} />
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
        <button onClick={onScan} disabled={scanning} className="bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:text-blue-400 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
          {scanning && <Spinner />}
          {scanning ? 'Scanning...' : 'Scan All Networks'}
        </button>
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

function ScanTargetsView({ targets, defaultCIDR, scanning, onRefresh, onScanTarget, onChangeSubnet }) {
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
          <button onClick={onChangeSubnet} className="text-sm text-blue-400 hover:text-blue-300">Change</button>
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

            <div className="flex gap-2 mt-6">
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
