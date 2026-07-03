import React, { useState, useEffect, useCallback } from 'react';
import { authFetch, authFetchJSON, getAdminToken, setAdminToken, clearAdminToken, hasAdminToken } from './lib/api';

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
  default: 'bg-teal-500/20 text-teal-300',
  iot: 'bg-amber-500/20 text-amber-300',
  guest: 'bg-green-400/20 text-green-400',
};

// Brand: Geometric Rook mark (amber on dark)
function RookMark({ size = 32 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 200 260" xmlns="http://www.w3.org/2000/svg">
      <rect x="40" y="220" width="120" height="16" rx="4" fill="#E8A020"/>
      <rect x="50" y="210" width="100" height="14" rx="3" fill="#E8A020"/>
      <path d="M58 210 L62 120 L56 110 L56 100 L144 100 L144 110 L138 120 L142 210 Z" fill="#E8A020"/>
      <rect x="62" y="108" width="76" height="14" fill="#0B1426" opacity="0.2"/>
      <rect x="56" y="60" width="28" height="42" rx="3" fill="#E8A020"/>
      <rect x="86" y="60" width="28" height="42" rx="3" fill="#E8A020"/>
      <rect x="116" y="60" width="28" height="42" rx="3" fill="#E8A020"/>
      <rect x="56" y="90" width="88" height="12" fill="#E8A020"/>
      <rect x="84" y="60" width="2" height="30" fill="#0B1426" opacity="0.12"/>
      <rect x="114" y="60" width="2" height="30" fill="#0B1426" opacity="0.12"/>
    </svg>
  );
}

export default function App() {
  const [status, setStatus] = useState(null);
  const [devices, setDevices] = useState([]);
  const [targets, setTargets] = useState([]);
  const [sensors, setSensors] = useState([]);
  const [sensorInterfaces, setSensorInterfaces] = useState([]);
  const [scanStatus, setScanStatus] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('dashboard');
  const [scanning, setScanning] = useState(false);
  const [showSetup, setShowSetup] = useState(false);
  const [showMenu, setShowMenu] = useState(false);
  const [defaultCIDR, setDefaultCIDR] = useState('');
  const [threatEvents, setThreatEvents] = useState([]);
  const [threatStats, setThreatStats] = useState(null);
  const [threatTimeline, setThreatTimeline] = useState([]);
  const [suppressionRules, setSuppressionRules] = useState([]);
  const [whitelistRules, setWhitelistRules] = useState([]);

  // Admin auth state (localStorage-backed via lib/api)
  const [adminToken, setAdminTokenState] = useState(() => getAdminToken());
  const [showTokenPrompt, setShowTokenPrompt] = useState(false);
  const [tokenInput, setTokenInput] = useState('');
  const [authError, setAuthError] = useState('');

  // Keep local state in sync with the lib (in case of external clear)
  const updateAdminToken = useCallback((token) => {
    setAdminToken(token);
    setAdminTokenState(token || '');
    setAuthError('');
  }, []);

  // Create the very first admin token (only works in bootstrap mode)
  const createInitialAdminToken = async () => {
    setAuthError('');
    try {
      const res = await fetch('/api/v1/auth/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scope: 'admin', label: 'Initial Admin (created from UI)' }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to create admin token');
      }
      if (data.token) {
        updateAdminToken(data.token);
        // Show the token one last time in an alert-style modal (user must copy it now)
        alert(
          'ADMIN TOKEN CREATED (shown only once):\n\n' +
          data.token + '\n\n' +
          'Copy this token and store it safely. It will not be shown again.\n' +
          'You can always create additional admin tokens from the Settings page if you have an active session.'
        );
        // Refresh data now that we are authenticated
        fetchStatus();
        fetchSensors();
      }
    } catch (e) {
      setAuthError(e.message || 'Failed to create admin token');
    }
  };

  // Allow user to paste an existing admin token (recovery / multi-device)
  const submitPastedToken = () => {
    const t = tokenInput.trim();
    if (!t) {
      setAuthError('Please paste a valid admin token');
      return;
    }
    updateAdminToken(t);
    setTokenInput('');
    setShowTokenPrompt(false);
    setAuthError('');
    // Re-fetch everything with the new token
    setTimeout(() => {
      fetchStatus();
      fetchSensors();
      fetchDevices();
      fetchTargets();
      fetchThreatData();
    }, 50);
  };

  const fetchStatus = useCallback(() => {
    authFetch('/api/v1/status')
      .then((r) => r.json())
      .then((data) => {
        setStatus(data);
        setScanStatus(data.scan);
        if (data.default_cidr) setDefaultCIDR(data.default_cidr);
      })
      .catch((e) => setError(e.message));
  }, []);

  const fetchDevices = useCallback(() => {
    authFetch('/api/v1/devices')
      .then((r) => r.json())
      .then((data) => setDevices(data.devices || []))
      .catch(() => {});
  }, []);

  const fetchTargets = useCallback(() => {
    authFetch('/api/v1/scan/targets')
      .then((r) => r.json())
      .then((data) => setTargets(data.targets || []))
      .catch(() => {});
  }, []);

  const fetchSensors = useCallback(() => {
    authFetch('/api/v1/sensor/list')
      .then((r) => r.json())
      .then((data) => setSensors(data.sensors || []))
      .catch(() => {});
  }, []);

  const fetchThreatData = useCallback(() => {
    Promise.all([
      fetch('/api/v1/events?min_score=0.3&limit=100&order=desc').then((r) => r.json()).catch(() => ({ events: [] })),
      fetch('/api/v1/events/stats').then((r) => r.json()).catch(() => ({})),
      fetch('/api/v1/events/timeline').then((r) => r.json()).catch(() => ({ timeline: [] })),
      fetch('/api/v1/suppression').then((r) => r.json()).catch(() => ({ rules: [] })),
      fetch('/api/v1/whitelist').then((r) => r.json()).catch(() => ({ rules: [] })),
    ]).then(([eventsData, statsData, timelineData, suppressionData, whitelistData]) => {
      setThreatEvents(eventsData.events || []);
      setThreatStats(statsData);
      setThreatTimeline(timelineData.timeline || []);
      setSuppressionRules(suppressionData.rules || []);
      setWhitelistRules(whitelistData.rules || []);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    const ifaces = [];
    sensors.forEach(s => {
      try {
        const parsed = JSON.parse(s.interfaces || '[]');
        parsed.forEach(iface => {
          if (!ifaces.find(i => i.name === iface.name)) {
            ifaces.push(iface);
          }
        });
      } catch {}
    });
    setSensorInterfaces(ifaces);
  }, [sensors]);

  // Global 401 handler — show token recovery prompt when backend rejects our admin token
  useEffect(() => {
    const onUnauthorized = () => {
      if (hasAdminToken()) {
        setAuthError('Your admin token is no longer valid. Please re-enter it.');
        setShowTokenPrompt(true);
      }
    };
    window.addEventListener('vedetta:auth:unauthorized', onUnauthorized);
    return () => window.removeEventListener('vedetta:auth:unauthorized', onUnauthorized);
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchDevices();
    fetchTargets();
    fetchSensors();
    fetchThreatData();

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
      fetchThreatData();
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchDevices, fetchTargets, fetchSensors, fetchThreatData]);

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

      {/* Admin Token Prompt / Recovery Modal */}
      {showTokenPrompt && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Admin Access</h3>
              <button onClick={() => { setShowTokenPrompt(false); setAuthError(''); }} className="text-gray-400 hover:text-white">✕</button>
            </div>

            {!adminToken && (
              <div className="space-y-3">
                <p className="text-sm text-gray-400">
                  No admin token found in this browser. Create one (first time only) or paste an existing one.
                </p>
                <button
                  onClick={createInitialAdminToken}
                  className="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2.5 rounded-lg font-medium transition-colors"
                >
                  Create Initial Admin Token
                </button>
                <div className="text-center text-xs text-gray-500">— or —</div>
              </div>
            )}

            <div className="space-y-2">
              <label className="text-xs text-gray-400 block">Paste admin token (recovery / other device)</label>
              <input
                type="text"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') submitPastedToken(); }}
                placeholder="64-character hex token..."
                className="w-full bg-gray-950 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-amber-500"
              />
              <button
                onClick={submitPastedToken}
                className="w-full bg-gray-800 hover:bg-gray-700 text-white py-2 rounded-lg text-sm transition-colors"
              >
                Use This Token
              </button>
            </div>

            {authError && (
              <div className="text-sm text-red-400 bg-red-950/50 border border-red-900 rounded p-2">{authError}</div>
            )}

            <p className="text-[10px] text-gray-500">
              Tokens are stored only in your browser (localStorage). Create additional admin tokens from the Settings view after logging in.
            </p>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-gray-800 px-6 py-4">
        <div className="flex items-center justify-between max-w-7xl mx-auto">
          <div className="flex items-center gap-3">
            <RookMark size={28} />
            <h1 className="text-xl font-display tracking-wide">Vedetta</h1>
            <span className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded font-mono">v0.1.0-dev</span>
          </div>
          <div className="flex items-center gap-4">
            {/* Admin auth status badge */}
            <div className="flex items-center gap-2 text-xs">
              {adminToken ? (
                <span
                  onClick={() => setShowTokenPrompt(true)}
                  className="px-2 py-0.5 bg-emerald-900/50 text-emerald-400 rounded cursor-pointer hover:bg-emerald-900"
                  title="Click to manage or recover admin token"
                >
                  Admin ✓
                </span>
              ) : (
                <button
                  onClick={() => setShowTokenPrompt(true)}
                  className="px-2 py-0.5 bg-amber-900/50 text-amber-400 rounded hover:bg-amber-900"
                >
                  No admin token
                </button>
              )}
            </div>

            <nav className="flex gap-1">
              {['dashboard', 'devices', 'threats', 'sensors', 'scan targets'].map((v) => (
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
                    <span className="ml-1.5 bg-teal-500/20 text-teal-300 text-xs font-bold px-1.5 py-0.5 rounded-full">
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
                      onClick={() => { setView('whitelist'); setShowMenu(false); }}
                      className={`w-full text-left px-4 py-2.5 text-sm flex items-center gap-3 transition-colors ${view === 'whitelist' ? 'bg-gray-800 text-white' : 'text-gray-300 hover:bg-gray-800 hover:text-white'}`}
                    >
                      <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      Whitelist Rules
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
            threatStats={threatStats} onNavigate={setView}
          />
        ) : view === 'devices' ? (
          <DevicesView devices={devices} scanning={scanning} onScan={triggerScan} scanStatus={scanStatus} threatEvents={threatEvents} onRefreshThreats={fetchThreatData} />
        ) : view === 'threats' ? (
          <ThreatsView events={threatEvents} stats={threatStats} timeline={threatTimeline} onRefresh={fetchThreatData}
            devices={devices} suppressionRules={suppressionRules} whitelistRules={whitelistRules} onNavigate={setView} />
        ) : view === 'sensors' ? (
          <SensorsView sensors={sensors} onSetup={() => setShowSetup(true)} onRefreshSensors={fetchSensors} />
        ) : view === 'logs' ? (
          <LogsView />
        ) : view === 'whitelist' ? (
          <WhitelistManagementView whitelistRules={whitelistRules} onRefresh={fetchThreatData} />
        ) : view === 'settings' ? (
          <SettingsView />
        ) : (
          <ScanTargetsView
            targets={targets} defaultCIDR={defaultCIDR} scanning={scanning}
            onRefresh={fetchTargets} onScanTarget={triggerTargetScan} sensorInterfaces={sensorInterfaces}
          />
        )}
      </main>
    </div>
  );
}

// --- Threat Intelligence Status Card ---

function ThreatIntelStatusCard({ stats, onClick }) {
  const threatCount = stats?.threat_count || 0;
  const isActive = threatCount > 0;

  return (
    <div
      className={`bg-gray-900 border rounded-lg p-4 ${isActive ? 'border-red-500/40' : 'border-gray-800'} ${onClick ? 'cursor-pointer hover:bg-gray-800/50 transition-colors' : ''}`}
      onClick={onClick}
    >
      <p className="text-sm text-gray-400">Threat Intel</p>
      <div className="flex items-center gap-2 mt-1">
        <span className={`w-2 h-2 rounded-full ${isActive ? 'bg-red-500' : 'bg-green-400'}`} />
        <p className="text-2xl font-semibold">{threatCount}</p>
      </div>
      <p className={`text-xs mt-1 ${isActive ? 'text-red-400' : 'text-gray-500'}`}>
        {isActive ? `${threatCount} threats detected` : 'No threats'}
      </p>
    </div>
  );
}

// --- Add Whitelist Rule (inline form) ---

function AddWhitelistRule({ onAdd, onError }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [domainPattern, setDomainPattern] = useState('');
  const [sourceIpPattern, setSourceIpPattern] = useState('');
  const [tagMatch, setTagMatch] = useState('');
  const [category, setCategory] = useState('custom');
  const [saving, setSaving] = useState(false);

  const doCreate = () => {
    if (!name.trim()) return onError('Rule name is required');
    if (!domainPattern.trim() && !sourceIpPattern.trim()) return onError('At least a domain or IP pattern is required');
    setSaving(true);
    fetch('/api/v1/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name.trim(), domain_pattern: domainPattern.trim(), source_ip_pattern: sourceIpPattern.trim(),
        tag_match: tagMatch.trim(), category, enabled: true,
      }),
    }).then(r => {
      if (!r.ok) throw new Error(`Server returned ${r.status}`);
      setOpen(false); setName(''); setDomainPattern(''); setSourceIpPattern(''); setTagMatch(''); setCategory('custom');
      onAdd();
    }).catch(err => onError(`Failed to create rule: ${err.message}`))
      .finally(() => setSaving(false));
  };

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="text-sm text-teal-400 hover:text-teal-300 transition-colors flex items-center gap-1">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" /></svg>
        Add Custom Rule
      </button>
    );
  }

  return (
    <div className="bg-gray-800/40 rounded-lg p-3 space-y-2">
      <div className="grid grid-cols-2 gap-2">
        <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Rule name"
          className="bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:border-teal-500" />
        <select value={category} onChange={(e) => setCategory(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-sm focus:outline-none focus:border-teal-500">
          <option value="custom">Custom</option>
          <option value="mdns">mDNS</option>
          <option value="apple">Apple</option>
          <option value="cloud">Cloud</option>
          <option value="os_updates">OS Updates</option>
          <option value="iot">IoT</option>
        </select>
      </div>
      <div className="grid grid-cols-3 gap-2">
        <input type="text" value={domainPattern} onChange={(e) => setDomainPattern(e.target.value)} placeholder="Domain (*.example.com)"
          className="bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-sm font-mono focus:outline-none focus:border-teal-500" />
        <input type="text" value={sourceIpPattern} onChange={(e) => setSourceIpPattern(e.target.value)} placeholder="Source IP (10.0.0.*)"
          className="bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-sm font-mono focus:outline-none focus:border-teal-500" />
        <input type="text" value={tagMatch} onChange={(e) => setTagMatch(e.target.value)} placeholder="Tag (beaconing)"
          className="bg-gray-800 border border-gray-700 rounded px-2.5 py-1.5 text-sm font-mono focus:outline-none focus:border-teal-500" />
      </div>
      <div className="flex items-center justify-end gap-2">
        <button onClick={() => setOpen(false)} className="text-xs text-gray-500 hover:text-gray-300 px-3 py-1">Cancel</button>
        <button onClick={doCreate} disabled={saving}
          className="text-xs bg-teal-500/20 text-teal-300 border border-teal-500/30 px-3 py-1.5 rounded hover:bg-teal-500/30 disabled:opacity-50 transition-colors">
          {saving ? 'Creating...' : 'Create Rule'}
        </button>
      </div>
    </div>
  );
}

// --- Threats View ---

function ThreatsView({ events, stats, timeline, onRefresh, devices, suppressionRules, whitelistRules, onNavigate }) {
  const [severityFilter, setSeverityFilter] = useState('all');
  const [contextFilter, setContextFilter] = useState('all'); // 'all' | 'new_device' | 'iot'
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [hideWhitelisted, setHideWhitelisted] = useState(true);
  const [showWhitelistPanel, setShowWhitelistPanel] = useState(false);
  const [actionMode, setActionMode] = useState(null); // { eventId, mode: 'ack'|'suppress', reason: '' }
  const [refreshing, setRefreshing] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [groupModal, setGroupModal] = useState(null); // { events: [], domain: '' }
  const [visibleCount, setVisibleCount] = useState(30);
  const [showAckAllModal, setShowAckAllModal] = useState(false);
  const [ackAllReason, setAckAllReason] = useState('');
  const [ackAllProcessing, setAckAllProcessing] = useState(false);

  // Build device lookup by IP
  const deviceByIP = {};
  (devices || []).forEach(d => { if (d.ip_address) deviceByIP[d.ip_address] = d; });

  // Find which suppression rule matches an event (returns rule or null)
  const findMatchingRule = (event) => {
    if (!suppressionRules || suppressionRules.length === 0) return null;
    return suppressionRules.find(rule => {
      if (!rule.active) return false;
      if (rule.domain && rule.domain !== event.domain) return false;
      if (rule.source_ip && rule.source_ip !== event.source_ip) return false;

      if (rule.tags && rule.tags.length > 0) {
        const eventTags = event.tags || [];
        const deviceVendor = (event.device_vendor || '').toLowerCase();
        const networkSegment = (event.network_segment || '').toLowerCase();

        for (const tag of rule.tags) {
          if (tag.startsWith('vendor:')) {
            const requiredVendor = tag.substring(7);
            if (deviceVendor !== requiredVendor) return false;
          } else if (tag.startsWith('segment:')) {
            const requiredSegment = tag.substring(8);
            if (networkSegment !== requiredSegment) return false;
          } else {
            // Normal tag
            if (!eventTags.includes(tag)) return false;
          }
        }
      }
      return true;
    }) || null;
  };

  const isSuppressed = (event) => findMatchingRule(event) !== null;

  // Check if an event matches any enabled whitelist rule (glob matching)
  const globMatch = (pattern, value) => {
    if (!pattern || !value) return false;
    // Convert glob to regex: * -> .*, escape other special chars
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    try { return new RegExp(`^${escaped}$`, 'i').test(value); } catch { return false; }
  };

  const isWhitelisted = (event) => {
    if (!whitelistRules || whitelistRules.length === 0) return false;
    return whitelistRules.some(rule => {
      if (!rule.enabled) return false;
      let domainMatch = !rule.domain_pattern;
      let ipMatch = !rule.source_ip_pattern;
      let tagMatch = !rule.tag_match;
      if (rule.domain_pattern && event.domain) domainMatch = globMatch(rule.domain_pattern, event.domain);
      if (rule.source_ip_pattern && event.source_ip) ipMatch = globMatch(rule.source_ip_pattern, event.source_ip);
      if (rule.tag_match && event.tags) tagMatch = event.tags.includes(rule.tag_match);
      else if (rule.tag_match) tagMatch = false;
      // All specified criteria must match
      return domainMatch && ipMatch && tagMatch;
    });
  };

  const whitelistedCount = events.filter(e => isWhitelisted(e)).length;

  // Group duplicate events — improved for SNR (behavioral clustering)
  // Now groups more aggressively by device + detection type over a longer window.
  // This dramatically reduces visual noise ("same device doing DGA-like queries" appears as one item).
  const groupEvents = (eventList) => {
    const groups = [];
    const used = new Set();
    const GROUP_WINDOW_MS = 30 * 60 * 1000; // Increased from 5 min to 30 min for better noise reduction

    for (let i = 0; i < eventList.length; i++) {
      if (used.has(i)) continue;
      const e = eventList[i];
      const group = { lead: e, count: 1, members: [e] };
      const eTime = new Date(e.timestamp).getTime();
      const ePrimaryTag = (e.tags && e.tags[0]) || '';
      const eSourceKey = e.source_ip + '|' + (e.network_segment || 'default');

      for (let j = i + 1; j < eventList.length; j++) {
        if (used.has(j)) continue;
        const o = eventList[j];
        const oTime = new Date(o.timestamp).getTime();
        const oPrimaryTag = (o.tags && o.tags[0]) || '';
        const oSourceKey = o.source_ip + '|' + (o.network_segment || 'default');

        // Group if same device/segment + same primary detection tag + within time window
        // This creates behavioral clusters ("this device is showing repeated DGA behavior")
        const sameBehavioralSource = eSourceKey === oSourceKey;
        const samePrimaryBehavior = ePrimaryTag !== '' && ePrimaryTag === oPrimaryTag;

        if (sameBehavioralSource && samePrimaryBehavior && Math.abs(eTime - oTime) < GROUP_WINDOW_MS) {
          group.count++;
          group.members.push(o);
          used.add(j);
        }
      }
      groups.push(group);
      used.add(i);
    }
    return groups;
  };

  // Filter: severity + context (new_device / iot)
  const baseFiltered = events.filter(e => {
    const score = e.anomaly_score || 0;
    if (severityFilter === 'critical' && score <= 0.7) return false;
    if (severityFilter === 'warning' && (score < 0.3 || score > 0.7)) return false;

    if (contextFilter === 'new_device' && !e.tags?.includes('new_device_context')) return false;
    if (contextFilter === 'iot' && !e.tags?.includes('iot_context')) return false;
    if (contextFilter === 'eol' && !e.tags?.includes('eol_router') && !e.tags?.includes('eol_device_context') && !e.tags?.includes('high_risk_iot') && !e.tags?.includes('known_exploited')) return false;

    return true;
  });

  const afterWhitelist = hideWhitelisted ? baseFiltered.filter(e => !isWhitelisted(e)) : baseFiltered;
  const visibleEvents = afterWhitelist.filter(e => !e.acknowledged && !isSuppressed(e));
  const suppressedEvents = afterWhitelist.filter(e => e.acknowledged || isSuppressed(e));
  const displayEvents = showSuppressed ? suppressedEvents : visibleEvents;
  const grouped = groupEvents(displayEvents);
  const paginatedGroups = grouped.slice(0, visibleCount);

  // Only show the Proc column when at least one visible event carries a process hint
  // (process attribution is future host-local work; hide the dead column until then)
  const hasProcColumn = paginatedGroups.some((g) => {
    try {
      const m = JSON.parse(g.lead.metadata || '{}');
      return !!(m && m.process);
    } catch {
      return false;
    }
  });

  // Pre-severity set (context + whitelist + suppressed, but no severity filter)
  // Used for correct severity button counts
  const contextOnly = events.filter(e => {
    if (contextFilter === 'new_device' && !e.tags?.includes('new_device_context')) return false;
    if (contextFilter === 'iot' && !e.tags?.includes('iot_context')) return false;
    if (contextFilter === 'eol' && !e.tags?.includes('eol_router') && !e.tags?.includes('eol_device_context') && !e.tags?.includes('high_risk_iot') && !e.tags?.includes('known_exploited')) return false;
    return true;
  });
  const afterWhitelistContextOnly = hideWhitelisted ? contextOnly.filter(e => !isWhitelisted(e)) : contextOnly;
  const visibleContextOnly = afterWhitelistContextOnly.filter(e => !e.acknowledged && !isSuppressed(e));
  const suppressedContextOnly = afterWhitelistContextOnly.filter(e => e.acknowledged || isSuppressed(e));
  const displayContextOnly = showSuppressed ? suppressedContextOnly : visibleContextOnly;

  // Pre-context set (severity + whitelist + suppressed, but no context filter)
  // Used for correct context button counts
  const severityOnly = events.filter(e => {
    const score = e.anomaly_score || 0;
    if (severityFilter === 'critical' && score <= 0.7) return false;
    if (severityFilter === 'warning' && (score < 0.3 || score > 0.7)) return false;
    return true;
  });
  const afterWhitelistSeverityOnly = hideWhitelisted ? severityOnly.filter(e => !isWhitelisted(e)) : severityOnly;
  const visibleSeverityOnly = afterWhitelistSeverityOnly.filter(e => !e.acknowledged && !isSuppressed(e));
  const suppressedSeverityOnly = afterWhitelistSeverityOnly.filter(e => e.acknowledged || isSuppressed(e));
  const displaySeverityOnly = showSuppressed ? suppressedSeverityOnly : visibleSeverityOnly;

  // Counts for contextual quick suppression buttons (SNR-23)
  // Computed from pre-context set so they reflect current severity selection
  const allContextCount = displaySeverityOnly.length;
  const iotContextCount = displaySeverityOnly.filter(e => e.tags?.includes('iot_context')).length;
  const newDeviceContextCount = displaySeverityOnly.filter(e => e.tags?.includes('new_device_context')).length;
  const eolContextCount = displaySeverityOnly.filter(e => e.tags?.includes('eol_router') || e.tags?.includes('eol_device_context') || e.tags?.includes('high_risk_iot') || e.tags?.includes('known_exploited')).length;

  // Severity counts for filter buttons
  // Computed from pre-severity set (after context + whitelist + suppressed)
  // so "All" always shows the grand total of the current context, and Critical/Warning show the breakdown
  const criticalCount = displayContextOnly.filter(e => (e.anomaly_score || 0) > 0.7).length;
  const warningCount = displayContextOnly.filter(e => {
    const s = e.anomaly_score || 0;
    return s >= 0.3 && s <= 0.7;
  }).length;
  const allCount = displayContextOnly.length;

  // Per-rule match counts for the Active Suppression Rules Summary (SNR-28)
  const activeRules = (suppressionRules || []).filter(r => r.active);
  const ruleMatchCounts = {};
  activeRules.forEach(rule => {
    ruleMatchCounts[rule.rule_id] = displayEvents.filter(e => {
      // Simplified check: use the existing findMatchingRule logic but for a single rule
      if (!rule.active) return false;
      if (rule.domain && rule.domain !== e.domain) return false;
      if (rule.source_ip && rule.source_ip !== e.source_ip) return false;
      if (rule.tags && rule.tags.length > 0) {
        const eventTags = e.tags || [];
        const deviceVendor = (e.device_vendor || '').toLowerCase();
        const networkSegment = (e.network_segment || '').toLowerCase();
        for (const tag of rule.tags) {
          if (tag.startsWith('vendor:')) {
            if (deviceVendor !== tag.substring(7)) return false;
          } else if (tag.startsWith('segment:')) {
            if (networkSegment !== tag.substring(8)) return false;
          } else {
            if (!eventTags.includes(tag)) return false;
          }
        }
      }
      return true;
    }).length;
  });

  const toggleRowExpanded = (eventId) => {
    const newSet = new Set(expandedRows);
    if (newSet.has(eventId)) newSet.delete(eventId);
    else newSet.add(eventId);
    setExpandedRows(newSet);
  };

  const getScoreColor = (score) => {
    if (score < 0.3) return 'bg-green-500';
    if (score < 0.7) return 'bg-amber-500';
    return 'bg-red-500';
  };

  const getScoreBarWidth = (score) => Math.max(Math.min(score * 100, 100), 10);

  const tagColors = {
    dga_candidate: 'bg-red-500/20 text-red-300',
    dns_tunnel: 'bg-purple-500/20 text-purple-300',
    beaconing: 'bg-orange-500/20 text-orange-300',
    dns_rebinding: 'bg-pink-500/20 text-pink-300',
    known_bad: 'bg-red-600/20 text-red-200',
    dns_bypass: 'bg-yellow-500/20 text-yellow-300',
    // Contextual tags (device/environment) - distinct styling
    iot_context: 'bg-teal-500/20 text-teal-300',
    new_device_context: 'bg-cyan-500/20 text-cyan-300',
    very_new_device: 'bg-red-600/30 text-red-400 font-bold', // Strong visual for <1h devices
    eol_router: 'bg-red-500/20 text-red-300 border border-red-500/40',
    eol_device_context: 'bg-red-500/20 text-red-300 border border-red-500/40 font-semibold',
    // New generalized risk categories
    high_risk_iot: 'bg-orange-500/20 text-orange-300 border border-orange-500/40',
    known_exploited: 'bg-red-600/20 text-red-300 border border-red-600/40 font-semibold',
  };

  const tagLabel = (tag) => {
    const labels = {
      dga_candidate: 'DGA',
      dns_tunnel: 'Tunnel',
      beaconing: 'Beacon',
      dns_rebinding: 'Rebinding',
      known_bad: 'Threat Intel',
      dns_bypass: 'DNS Bypass',
      // Contextual labels
      iot_context: 'IoT Segment',
      new_device_context: 'New Device',
      very_new_device: 'Very New (<1h)',
      eol_router: 'EOL Router',
      eol_device_context: 'EOL Device (High Risk)',
      // New generalized risk categories
      high_risk_iot: 'High Risk IoT',
      known_exploited: 'Known Exploited',
    };
    return labels[tag] || tag;
  };

  const dnsSourceLabel = (src) => {
    const labels = {
      passive_capture: 'Passive Capture',
      pihole: 'Pi-hole',
      adguard: 'AdGuard Home',
      embedded_resolver: 'Embedded DNS',
      iptables_intercept: 'iptables',
    };
    return labels[src] || src || '—';
  };

  const parseMetadata = (metaStr) => {
    if (!metaStr || metaStr === '{}') return null;
    try { return JSON.parse(metaStr); } catch { return null; }
  };

  const formatTimestamp = (ts) => {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
      + ' ' + d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  const doRefresh = () => {
    setRefreshing(true);
    setActionError(null);
    onRefresh();
    // onRefresh is async but doesn't return a promise, so we just reset after a delay
    setTimeout(() => setRefreshing(false), 1500);
  };

  const handleAck = (eventId, reason) => {
    setActionError(null);
    fetch(`/api/v1/events/${eventId}/ack`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    }).then(r => {
      if (!r.ok) throw new Error(`Server returned ${r.status}`);
      setActionMode(null);
      onRefresh();
    }).catch(err => setActionError(`Acknowledge failed: ${err.message}`));
  };

  const handleUnack = (eventId) => {
    setActionError(null);
    fetch(`/api/v1/events/${eventId}/ack`, { method: 'DELETE' })
      .then(r => {
        if (!r.ok) throw new Error(`Server returned ${r.status}`);
        onRefresh();
      }).catch(err => setActionError(`Unacknowledge failed: ${err.message}`));
  };

  const handleCreateSuppression = (event, reason) => {
    setActionError(null);
    fetch('/api/v1/suppression', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: event.domain, source_ip: event.source_ip, tags: [], reason: reason || '' }),
    }).then(r => {
      if (!r.ok) throw new Error(`Server returned ${r.status}`);
      setActionMode(null);
      onRefresh();
    }).catch(err => setActionError(`Suppress failed: ${err.message}. Try: docker compose up -d --build`));
  };

  const handleDeleteSuppression = (ruleId) => {
    setActionError(null);
    fetch(`/api/v1/suppression/${ruleId}`, { method: 'DELETE' })
      .then(r => {
        if (!r.ok) throw new Error(`Server returned ${r.status}`);
        onRefresh();
      }).catch(err => setActionError(`Unsuppress failed: ${err.message}`));
  };

  // Determine event's current disposition
  const getEventState = (event) => {
    const rule = findMatchingRule(event);
    if (event.acknowledged) return { type: 'acked', reason: event.ack_reason || '', rule: null };
    if (rule) return { type: 'suppressed', reason: rule.reason || '', rule };
    return { type: 'active', reason: '', rule: null };
  };

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-display">Threat Events</h2>
          <p className="text-gray-400 text-sm mt-1">
            {visibleEvents.length} active{suppressedEvents.length > 0 ? `, ${suppressedEvents.length} suppressed` : ''}
            {hideWhitelisted && whitelistedCount > 0 ? ` · ${whitelistedCount} hidden by whitelist` : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowWhitelistPanel(!showWhitelistPanel)}
            className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              showWhitelistPanel ? 'bg-teal-500/20 text-teal-300 border border-teal-500/30' : 'bg-gray-700 hover:bg-gray-600 text-gray-200'
            }`}
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            Whitelist{whitelistRules.filter(r => r.enabled).length > 0 ? ` (${whitelistRules.filter(r => r.enabled).length})` : ''}
          </button>
          {visibleEvents.length > 0 && (
            <button
              onClick={() => setShowAckAllModal(true)}
              className="bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              Acknowledge All
            </button>
          )}
          {visibleEvents.length > 0 && (
            <button
              onClick={() => {
                const params = new URLSearchParams();
                params.set('format', 'csv');
                params.set('limit', '10000');
                if (severityFilter !== 'all') params.set('min_score', '0.3');
                window.open('/api/v1/events?' + params.toString(), '_blank');
              }}
              className="px-3 py-2 border border-amber-500/30 text-amber-400 rounded-lg text-sm hover:bg-amber-500/10 transition-colors"
            >
              Export CSV
            </button>
          )}
          <button
            onClick={doRefresh}
            disabled={refreshing}
            className="bg-amber-500 hover:bg-amber-400 disabled:bg-amber-800 disabled:text-amber-600 text-gray-950 px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            {refreshing && <Spinner />}
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Acknowledge All Modal */}
      {showAckAllModal && (
        <>
          <div className="fixed inset-0 bg-black/60 z-40" onClick={() => !ackAllProcessing && setShowAckAllModal(false)} />
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="bg-gray-900 border border-gray-800 rounded-lg max-w-md w-full shadow-xl">
              <div className="border-b border-gray-800 px-6 py-4">
                <h3 className="text-lg font-medium text-white">Acknowledge All Threat Events</h3>
              </div>
              <div className="px-6 py-4 space-y-4">
                <div className="bg-amber-950/30 border border-amber-900/50 rounded-lg p-3 flex gap-3">
                  <svg className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4v2m0 4v2M8.228 9.228A9 9 0 1120.228 20.228M12 5v4m0 4v4" />
                  </svg>
                  <p className="text-sm text-amber-300">This will acknowledge and clear all existing threat alerts from the active view. It will NOT suppress future alerts matching these patterns. Acknowledged events can still be viewed by toggling the suppressed filter.</p>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-2">Reason (optional)</label>
                  <input
                    type="text"
                    value={ackAllReason}
                    onChange={(e) => setAckAllReason(e.target.value)}
                    placeholder="e.g., Initial baseline, reviewed all events"
                    disabled={ackAllProcessing}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-amber-500 disabled:opacity-50"
                  />
                </div>
              </div>
              <div className="border-t border-gray-800 px-6 py-4 flex items-center justify-end gap-3">
                <button
                  onClick={() => !ackAllProcessing && setShowAckAllModal(false)}
                  disabled={ackAllProcessing}
                  className="px-4 py-2 rounded-lg text-sm font-medium bg-gray-700 text-gray-200 hover:bg-gray-600 transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={async () => {
                    setAckAllProcessing(true);
                    setActionError(null);
                    let completed = 0;
                    let failed = 0;
                    for (const event of visibleEvents) {
                      try {
                        const r = await fetch(`/api/v1/events/${event.event_id}/ack`, {
                          method: 'PUT',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({ reason: ackAllReason }),
                        });
                        if (r.ok) completed++;
                        else failed++;
                      } catch {
                        failed++;
                      }
                    }
                    setAckAllProcessing(false);
                    setShowAckAllModal(false);
                    setAckAllReason('');
                    if (failed === 0) {
                      onRefresh();
                    } else {
                      setActionError(`Acknowledged ${completed} events, ${failed} failed`);
                      setTimeout(() => onRefresh(), 500);
                    }
                  }}
                  disabled={ackAllProcessing}
                  className="px-4 py-2 rounded-lg text-sm font-medium bg-amber-500 text-gray-950 hover:bg-amber-400 transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  {ackAllProcessing && <Spinner />}
                  {ackAllProcessing ? 'Acknowledging...' : 'Yes, Acknowledge All'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Error toast */}
      {actionError && (
        <div className="bg-red-950/30 border border-red-900/50 rounded-lg p-3 mb-4 flex items-center justify-between">
          <span className="text-sm text-red-300">{actionError}</span>
          <button onClick={() => setActionError(null)} className="text-red-400 hover:text-red-200 text-sm ml-3">Dismiss</button>
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Total Events" value={stats?.total_count || '0'} sub="All time" />
        <StatCard label="Threats Detected" value={stats?.threat_count || '0'} sub="With anomaly score" highlight={stats?.threat_count > 0} />
        <StatCard label="Events (24h)" value={stats?.last_24h_count || '0'} sub="Last 24 hours" />
        <StatCard label="Blocked Queries" value={events.filter(e => e.blocked).length} sub="Recent events" />
      </div>

      {/* Timeline Chart */}
      {timeline && timeline.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-8">
          <h3 className="text-sm font-medium mb-4">Event Timeline (24h)</h3>
          <div className="flex items-end gap-1 h-32 justify-between">
            {timeline.map((hour, idx) => {
              const maxCount = Math.max(...timeline.map(t => t.count || 0));
              const height = maxCount > 0 ? ((hour.count || 0) / maxCount) * 100 : 0;
              const isThreat = (hour.count || 0) > 0;
              return (
                <div key={idx} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full bg-gray-800 rounded-sm relative h-28 flex items-end">
                    <div
                      className={`w-full rounded-sm transition-all ${isThreat ? 'bg-red-500' : 'bg-teal-500'}`}
                      style={{ height: `${Math.max(height, 5)}%` }}
                      title={`${hour.count || 0} events`}
                    />
                  </div>
                  <span className="text-xs text-gray-600 whitespace-nowrap">{new Date(hour.hour).getHours()}:00</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Whitelist Management Panel */}
      {showWhitelistPanel && (
        <div className="bg-gray-900 border border-teal-500/20 rounded-lg p-5 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-medium text-teal-300">Known Traffic Whitelist</h3>
              <p className="text-xs text-gray-500 mt-1">Auto-hide expected home network traffic. Toggle rules on/off to tune your signal-to-noise ratio.</p>
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <span className="text-xs text-gray-400">Hide whitelisted</span>
              <div className={`relative w-9 h-5 rounded-full transition-colors ${hideWhitelisted ? 'bg-teal-500' : 'bg-gray-700'}`}
                onClick={() => setHideWhitelisted(!hideWhitelisted)}>
                <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${hideWhitelisted ? 'translate-x-4' : 'translate-x-0.5'}`} />
              </div>
            </label>
          </div>
          {(() => {
            const categories = [...new Set((whitelistRules || []).map(r => r.category))].sort();
            const categoryLabels = { apple: 'Apple', mdns: 'mDNS / Bonjour', cloud: 'Cloud Services', os_updates: 'OS Updates', iot: 'IoT / Smart Home', custom: 'Custom' };
            const toggleRule = (ruleId, enabled) => {
              fetch(`/api/v1/whitelist/${ruleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled }),
              }).then(r => { if (r.ok) onRefresh(); else setActionError('Failed to update whitelist rule'); })
                .catch(() => setActionError('Failed to update whitelist rule'));
            };
            const deleteRule = (ruleId) => {
              fetch(`/api/v1/whitelist/${ruleId}`, { method: 'DELETE' })
                .then(r => { if (r.ok) onRefresh(); else r.text().then(t => setActionError(t || 'Cannot delete default rules')); })
                .catch(() => setActionError('Failed to delete whitelist rule'));
            };
            return categories.length > 0 ? (
              <div className="space-y-4">
                {categories.map(cat => (
                  <div key={cat}>
                    <h4 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">{categoryLabels[cat] || cat}</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {whitelistRules.filter(r => r.category === cat).map(rule => (
                        <div key={rule.rule_id} className={`flex items-center justify-between bg-gray-800/60 rounded-lg px-3 py-2 ${
                          rule.enabled ? '' : 'opacity-50'
                        }`}>
                          <div className="flex items-center gap-2 min-w-0 flex-1">
                            <div className={`relative w-8 h-4 rounded-full transition-colors cursor-pointer ${rule.enabled ? 'bg-teal-500' : 'bg-gray-700'}`}
                              onClick={() => toggleRule(rule.rule_id, !rule.enabled)}>
                              <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${rule.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                            </div>
                            <div className="min-w-0">
                              <span className="text-sm text-gray-200 block truncate">{rule.name}</span>
                              <span className="text-xs text-gray-500 font-mono block truncate">
                                {rule.domain_pattern || rule.source_ip_pattern || '—'}
                                {rule.tag_match ? ` [${rule.tag_match}]` : ''}
                              </span>
                            </div>
                          </div>
                          {!rule.is_default && (
                            <button onClick={() => deleteRule(rule.rule_id)}
                              className="text-gray-600 hover:text-red-400 text-xs ml-2 shrink-0">
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
                <div className="border-t border-gray-800 pt-3">
                  <AddWhitelistRule onAdd={() => onRefresh()} onError={setActionError} />
                </div>
              </div>
            ) : (
              <div className="text-center py-4">
                <p className="text-gray-500 text-sm mb-3">No whitelist rules loaded yet.</p>
                <button
                  onClick={() => {
                    fetch('/api/v1/whitelist/seed', { method: 'POST' })
                      .then(r => { if (r.ok) onRefresh(); })
                      .catch(() => {});
                  }}
                  className="bg-teal-500/20 text-teal-300 border border-teal-500/30 px-4 py-2 rounded-lg text-sm hover:bg-teal-500/30 transition-colors"
                >
                  Load Default Rules
                </button>
              </div>
            );
          })()}
        </div>
      )}

      {/* Active Context Filter Indicator (SNR-24) + Reset */}
      {(contextFilter !== 'all' || severityFilter !== 'all') && (
        <div className="mb-2 flex items-center gap-2">
          {contextFilter !== 'all' && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-teal-500/10 text-teal-400 border border-teal-500/30">
              Active filter: {contextFilter === 'new_device' ? 'New Devices only' : contextFilter === 'iot' ? 'IoT Segment only' : 'EOL Routers only'}
            </span>
          )}
          {severityFilter !== 'all' && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/30">
              Severity: {severityFilter}
            </span>
          )}
          <button
            onClick={() => { setSeverityFilter('all'); setContextFilter('all'); }}
            className="text-xs px-2 py-0.5 rounded-full bg-gray-700 text-gray-300 hover:bg-gray-600 border border-gray-600 transition-colors"
          >
            Reset All Filters
          </button>
        </div>
      )}

      {/* SNR Impact Summary */}
      <div className="flex items-center gap-4 mb-3 text-xs text-gray-400">
        <span>
          {suppressedEvents.length} events suppressed by rules
        </span>
        {whitelistedCount > 0 && (
          <span>
            {whitelistedCount} events hidden by whitelist
          </span>
        )}
        <span className="text-gray-500">•</span>
        <span>
          Showing {displayEvents.length} active threats
        </span>
      </div>

      {/* Active Suppression Rules Summary (SNR-25 + SNR-28) */}
      {activeRules.length > 0 && (
        <div className="mb-3 text-xs">
          <span className="text-gray-500">Active suppression rules: </span>
          {activeRules.slice(0, 3).map((rule) => (
            <span key={rule.rule_id} className="inline-block bg-gray-800 text-gray-300 px-1.5 py-0.5 rounded mr-1">
              {rule.reason || 'Unnamed rule'} <span className="text-teal-400">({ruleMatchCounts[rule.rule_id] || 0})</span>
            </span>
          ))}
          {activeRules.length > 3 && (
            <span className="text-gray-500">+{activeRules.length - 3} more</span>
          )}
          <button
            onClick={() => setShowSuppressed(true)}
            className="ml-2 text-teal-400 hover:text-teal-300 underline"
          >
            View all suppressed
          </button>
        </div>
      )}

      {/* Severity Filter + Suppressed Toggle */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex gap-2">
          {['all', 'warning', 'critical'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                severityFilter === sev ? 'bg-amber-500 text-gray-950' : 'bg-gray-800 text-gray-400 hover:text-white'
              }`}
            >
              {sev === 'all' 
                ? `All (${allCount})` 
                : sev === 'critical' 
                  ? `Critical (>0.7) (${criticalCount})` 
                  : `Warning (0.3-0.7) (${warningCount})`}
            </button>
          ))}

          {/* Contextual risk filters (SNR-16) */}
          <div className="w-px bg-gray-700 mx-1" />
          {[
            { key: 'all', label: 'All Contexts' },
            { key: 'new_device', label: 'New Devices' },
            { key: 'iot', label: 'IoT Segment' },
            { key: 'eol', label: 'EOL Routers' },
          ].map((ctx) => (
            <button
              key={ctx.key}
              onClick={() => setContextFilter(ctx.key)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                contextFilter === ctx.key ? 'bg-teal-500 text-gray-950' : 'bg-gray-800 text-gray-400 hover:text-white'
              }`}
            >
              {ctx.key === 'all' 
                ? `All Contexts (${allContextCount})` 
                : `${ctx.label} (${ctx.key === 'new_device' ? newDeviceContextCount : ctx.key === 'iot' ? iotContextCount : eolContextCount})`}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          {hideWhitelisted && whitelistedCount > 0 && (
            <button
              onClick={() => setHideWhitelisted(false)}
              className="px-3 py-1 rounded-full text-xs font-medium bg-teal-500/10 text-teal-400 hover:bg-teal-500/20 transition-colors"
            >
              {whitelistedCount} whitelisted
            </button>
          )}
          <button
            onClick={() => setShowSuppressed(!showSuppressed)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              showSuppressed ? 'bg-gray-600 text-white' : 'bg-gray-800 text-gray-500 hover:text-white'
            }`}
          >
            {showSuppressed ? `Showing ${suppressedEvents.length} suppressed` : `${suppressedEvents.length} suppressed`}
          </button>
        </div>
      </div>

      {/* Events Table */}
      {paginatedGroups.length > 0 ? (
        <>
          <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
            <table className="w-full table-fixed">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800 bg-gray-800/30">
                  <th className="px-4 py-3 w-10"></th>
                  <th className="px-4 py-3 w-24">Time</th>
                  <th className="px-4 py-3 w-48">Source Device</th>
                  <th className="px-4 py-3">Domain</th>
                  <th className="px-4 py-3 w-24">Server</th>
                  <th className="px-4 py-3 w-16">Ans</th>
                  {hasProcColumn && <th className="px-4 py-3 w-10" title="Process hint from sensor (future host-local mode)">Proc</th>}
                  <th className="px-4 py-3 w-32">Score</th>
                  <th className="px-4 py-3 w-32">Detection</th>
                  <th className="px-4 py-3 w-28">Status</th>
                </tr>
              </thead>
              <tbody>
                {paginatedGroups.map((group) => {
                  const event = group.lead;
                  const isExpanded = expandedRows.has(event.event_id);
                  const meta = parseMetadata(event.metadata);
                  const device = event.source_ip ? deviceByIP[event.source_ip] : null;
                  const deviceName = device?.custom_name || device?.hostname || null;
                  const eventState = getEventState(event);
                  const isEditing = actionMode && actionMode.eventId === event.event_id;
                  return (
                    <React.Fragment key={event.event_id}>
                      <tr
                        className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors cursor-pointer ${
                          (event.anomaly_score || 0) > 0.7 ? 'bg-red-950/10' : ''
                        } ${eventState.type !== 'active' ? 'opacity-60' : ''}`}
                        onClick={() => toggleRowExpanded(event.event_id)}
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-1">
                            <svg
                              className={`w-4 h-4 text-gray-500 transition-transform shrink-0 ${isExpanded ? 'rotate-90' : ''}`}
                              fill="none" stroke="currentColor" viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                            </svg>
                            {group.count > 1 && (
                              <span className="bg-gray-700 text-gray-300 text-xs font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center">{group.count}</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-400 truncate">{timeAgo(event.timestamp)}</td>
                        <td className="px-4 py-3">
                          <div className="text-sm truncate">
                            {device ? (
                              <button
                                className="text-left hover:text-amber-400 transition-colors"
                                onClick={(e) => { e.stopPropagation(); onNavigate && onNavigate('devices'); }}
                                title={`View device: ${device.ip_address}`}
                              >
                                <span className="font-medium text-amber-300">{deviceName || device.ip_address}</span>
                                {device.mac_address && <span className="text-xs text-gray-500 ml-1.5">{device.mac_address.slice(-8)}</span>}
                                {event.network_segment && event.network_segment !== 'default' && (
                                  <span className="ml-1.5 text-[10px] px-1 py-0.5 rounded bg-gray-700 text-gray-400">{event.network_segment}</span>
                                )}
                                {event.device_vendor && <span className="ml-1 text-[10px] text-gray-500">({event.device_vendor})</span>}
                                {device.model && <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-gray-800 text-gray-400">{device.model}</span>}
                                {device.discovery_source && device.discovery_source !== 'nmap_active' && device.discovery_source !== 'active_nmap' && <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-gray-800 text-gray-400">{discoveryLabel(device.discovery_source)}</span>}
                                {device.services && device.services.length > 0 && <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-gray-800 text-gray-400">S:{device.services.length}</span>}
                              </button>
                            ) : (
                              <span className="font-mono text-gray-200">{event.source_ip || '—'}</span>
                            )}
                            {!device && event.device_vendor && (
                              <span className="text-xs text-gray-500 ml-2">({event.device_vendor})</span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm font-mono text-gray-300 truncate" title={event.domain}>
                          {event.domain || '—'}
                        </td>
                        <td className="px-4 py-3 text-xs font-mono text-gray-400 truncate" title={event.server_ip || ''}>
                          {event.server_ip || '—'}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-400 text-center" title={meta && meta.dns_answers && meta.dns_answers.length ? meta.dns_answers.join(', ') : ''}>
                          {meta && meta.dns_answers && meta.dns_answers.length ? meta.dns_answers.length : '—'}
                        </td>
                        {hasProcColumn && (
                          <td className="px-4 py-3 text-xs text-gray-400 text-center font-mono truncate" title={meta && meta.process ? meta.process : ''} style={{maxWidth: '7rem'}}>
                            {meta && meta.process ? (meta.process.length > 12 ? meta.process.slice(0, 12) + '…' : meta.process) : '—'}
                          </td>
                        )}
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="w-16 bg-gray-800 rounded h-2 shrink-0">
                              <div
                                className={`h-full rounded ${getScoreColor(event.anomaly_score || 0)}`}
                                style={{ width: `${getScoreBarWidth(event.anomaly_score || 0)}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-500">{(event.anomaly_score || 0).toFixed(2)}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {event.tags && event.tags.length > 0 ? (
                            <div className="flex gap-1 flex-wrap">
                              {event.tags.slice(0, 2).map((tag, idx) => (
                                <span
                                  key={idx}
                                  className={`text-xs px-2 py-0.5 rounded font-medium ${tagColors[tag] || 'bg-gray-800 text-gray-300'}`}
                                >
                                  {tagLabel(tag)}
                                </span>
                              ))}
                              {event.tags.length > 2 && <span className="text-xs text-gray-500">+{event.tags.length - 2}</span>}
                            </div>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm">
                          <div className="flex flex-col gap-1">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium inline-block w-fit ${
                              event.blocked ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300'
                            }`}>
                              {event.blocked ? 'blocked' : 'allowed'}
                            </span>
                            {eventState.type === 'acked' && (
                              <span className="text-xs text-blue-400 px-2 py-0.5 bg-blue-500/10 rounded w-fit">ack'd</span>
                            )}
                            {eventState.type === 'suppressed' && (
                              <span className="text-xs text-gray-400 px-2 py-0.5 bg-gray-500/10 rounded w-fit">suppressed</span>
                            )}
                            {!hideWhitelisted && isWhitelisted(event) && (
                              <span className="text-xs text-teal-400 px-2 py-0.5 bg-teal-500/10 rounded w-fit">whitelisted</span>
                            )}
                          </div>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-gray-800/20 border-b border-gray-800/50">
                          <td colSpan={hasProcColumn ? 10 : 9} className="px-6 py-5">
                            <div className="space-y-4">
                              {/* Grouped events button */}
                              {group.count > 1 && (
                                <button
                                  className="w-full bg-gray-800/60 border border-gray-700 rounded-lg p-3 text-sm text-gray-300 hover:bg-gray-800 transition-colors flex items-center justify-between"
                                  onClick={(e) => { e.stopPropagation(); setGroupModal({ events: group.members, domain: event.domain }); }}
                                >
                                  <span>View all {group.count} individual events</span>
                                  <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                                  </svg>
                                </button>
                              )}

                              {/* Threat explanation */}
                              {event.threat_desc && (
                                <div className="bg-red-950/20 border border-red-900/30 rounded-lg p-4">
                                  <div className="flex items-center justify-between mb-2">
                                    <h4 className="text-xs uppercase tracking-wider text-red-400 font-medium">Why this was flagged</h4>
                                    {meta?.threat_db && (
                                      <a
                                        href={`https://www.virustotal.com/gui/domain/${event.domain}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="text-xs text-amber-400 hover:text-amber-300"
                                        onClick={(e) => e.stopPropagation()}
                                      >
                                        More info →
                                      </a>
                                    )}
                                  </div>
                                  <p className="text-sm text-gray-300 leading-relaxed">{event.threat_desc}</p>
                                </div>
                              )}

                              {/* Quick Suppression - high impact for SNR */}
                              <div className="bg-gray-900/60 border border-gray-700 rounded-lg p-3">
                                <div className="text-xs uppercase tracking-wider text-teal-400 font-medium mb-2">Quick Noise Reduction</div>
                                <div className="flex flex-wrap gap-2">
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleCreateSuppression(event, `Suppressed ${event.domain} for ${event.source_ip}`); }}
                                    className="text-xs px-3 py-1.5 bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 border border-teal-500/30 rounded transition-colors"
                                  >
                                    Suppress this domain for this device
                                  </button>

                                  {/* Prefer contextual tags for suppression (high SNR value) */}
                                  {event.tags && event.tags.includes('iot_context') && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        fetch('/api/v1/suppression', {
                                          method: 'POST',
                                          headers: { 'Content-Type': 'application/json' },
                                          body: JSON.stringify({ domain: '', source_ip: '', tags: ['iot_context'], reason: 'Suppressed all IoT segment activity' })
                                        }).then(r => { if (r.ok) onRefresh(); });
                                      }}
                                      className="text-xs px-3 py-1.5 bg-teal-500/10 hover:bg-teal-500/20 text-teal-300 border border-teal-500/30 rounded transition-colors"
                                    >
                                      Suppress all from IoT Segment {iotContextCount > 0 ? `(${iotContextCount})` : ''}
                                    </button>
                                  )}
                                  {event.tags && event.tags.includes('new_device_context') && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        fetch('/api/v1/suppression', {
                                          method: 'POST',
                                          headers: { 'Content-Type': 'application/json' },
                                          body: JSON.stringify({ domain: '', source_ip: '', tags: ['new_device_context'], reason: 'Suppressed all new device activity' })
                                        }).then(r => { if (r.ok) onRefresh(); });
                                      }}
                                      className="text-xs px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded transition-colors"
                                    >
                                      Suppress all from New Devices {newDeviceContextCount > 0 ? `(${newDeviceContextCount})` : ''}
                                    </button>
                                  )}
                                  {(event.tags && (event.tags.includes('eol_router') || event.tags.includes('eol_device_context'))) && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        fetch('/api/v1/suppression', {
                                          method: 'POST',
                                          headers: { 'Content-Type': 'application/json' },
                                          body: JSON.stringify({ domain: '', source_ip: '', tags: ['eol_router'], reason: 'Suppressed all EOL router high-risk device activity' })
                                        }).then(r => { if (r.ok) onRefresh(); });
                                      }}
                                      className="text-xs px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 rounded transition-colors"
                                    >
                                      Suppress all from EOL Routers {eolContextCount > 0 ? `(${eolContextCount})` : ''}
                                    </button>
                                  )}

                                  {/* Vendor + Segment suppression for IoT noise */}
                                  {event.device_vendor && event.network_segment && event.network_segment !== 'default' && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        fetch('/api/v1/suppression', {
                                          method: 'POST',
                                          headers: { 'Content-Type': 'application/json' },
                                          body: JSON.stringify({
                                            domain: '',
                                            source_ip: '',
                                            tags: [`vendor:${event.device_vendor.toLowerCase()}`, `segment:${event.network_segment}`],
                                            reason: `Suppressed all ${event.device_vendor} on ${event.network_segment}`
                                          })
                                        }).then(r => { if (r.ok) onRefresh(); });
                                      }}
                                      className="text-xs px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 rounded transition-colors"
                                    >
                                      Suppress all {event.device_vendor} on {event.network_segment}
                                    </button>
                                  )}

                                  {/* Fallback to first non-contextual tag */}
                                  {event.tags && event.tags.length > 0 && !event.tags.includes('iot_context') && !event.tags.includes('new_device_context') && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        fetch('/api/v1/suppression', {
                                          method: 'POST',
                                          headers: { 'Content-Type': 'application/json' },
                                          body: JSON.stringify({
                                            domain: '',
                                            source_ip: event.source_ip,
                                            tags: [event.tags[0]],
                                            reason: `Suppressed ${event.tags[0]} for device`
                                          })
                                        }).then(r => { if (r.ok) onRefresh(); });
                                      }}
                                      className="text-xs px-3 py-1.5 bg-orange-500/10 hover:bg-orange-500/20 text-orange-300 border border-orange-500/30 rounded transition-colors"
                                    >
                                      Suppress "{tagLabel(event.tags[0])}" for this device
                                    </button>
                                  )}
                                </div>
                              </div>

                              {/* Device info card (if matched) */}
                              {device && (
                                <div className="bg-teal-950/20 border border-teal-900/30 rounded-lg p-4">
                                  <h4 className="text-xs uppercase tracking-wider text-teal-400 font-medium mb-2">Source Device</h4>
                                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                                    <div>
                                      <span className="text-xs text-gray-500 block">Name</span>
                                      <span className="text-gray-200">{device.custom_name || device.hostname || '—'}</span>
                                    </div>
                                    <div>
                                      <span className="text-xs text-gray-500 block">IP</span>
                                      <span className="font-mono text-gray-200">{device.ip_address}</span>
                                    </div>
                                    <div>
                                      <span className="text-xs text-gray-500 block">MAC</span>
                                      <span className="font-mono text-gray-200">{device.mac_address || '—'}</span>
                                    </div>
                                    <div>
                                      <span className="text-xs text-gray-500 block">Vendor</span>
                                      <span className="text-gray-200">{device.vendor || '—'}</span>
                                    </div>
                                    <div>
                                      <span className="text-xs text-gray-500 block">Model</span>
                                      <span className="text-gray-200">{device.model || '—'}</span>
                                    </div>
                                    <div>
                                      <span className="text-xs text-gray-500 block">Discovery Source</span>
                                      <span className="text-gray-200 text-xs">{discoveryLabel(device.discovery_source)}</span>
                                    </div>
                                    {device.services && device.services.length > 0 && (
                                      <div className="col-span-2">
                                        <span className="text-xs text-gray-500 block">Services (from passive)</span>
                                        <div className="flex flex-wrap gap-1 mt-0.5">
                                          {device.services.map((s, i) => (
                                            <span key={i} className="inline-block text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700" title={s}>{s}</span>
                                          ))}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                  <button
                                    className="text-xs text-amber-400 hover:text-amber-300 mt-2"
                                    onClick={(e) => { e.stopPropagation(); onNavigate && onNavigate('devices'); }}
                                  >
                                    View device details →
                                  </button>
                                </div>
                              )}

                              {/* Detection details grid */}
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                <div>
                                  <span className="text-xs text-gray-500 block">Source IP</span>
                                  <span className="text-sm font-mono text-gray-200">{event.source_ip || '—'}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Server IP</span>
                                  <span className="text-sm font-mono text-gray-200">{event.server_ip || '—'}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Process (from sensor)</span>
                                  <span className="text-sm font-mono text-gray-200">{(meta && meta.process) || '—'}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Resolved IP</span>
                                  <span className="text-sm font-mono text-gray-200">{event.resolved_ip || '—'}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Answers / Destinations</span>
                                  <span className="text-sm font-mono text-gray-200 break-all">{(meta && meta.dns_answers && meta.dns_answers.length ? meta.dns_answers.join(', ') : (event.resolved_ip || '—'))}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Query Type</span>
                                  <span className="text-sm text-gray-200">{event.query_type || '—'}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">DNS Source</span>
                                  <span className="text-sm text-gray-200">{dnsSourceLabel(event.dns_source)}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Device Vendor</span>
                                  <span className="text-sm text-gray-200">{event.device_vendor || '—'}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Network Segment</span>
                                  <span className="text-sm text-gray-200">{event.network_segment || 'default'}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Anomaly Score</span>
                                  <span className="text-sm text-gray-200">{(event.anomaly_score || 0).toFixed(3)}</span>
                                </div>
                                <div>
                                  <span className="text-xs text-gray-500 block">Event ID</span>
                                  <span className="text-sm font-mono text-gray-400 text-xs">{event.event_id}</span>
                                </div>
                              </div>

                              {/* Dedicated answers/destinations from richer sensor data for actionability */}
                              {meta && meta.dns_answers && meta.dns_answers.length > 0 && (
                                <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
                                  <h4 className="text-xs uppercase tracking-wider text-gray-500 font-medium mb-3">Answers / Destinations (from sensor)</h4>
                                  <div className="text-sm font-mono text-gray-200 break-all">{meta.dns_answers.join(', ')}</div>
                                </div>
                              )}

                              {/* Algorithm-specific metadata */}
                              {meta && (
                                <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
                                  <h4 className="text-xs uppercase tracking-wider text-gray-500 font-medium mb-3">Detection Details</h4>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                                    {meta.dga && (
                                      <div className="bg-gray-800/50 rounded p-3">
                                        <span className="text-red-400 font-medium text-xs">DGA Analysis</span>
                                        <div className="mt-1 text-gray-300 space-y-1">
                                          <div>Entropy: <span className="font-mono">{meta.dga.entropy.toFixed(2)}</span> bits</div>
                                          <div>Bigram anomaly: <span className="font-mono">{(meta.dga.bigram_score * 100).toFixed(0)}%</span></div>
                                          <div>Scored label: <span className="font-mono">{meta.dga.label}</span></div>
                                          <div>Composite: <span className="font-mono">{(meta.dga.score * 100).toFixed(0)}%</span></div>
                                        </div>
                                      </div>
                                    )}
                                    {meta.tunnel && (
                                      <div className="bg-gray-800/50 rounded p-3">
                                        <span className="text-purple-400 font-medium text-xs">Tunnel Analysis</span>
                                        <div className="mt-1 text-gray-300 space-y-1">
                                          <div>Score: <span className="font-mono">{(meta.tunnel.score * 100).toFixed(0)}%</span></div>
                                          <div>Signals: {meta.tunnel.signals.map((s, i) => (
                                            <span key={i} className="inline-block bg-purple-500/10 text-purple-300 text-xs px-1.5 py-0.5 rounded mr-1 mt-1">{s}</span>
                                          ))}</div>
                                        </div>
                                      </div>
                                    )}
                                    {meta.beacon && (
                                      <div className="bg-gray-800/50 rounded p-3">
                                        <span className="text-orange-400 font-medium text-xs">Beacon Analysis</span>
                                        <div className="mt-1 text-gray-300 space-y-1">
                                          <div>Mean interval: <span className="font-mono">{meta.beacon.mean_interval_sec.toFixed(1)}s</span></div>
                                          <div>Variation (CV): <span className="font-mono">{(meta.beacon.cv * 100).toFixed(1)}%</span></div>
                                          <div>Samples: <span className="font-mono">{meta.beacon.samples}</span></div>
                                        </div>
                                      </div>
                                    )}
                                    {meta.rebinding && (
                                      <div className="bg-gray-800/50 rounded p-3">
                                        <span className="text-pink-400 font-medium text-xs">Rebinding Detection</span>
                                        <div className="mt-1 text-gray-300 space-y-1">
                                          <div>Public IP: <span className="font-mono">{meta.rebinding.public_ip}</span></div>
                                          <div>Private IP: <span className="font-mono">{meta.rebinding.private_ip}</span></div>
                                        </div>
                                      </div>
                                    )}
                                    {meta.device_context && meta.device_context.boosts && meta.device_context.boosts.length > 0 && (
                                      <div className="bg-gray-800/50 rounded p-3">
                                        <span className="text-teal-400 font-medium text-xs">Device Context Boosts</span>
                                        <div className="mt-1 text-gray-300 space-y-1">
                                          <div>Segment: <span className="font-mono">{meta.device_context.segment || '—'}</span></div>
                                          <div>Vendor: <span className="font-mono">{meta.device_context.vendor || '—'}</span></div>
                                          <div>Boosts: {meta.device_context.boosts.map((b, i) => (
                                            <span key={i} className="inline-block bg-teal-500/10 text-teal-300 text-xs px-1.5 py-0.5 rounded mr-1 mt-1">{b}</span>
                                          ))}</div>
                                        </div>
                                      </div>
                                    )}
                                    {meta.threat_db && (
                                      <div className="bg-gray-800/50 rounded p-3">
                                        <span className="text-red-400 font-medium text-xs">Threat Intelligence</span>
                                        <div className="mt-1 text-gray-300 space-y-1">
                                          <div>Confidence: <span className="font-mono">{(meta.threat_db.confidence * 100).toFixed(0)}%</span></div>
                                          {meta.threat_db.feed_tags && <div>Tags: {meta.threat_db.feed_tags.join(', ')}</div>}
                                        </div>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}

                              {/* Action panel — stateful ack/suppress */}
                              <div className="bg-gray-900/50 border border-gray-800 rounded-lg p-4">
                                <h4 className="text-xs uppercase tracking-wider text-gray-500 font-medium mb-3">Actions</h4>

                                {/* Current state display */}
                                {eventState.type === 'acked' && !isEditing && (
                                  <div className="flex items-start justify-between bg-blue-950/20 border border-blue-900/30 rounded p-3 mb-3">
                                    <div>
                                      <span className="text-xs font-medium text-blue-400">Acknowledged</span>
                                      {eventState.reason && <p className="text-sm text-gray-300 mt-1">{eventState.reason}</p>}
                                    </div>
                                    <div className="flex gap-2 shrink-0 ml-3">
                                      <button
                                        className="text-xs text-blue-400 hover:text-blue-300"
                                        onClick={(e) => { e.stopPropagation(); setActionMode({ eventId: event.event_id, mode: 'edit-ack', reason: eventState.reason }); }}
                                      >
                                        Edit
                                      </button>
                                      <button
                                        className="text-xs text-gray-500 hover:text-gray-300"
                                        onClick={(e) => { e.stopPropagation(); handleUnack(event.event_id); }}
                                      >
                                        Remove
                                      </button>
                                      <button
                                        className="text-xs text-amber-400 hover:text-amber-300"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleUnack(event.event_id);
                                          setActionMode({ eventId: event.event_id, mode: 'suppress', reason: eventState.reason });
                                        }}
                                      >
                                        Switch to Suppress
                                      </button>
                                    </div>
                                  </div>
                                )}

                                {eventState.type === 'suppressed' && !isEditing && (
                                  <div className="flex items-start justify-between bg-gray-800/40 border border-gray-700 rounded p-3 mb-3">
                                    <div>
                                      <span className="text-xs font-medium text-gray-400">Suppressed by rule</span>
                                      {eventState.reason && <p className="text-sm text-gray-300 mt-1">{eventState.reason}</p>}
                                      <p className="text-xs text-gray-600 mt-1">Matching: {eventState.rule?.domain || '*'} from {eventState.rule?.source_ip || '*'}</p>
                                    </div>
                                    <div className="flex gap-2 shrink-0 ml-3">
                                      <button
                                        className="text-xs text-gray-400 hover:text-gray-200"
                                        onClick={(e) => { e.stopPropagation(); handleDeleteSuppression(eventState.rule.rule_id); }}
                                      >
                                        Remove Rule
                                      </button>
                                      <button
                                        className="text-xs text-blue-400 hover:text-blue-300"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          handleDeleteSuppression(eventState.rule.rule_id);
                                          setActionMode({ eventId: event.event_id, mode: 'ack', reason: eventState.reason });
                                        }}
                                      >
                                        Switch to Ack
                                      </button>
                                    </div>
                                  </div>
                                )}

                                {/* Edit/Create form */}
                                {isEditing ? (
                                  <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                                    <span className="text-xs text-gray-500 shrink-0">
                                      {actionMode.mode === 'ack' || actionMode.mode === 'edit-ack' ? 'Ack reason:' : 'Suppress reason:'}
                                    </span>
                                    <input
                                      type="text"
                                      value={actionMode.reason}
                                      onChange={(e) => setActionMode({ ...actionMode, reason: e.target.value })}
                                      placeholder="e.g., my VPN, Ring doorbell, expected traffic"
                                      className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-amber-500"
                                      autoFocus
                                      onKeyDown={(e) => {
                                        if (e.key === 'Enter') {
                                          if (actionMode.mode === 'ack' || actionMode.mode === 'edit-ack') handleAck(event.event_id, actionMode.reason);
                                          else handleCreateSuppression(event, actionMode.reason);
                                        }
                                        if (e.key === 'Escape') setActionMode(null);
                                      }}
                                    />
                                    <button
                                      className="text-xs bg-amber-500/20 text-amber-300 px-3 py-1.5 rounded hover:bg-amber-500/30 shrink-0"
                                      onClick={() => {
                                        if (actionMode.mode === 'ack' || actionMode.mode === 'edit-ack') handleAck(event.event_id, actionMode.reason);
                                        else handleCreateSuppression(event, actionMode.reason);
                                      }}
                                    >
                                      Save
                                    </button>
                                    <button
                                      className="text-xs text-gray-500 hover:text-gray-300 shrink-0"
                                      onClick={() => setActionMode(null)}
                                    >
                                      Cancel
                                    </button>
                                  </div>
                                ) : eventState.type === 'active' && (
                                  <div className="flex gap-2">
                                    <button
                                      className="text-xs bg-blue-500/10 text-blue-300 border border-blue-500/20 px-3 py-1.5 rounded hover:bg-blue-500/20 transition-colors"
                                      onClick={(e) => { e.stopPropagation(); setActionMode({ eventId: event.event_id, mode: 'ack', reason: '' }); }}
                                    >
                                      Acknowledge
                                    </button>
                                    <button
                                      className="text-xs bg-gray-700/50 text-gray-300 border border-gray-600 px-3 py-1.5 rounded hover:bg-gray-700 transition-colors"
                                      onClick={(e) => { e.stopPropagation(); setActionMode({ eventId: event.event_id, mode: 'suppress', reason: '' }); }}
                                    >
                                      Suppress Similar
                                    </button>
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Load More */}
          {grouped.length > visibleCount && (
            <div className="text-center mt-4">
              <button
                onClick={() => setVisibleCount(prev => prev + 30)}
                className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-6 py-2 rounded-lg text-sm font-medium transition-colors"
              >
                Show more ({grouped.length - visibleCount} remaining)
              </button>
            </div>
          )}
        </>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <p className="text-gray-500">
            {showSuppressed ? 'No suppressed events.' : 'No threat events detected. Your network is secure.'}
          </p>
        </div>
      )}

      {/* Grouped Events Modal */}
      {groupModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-2xl w-full p-6 max-h-[80vh] flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-display">Grouped Events</h3>
                <p className="text-sm text-gray-400 font-mono mt-1">{groupModal.domain}</p>
              </div>
              <button onClick={() => setGroupModal(null)} className="text-gray-500 hover:text-white text-lg px-2">✕</button>
            </div>
            <div className="overflow-y-auto flex-1 -mx-2 px-2">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-xs text-gray-500 uppercase border-b border-gray-800">
                    <th className="pb-2 pr-4">Time</th>
                    <th className="pb-2 pr-4">Source IP</th>
                    <th className="pb-2 pr-4">Score</th>
                    <th className="pb-2 pr-4">Status</th>
                    <th className="pb-2">Event ID</th>
                  </tr>
                </thead>
                <tbody>
                  {groupModal.events.map((evt) => (
                    <tr key={evt.event_id} className="border-b border-gray-800/30 text-sm">
                      <td className="py-2 pr-4 text-gray-300">{formatTimestamp(evt.timestamp)}</td>
                      <td className="py-2 pr-4 font-mono text-gray-400">{evt.source_ip || '—'}</td>
                      <td className="py-2 pr-4">
                        <span className={`text-xs font-medium ${(evt.anomaly_score || 0) > 0.7 ? 'text-red-400' : (evt.anomaly_score || 0) > 0.3 ? 'text-amber-400' : 'text-green-400'}`}>
                          {(evt.anomaly_score || 0).toFixed(2)}
                        </span>
                      </td>
                      <td className="py-2 pr-4">
                        <span className={`text-xs px-2 py-0.5 rounded ${evt.blocked ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300'}`}>
                          {evt.blocked ? 'blocked' : 'allowed'}
                        </span>
                      </td>
                      <td className="py-2 font-mono text-xs text-gray-600">{evt.event_id.slice(0, 8)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pt-4 border-t border-gray-800 mt-4">
              <button
                onClick={() => setGroupModal(null)}
                className="w-full bg-gray-800 hover:bg-gray-700 text-gray-300 py-2 rounded-lg text-sm font-medium transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// --- Sensor Setup Wizard ---

function SensorSetupDialog({ onDismiss }) {
  const [step, setStep] = useState(0);
  const [setupStatus, setSetupStatus] = useState(null);
  const [sensorConnected, setSensorConnected] = useState(false);
  const [deviceCount, setDeviceCount] = useState(0);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    // Check setup status on mount
    fetch('/api/v1/auth/setup-status')
      .then(r => r.json())
      .then(data => {
        setSetupStatus(data);
        // Auto-advance based on completed steps
        if (data.sensor_connected) setSensorConnected(true);
      })
      .catch(() => {});

    // Poll device count if on step 3
    if (step === 3) {
      const interval = setInterval(() => {
        fetch('/api/v1/devices')
          .then(r => r.json())
          .then(data => setDeviceCount(data.devices ? data.devices.length : 0))
          .catch(() => {});
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [step]);

  const checkSensorConnection = () => {
    setChecking(true);
    fetch('/api/v1/sensor/list')
      .then(r => r.json())
      .then(data => {
        if (data.sensors && data.sensors.length > 0) {
          setSensorConnected(true);
          setStep(3); // Jump to discovery step
        }
        setChecking(false);
      })
      .catch(() => setChecking(false));
  };

  const steps = [
    {
      title: 'Welcome to Vedetta',
      content: (
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <RookMark size={80} />
          </div>
          <p className="text-gray-300">Your network watchtower</p>
          <p className="text-sm text-gray-400">Vedetta is an open-source home SIEM that discovers devices on your network, monitors DNS activity, and alerts you to threats.</p>
        </div>
      ),
    },
    {
      title: 'Deploy Sensor',
      content: (
        <div className="space-y-4">
          <p className="text-sm text-gray-400">Install the lightweight sensor on any machine connected to your network.</p>
          <div className="bg-gray-800 rounded-lg p-4">
            <p className="text-xs text-gray-400 mb-2 font-medium">Quick start (macOS / Linux):</p>
            <code className="text-sm text-teal-400 font-mono block whitespace-pre-wrap break-words">
{`cd sensor && go build -o vedetta-sensor ./cmd/vedetta-sensor
sudo ./vedetta-sensor --core http://localhost:8080`}
            </code>
          </div>
          <div className="bg-gray-800 rounded-lg p-4">
            <p className="text-xs text-gray-400 mb-2 font-medium">Common options:</p>
            <div className="text-xs text-gray-400 space-y-1 font-mono">
              <p><span className="text-amber-400">--cidr</span> 10.0.0.0/24 <span className="text-gray-600"># scan specific subnet</span></p>
              <p><span className="text-amber-400">--interval</span> 5m <span className="text-gray-600"># scan frequency</span></p>
              <p><span className="text-amber-400">--ports</span> <span className="text-gray-600"># include port scan</span></p>
            </div>
          </div>
          <button
            onClick={checkSensorConnection}
            disabled={checking}
            className="w-full bg-blue-500 hover:bg-blue-400 disabled:bg-gray-700 text-white py-2 rounded-lg text-sm font-medium transition-colors"
          >
            {checking ? 'Checking...' : 'Check Connection'}
          </button>
        </div>
      ),
    },
    {
      title: 'Network Discovery',
      content: (
        <div className="space-y-4">
          <p className="text-sm text-gray-400">Your sensor is connected and discovering devices on your network.</p>
          <div className="bg-gray-800 rounded-lg p-6 text-center">
            <p className="text-3xl font-bold text-amber-400">{deviceCount}</p>
            <p className="text-xs text-gray-400 mt-1">device{deviceCount !== 1 ? 's' : ''} discovered</p>
          </div>
          <p className="text-xs text-gray-400">The sensor will continue to discover new devices as they connect to your network.</p>
        </div>
      ),
    },
    {
      title: 'DNS Monitoring',
      content: (
        <div className="space-y-4">
          <p className="text-sm text-gray-400">Choose how to monitor DNS activity on your network:</p>
          <div className="space-y-3">
            <label className="flex items-center gap-3 p-3 border border-gray-700 rounded-lg hover:bg-gray-800/50 cursor-pointer">
              <input type="radio" name="dns" defaultChecked className="w-4 h-4" />
              <div>
                <p className="text-sm text-gray-200">Passive DNS Capture</p>
                <p className="text-xs text-gray-500">Monitor DNS queries from your network</p>
              </div>
            </label>
            <label className="flex items-center gap-3 p-3 border border-gray-700 rounded-lg hover:bg-gray-800/50 cursor-pointer">
              <input type="radio" name="dns" className="w-4 h-4" />
              <div>
                <p className="text-sm text-gray-200">Pi-hole Integration</p>
                <p className="text-xs text-gray-500">Connect to existing Pi-hole instance</p>
              </div>
            </label>
            <label className="flex items-center gap-3 p-3 border border-gray-700 rounded-lg hover:bg-gray-800/50 cursor-pointer">
              <input type="radio" name="dns" className="w-4 h-4" />
              <div>
                <p className="text-sm text-gray-200">AdGuard Integration</p>
                <p className="text-xs text-gray-500">Connect to existing AdGuard instance</p>
              </div>
            </label>
          </div>
        </div>
      ),
    },
    {
      title: 'All Set!',
      content: (
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <svg className="w-16 h-16 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <p className="text-gray-300 font-medium">You're all set!</p>
          <p className="text-sm text-gray-400">Start exploring your network and monitoring threats.</p>
          <div className="grid grid-cols-2 gap-3 pt-4">
            <a href="#" className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg text-center transition-colors">View Devices</a>
            <a href="#" className="text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg text-center transition-colors">View Threats</a>
          </div>
        </div>
      ),
    },
  ];

  const currentStep = steps[step];
  const progress = ((step + 1) / steps.length) * 100;

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-lg w-full p-6">
        {/* Progress bar */}
        <div className="mb-6">
          <div className="h-1 bg-gray-800 rounded-full overflow-hidden">
            <div className="h-full bg-amber-500 transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
          <p className="text-xs text-gray-500 mt-2">{step + 1} of {steps.length}</p>
        </div>

        {/* Step title */}
        <h2 className="text-xl font-display mb-4">{currentStep.title}</h2>

        {/* Step content */}
        <div className="mb-6">
          {currentStep.content}
        </div>

        {/* Navigation buttons */}
        <div className="flex gap-3">
          {step > 0 && (
            <button
              onClick={() => setStep(step - 1)}
              className="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              Back
            </button>
          )}
          <button
            onClick={() => {
              if (step < steps.length - 1) {
                setStep(step + 1);
              } else {
                onDismiss();
              }
            }}
            className="flex-1 bg-amber-500 hover:bg-amber-400 text-gray-950 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            {step === steps.length - 1 ? 'Finish' : 'Continue'}
          </button>
          {step > 0 && step < steps.length - 1 && (
            <button
              onClick={onDismiss}
              className="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              Skip
            </button>
          )}
        </div>
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
        <h2 className="text-2xl font-display">Sensors</h2>
        <button
          onClick={onSetup}
          className="bg-amber-500 hover:bg-amber-400 text-gray-950 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
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
            <div key={s.sensor_id} className={`bg-gray-900 border rounded-lg p-4 ${s.is_primary ? 'border-amber-500/40' : 'border-gray-800'}`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`w-2.5 h-2.5 rounded-full ${s.status === 'online' ? 'bg-green-400' : 'bg-gray-600'}`} />
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium">{s.hostname}</p>
                      {s.is_primary && (
                        <span className="text-xs bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded">primary</span>
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
                    className="text-xs text-amber-400 hover:text-amber-300 transition-colors"
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

function DashboardView({ devices, scanStatus, newDeviceCount, scanning, onScan, onViewDevices, defaultCIDR, targets, sensors, threatStats, onNavigate }) {
  const segmentCounts = {};
  devices.forEach((d) => {
    segmentCounts[d.segment] = (segmentCounts[d.segment] || 0) + 1;
  });

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <StatCard label="Devices" value={devices.length || '—'} sub={devices.length > 0 ? `${newDeviceCount} new (24h)` : 'Awaiting sensor data'} highlight={newDeviceCount > 0} onClick={() => onNavigate('devices')} />
        <StatCard label="Sensors" value={sensors.length || '0'} sub={sensors.length > 0 ? `${sensors.filter(s => s.status === 'online').length} online` : 'None connected'} highlight={sensors.length === 0} onClick={() => onNavigate('sensors')} />
        <ThreatIntelStatusCard stats={threatStats} onClick={() => onNavigate('threats')} />
        <StatCard label="DNS Queries" value={threatStats?.total_count || '—'} sub={threatStats?.last_24h_count ? `${threatStats.last_24h_count} in 24h` : 'Monitoring'} onClick={() => onNavigate('threats')} />
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
          <h2 className="text-lg font-display text-gray-100">Welcome to Vedetta</h2>
          <p className="text-gray-400 mt-2 max-w-md mx-auto">Your network watchtower is ready. Run a scan to discover devices on your network.</p>
          <div className="mt-6">
            <button onClick={onScan} disabled={scanning} className="bg-amber-500 hover:bg-amber-400 disabled:bg-amber-800 disabled:text-amber-600 text-gray-950 px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 mx-auto">
              {scanning && <Spinner />}
              {scanning ? 'Scanning...' : 'Run Network Scan'}
            </button>
          </div>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-medium">Recent Devices</h2>
            <button onClick={onViewDevices} className="text-sm text-amber-400 hover:text-amber-300">View all →</button>
          </div>
          <DeviceTable devices={devices.slice(0, 5)} compact />
        </div>
      )}
    </>
  );
}

// --- Devices ---

function DevicesView({ devices, scanning, onScan, scanStatus, threatEvents, onRefreshThreats }) {
  const [segmentFilter, setSegmentFilter] = useState('all');
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [editName, setEditName] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [editSegment, setEditSegment] = useState('');
  const [editDeviceType, setEditDeviceType] = useState('');
  const [editOSFamily, setEditOSFamily] = useState('');
  const [editModel, setEditModel] = useState('');
  const [saving, setSaving] = useState(false);
  const [checkedEvents, setCheckedEvents] = useState(new Set());
  const [bulkAction, setBulkAction] = useState(null); // null | 'ack' | 'suppress'
  const [bulkReason, setBulkReason] = useState('');
  const [bulkProcessing, setBulkProcessing] = useState(false);
  const [bulkError, setBulkError] = useState(null);

  const segments = ['all', ...new Set(devices.map((d) => d.segment).filter(Boolean))];
  const filtered = segmentFilter === 'all' ? devices : devices.filter((d) => d.segment === segmentFilter);

  const exportCSV = () => {
    const headers = ['Status', 'IP Address', 'Hostname', 'Vendor', 'Model', 'Discovery Source', 'Services', 'Segment', 'MAC Address', 'Open Ports', 'First Seen', 'Last Seen'];
    const rows = filtered.map((d) => [
      d.is_online ? 'Online' : 'Offline',
      d.ip_address || '',
      d.hostname || '',
      d.vendor || '',
      d.model || '',
      d.discovery_source || '',
      (d.services && d.services.length ? d.services.join(';') : ''),
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
          <h2 className="text-2xl font-display">Device Inventory</h2>
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
          <button onClick={onScan} disabled={scanning} className="bg-amber-500 hover:bg-amber-400 disabled:bg-amber-800 disabled:text-amber-600 text-gray-950 px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
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
                segmentFilter === seg ? 'bg-amber-500 text-gray-950' : 'bg-gray-800 text-gray-400 hover:text-white'
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
          <DeviceTable devices={filtered} onSelectDevice={(d) => {
            setSelectedDevice(d);
            setEditName(d.custom_name || '');
            setEditNotes(d.notes || '');
            setEditSegment(d.segment || 'default');
            setEditDeviceType(d.device_type || '');
            setEditOSFamily(d.os_family || '');
            setEditModel(d.model || '');
            setCheckedEvents(new Set());
            setBulkAction(null);
            setBulkReason('');
            setBulkError(null);
          }} />
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <p className="text-gray-500">No devices found. Run a scan to discover your network.</p>
        </div>
      )}

      {/* Device Detail Panel */}
      {selectedDevice && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-xl max-w-2xl w-full p-6 max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-display">{selectedDevice.custom_name || selectedDevice.hostname || selectedDevice.ip_address}</h3>
              <button onClick={() => setSelectedDevice(null)} className="text-gray-500 hover:text-white text-lg">✕</button>
            </div>

            {/* Device info grid */}
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
              <div>
                <span className="text-xs text-gray-500 block">IP Address</span>
                <span className="text-sm font-mono">{selectedDevice.ip_address}</span>
              </div>
              <div>
                <span className="text-xs text-gray-500 block">MAC Address</span>
                <span className="text-sm font-mono">{selectedDevice.mac_address || '—'}</span>
              </div>
              <div>
                <span className="text-xs text-gray-500 block">Vendor</span>
                <span className="text-sm">{selectedDevice.vendor || '—'}</span>
              </div>
              <div>
                <span className="text-xs text-gray-500 block">Device Type</span>
                <span className="text-sm">{selectedDevice.device_type || '—'}</span>
              </div>
              <div>
                <span className="text-xs text-gray-500 block">OS</span>
                <span className="text-sm">{selectedDevice.os_family ? `${selectedDevice.os_family} ${selectedDevice.os_version || ''}`.trim() : '—'}</span>
              </div>
              <div>
                <span className="text-xs text-gray-500 block">Model</span>
                <span className="text-sm">{selectedDevice.model || '—'}</span>
              </div>
              <div>
                <span className="text-xs text-gray-500 block">Discovery Source</span>
                <span className="text-sm text-xs">{discoveryLabel(selectedDevice.discovery_source)}</span>
              </div>
              <div className="col-span-2">
                <span className="text-xs text-gray-500 block">Services (from passive sensor data)</span>
                {selectedDevice.services && selectedDevice.services.length > 0 ? (
                  <div className="flex flex-wrap gap-1 mt-0.5">
                    {selectedDevice.services.map((s, i) => (
                      <span key={i} className="inline-block text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700" title={s}>{s}</span>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-gray-500">—</span>
                )}
              </div>
              <div>
                <span className="text-xs text-gray-500 block">First Seen</span>
                <span className="text-sm">{timeAgo(selectedDevice.first_seen)}</span>
              </div>
              {selectedDevice.eol_risk && (
                <div className="col-span-2 md:col-span-3 mt-2 p-3 bg-red-500/10 border border-red-500/40 rounded-lg">
                  <div className="flex items-center gap-2 text-red-300 text-sm font-semibold">
                    ⚠ END-OF-LIFE / HIGH RISK DEVICE
                  </div>
                  <div className="text-xs text-red-200 mt-1">
                    Matches model(s) listed in FBI IC3 FLASH 2026-03-12 (AVrecon malware). These routers/cameras are no longer patched and are actively exploited as residential proxies and C2 infrastructure. Consider replacing.
                    {selectedDevice.eol_model && <span className="block mt-1 font-mono text-red-300">{selectedDevice.eol_model}</span>}
                  </div>
                </div>
              )}
              {selectedDevice.open_ports && selectedDevice.open_ports.length > 0 && (
                <div className="col-span-2">
                  <span className="text-xs text-gray-500 block">Open Ports</span>
                  <div className="flex gap-1 flex-wrap mt-1">
                    {selectedDevice.open_ports.map((p) => (
                      <span key={p} className="bg-gray-800 text-gray-300 text-xs px-1.5 py-0.5 rounded">{p}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Editable fields */}
            <div className="space-y-3 mb-6 border-t border-gray-800 pt-4">
              <h4 className="text-sm font-medium text-gray-300">Edit Device</h4>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Custom Name</label>
                <input type="text" value={editName} onChange={(e) => setEditName(e.target.value)}
                  placeholder="e.g., Living Room TV, Ring Doorbell"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Notes</label>
                <textarea value={editNotes} onChange={(e) => setEditNotes(e.target.value)}
                  placeholder="Any notes about this device..."
                  rows={2}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500 resize-none" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Segment</label>
                <select value={editSegment} onChange={(e) => setEditSegment(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500">
                  <option value="default">Default</option>
                  <option value="iot">IoT</option>
                  <option value="guest">Guest</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Device Type</label>
                <select value={editDeviceType} onChange={(e) => setEditDeviceType(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500">
                  <option value="">Auto-detect</option>
                  <option value="computer">Computer</option>
                  <option value="laptop">Laptop</option>
                  <option value="phone">Phone</option>
                  <option value="tablet">Tablet</option>
                  <option value="smart_tv">Smart TV</option>
                  <option value="streaming">Streaming Device</option>
                  <option value="speaker">Smart Speaker</option>
                  <option value="camera">Camera</option>
                  <option value="printer">Printer</option>
                  <option value="router">Router/Gateway</option>
                  <option value="access_point">Access Point</option>
                  <option value="nas">NAS</option>
                  <option value="game_console">Game Console</option>
                  <option value="iot_generic">IoT Device</option>
                  <option value="wearable">Wearable</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">OS / Platform</label>
                  <input type="text" value={editOSFamily} onChange={(e) => setEditOSFamily(e.target.value)}
                    placeholder="e.g., macOS, Windows, iOS, Linux"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500" />
                </div>
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Model</label>
                  <input type="text" value={editModel} onChange={(e) => setEditModel(e.target.value)}
                    placeholder="e.g., MacBook Pro, Ring Doorbell"
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500" />
                </div>
              </div>
              <button
                disabled={saving}
                onClick={() => {
                  setSaving(true);
                  fetch(`/api/v1/devices/${selectedDevice.device_id}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ custom_name: editName, notes: editNotes, segment: editSegment, device_type: editDeviceType, os_family: editOSFamily, model: editModel }),
                  }).then(() => {
                    setSaving(false);
                    setSelectedDevice(null);
                    // Trigger re-fetch from parent
                  }).catch(() => setSaving(false));
                }}
                className="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-700 text-gray-950 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>

            {/* Threat history for this device */}
            {threatEvents && threatEvents.length > 0 && (() => {
              const deviceThreats = threatEvents.filter(e => e.source_ip === selectedDevice.ip_address);
              if (deviceThreats.length === 0) return null;

              const allChecked = deviceThreats.length > 0 && deviceThreats.every(e => checkedEvents.has(e.event_id));
              const someChecked = checkedEvents.size > 0;

              const toggleAll = () => {
                if (allChecked) {
                  setCheckedEvents(new Set());
                } else {
                  setCheckedEvents(new Set(deviceThreats.map(e => e.event_id)));
                }
              };

              const toggleOne = (eventId) => {
                const next = new Set(checkedEvents);
                if (next.has(eventId)) next.delete(eventId); else next.add(eventId);
                setCheckedEvents(next);
              };

              const doBulkAction = async (action, reason) => {
                setBulkProcessing(true);
                setBulkError(null);
                const ids = [...checkedEvents];
                try {
                  if (action === 'ack') {
                    for (const id of ids) {
                      const r = await fetch(`/api/v1/events/${id}/ack`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ reason }),
                      });
                      if (!r.ok) throw new Error(`Failed to ack ${id}: ${r.status}`);
                    }
                  } else if (action === 'suppress') {
                    // Get unique domain+source_ip combos from checked events
                    const seen = new Set();
                    for (const id of ids) {
                      const evt = deviceThreats.find(e => e.event_id === id);
                      if (!evt) continue;
                      const key = `${evt.domain}||${evt.source_ip}`;
                      if (seen.has(key)) continue;
                      seen.add(key);
                      const r = await fetch('/api/v1/suppression', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ domain: evt.domain, source_ip: evt.source_ip, tags: [], reason }),
                      });
                      if (!r.ok) throw new Error(`Failed to suppress: ${r.status}`);
                    }
                  }
                  setCheckedEvents(new Set());
                  setBulkAction(null);
                  setBulkReason('');
                  if (onRefreshThreats) onRefreshThreats();
                } catch (err) {
                  setBulkError(err.message);
                } finally {
                  setBulkProcessing(false);
                }
              };

              return (
                <div className="border-t border-gray-800 pt-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-sm font-medium text-gray-300">Threat History ({deviceThreats.length} events)</h4>
                    {someChecked && !bulkAction && (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-500">{checkedEvents.size} selected</span>
                        <button
                          className="text-xs bg-blue-500/10 text-blue-300 border border-blue-500/20 px-2.5 py-1 rounded hover:bg-blue-500/20 transition-colors"
                          onClick={() => setBulkAction('ack')}
                        >
                          Ack Selected
                        </button>
                        <button
                          className="text-xs bg-gray-700/50 text-gray-300 border border-gray-600 px-2.5 py-1 rounded hover:bg-gray-700 transition-colors"
                          onClick={() => setBulkAction('suppress')}
                        >
                          Suppress Selected
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Bulk action reason input */}
                  {bulkAction && (
                    <div className="bg-gray-800/60 border border-gray-700 rounded-lg p-3 mb-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-400 shrink-0">
                          {bulkAction === 'ack' ? 'Ack' : 'Suppress'} {checkedEvents.size} events — reason:
                        </span>
                        <input
                          type="text"
                          value={bulkReason}
                          onChange={(e) => setBulkReason(e.target.value)}
                          placeholder="e.g., known Azure traffic, my VPN"
                          className="flex-1 bg-gray-800 border border-gray-700 rounded px-2.5 py-1 text-sm focus:outline-none focus:border-amber-500"
                          autoFocus
                          onKeyDown={(e) => { if (e.key === 'Enter') doBulkAction(bulkAction, bulkReason); if (e.key === 'Escape') { setBulkAction(null); setBulkReason(''); } }}
                        />
                        <button
                          disabled={bulkProcessing}
                          className="text-xs bg-amber-500/20 text-amber-300 px-3 py-1 rounded hover:bg-amber-500/30 disabled:opacity-50"
                          onClick={() => doBulkAction(bulkAction, bulkReason)}
                        >
                          {bulkProcessing ? 'Processing...' : 'Confirm'}
                        </button>
                        <button
                          className="text-xs text-gray-500 hover:text-gray-300"
                          onClick={() => { setBulkAction(null); setBulkReason(''); }}
                        >
                          Cancel
                        </button>
                      </div>
                      {bulkError && <p className="text-xs text-red-400 mt-2">{bulkError}</p>}
                    </div>
                  )}

                  {/* Select all checkbox */}
                  <div className="flex items-center gap-2 mb-2 px-1 cursor-pointer" onClick={toggleAll}>
                    <input
                      type="checkbox"
                      checked={allChecked}
                      onChange={toggleAll}
                      style={{ accentColor: '#f59e0b' }}
                      className="rounded border-gray-600 w-3.5 h-3.5"
                      onClick={(e) => e.stopPropagation()}
                    />
                    <span className="text-xs text-gray-500">Select all</span>
                  </div>

                  <div className="space-y-1.5 max-h-72 overflow-y-auto">
                    {deviceThreats.map((evt) => (
                      <div key={evt.event_id} className={`rounded p-3 text-sm flex items-start gap-3 cursor-pointer ${
                        checkedEvents.has(evt.event_id) ? 'bg-amber-500/5 border border-amber-500/20' : 'bg-gray-800/50'
                      } ${evt.acknowledged ? 'opacity-50' : ''}`} onClick={() => toggleOne(evt.event_id)}>
                        <input
                          type="checkbox"
                          checked={checkedEvents.has(evt.event_id)}
                          onChange={() => toggleOne(evt.event_id)}
                          style={{ accentColor: '#f59e0b' }}
                          className="rounded border-gray-600 mt-0.5 w-3.5 h-3.5 shrink-0"
                          onClick={(e) => e.stopPropagation()}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-gray-300 truncate flex-1">{evt.domain || '—'}</span>
                            <span className="text-xs text-gray-500 ml-2 shrink-0">{timeAgo(evt.timestamp)}</span>
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            {evt.tags && evt.tags.map((tag, idx) => (
                              <span key={idx} className="text-xs bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded">{tag}</span>
                            ))}
                            <span className={`text-xs ${evt.blocked ? 'text-red-400' : 'text-green-400'}`}>
                              {evt.blocked ? 'blocked' : 'allowed'}
                            </span>
                            {evt.acknowledged && (
                              <span className="text-xs text-blue-400">ack'd{evt.ack_reason ? `: ${evt.ack_reason}` : ''}</span>
                            )}
                          </div>
                          {evt.threat_desc && <p className="text-xs text-gray-500 mt-1 line-clamp-2">{evt.threat_desc}</p>}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })()}
          </div>
        </div>
      )}
    </>
  );
}

// --- Scan Targets ---

function ScanTargetsView({ targets, defaultCIDR, scanning, onRefresh, onScanTarget, sensorInterfaces }) {
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState('');
  const [cidr, setCidr] = useState('');
  const [segment, setSegment] = useState('iot');
  const [scanPorts, setScanPorts] = useState(false);
  const [dnsCapture, setDnsCapture] = useState(false);
  const [dnsInterface, setDnsInterface] = useState('');

  const addTarget = () => {
    if (!name || !cidr) return;
    fetch('/api/v1/scan/targets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, cidr, segment, scan_ports: scanPorts, dns_capture: dnsCapture, dns_interface: dnsInterface }),
    }).then(() => {
      setShowAdd(false);
      setName('');
      setCidr('');
      setDnsCapture(false);
      setDnsInterface('');
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
          <h2 className="text-2xl font-display">Scan Targets</h2>
          <p className="text-gray-400 text-sm mt-1">
            Manage which networks Vedetta scans. The primary subnet is auto-scanned on a schedule. Custom targets are included in every scan cycle.
          </p>
        </div>
        <button onClick={() => setShowAdd(true)} className="bg-amber-500 hover:bg-amber-400 text-gray-950 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          Add Network
        </button>
      </div>

      {/* Primary subnet card */}
      <div className="bg-gray-900 border border-amber-500/30 rounded-lg p-4 mb-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">Primary Network</span>
              <span className="text-xs bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded">auto-scan</span>
              <span className="text-xs bg-teal-500/20 text-teal-300 px-1.5 py-0.5 rounded">DNS capture</span>
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
                    {t.dns_capture && (
                      <span className="text-xs bg-teal-500/20 text-teal-300 px-1.5 py-0.5 rounded">
                        DNS: {t.dns_interface || 'auto'}
                      </span>
                    )}
                  </div>
                  <p className="font-mono text-sm text-gray-400 mt-1">{t.cidr}</p>
                  {t.last_scan && <p className="text-xs text-gray-500 mt-1">Last scan: {timeAgo(t.last_scan)}</p>}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => onScanTarget(t.target_id)}
                    disabled={scanning}
                    className="text-sm text-amber-400 hover:text-amber-300 disabled:text-gray-600"
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
            <h3 className="text-lg font-display mb-4">Add Scan Target</h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Name</label>
                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="IoT Network"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">CIDR</label>
                <input type="text" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="10.0.50.0/24"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-amber-500" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Segment</label>
                <select value={segment} onChange={(e) => setSegment(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500">
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
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={dnsCapture} onChange={(e) => setDnsCapture(e.target.checked)}
                  className="rounded border-gray-600" />
                Capture DNS traffic
              </label>
              {dnsCapture && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">DNS Interface</label>
                  <select value={dnsInterface} onChange={(e) => setDnsInterface(e.target.value)}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-amber-500">
                    <option value="">Auto-detect</option>
                    {sensorInterfaces.map(iface => (
                      <option key={iface.name} value={iface.name}>
                        {iface.name} ({iface.subnet || iface.ips?.[0] || 'no IP'})
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            {/* L2 limitation note */}
            <div className="bg-teal-500/10 border border-teal-500/20 rounded-lg p-3 mt-4">
              <div className="flex gap-2">
                <svg className="w-4 h-4 text-teal-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                  <p className="text-xs text-teal-300">
                    Network discovery works best with a sensor running on each network segment. Remote subnets scanned without a local sensor will have limited fingerprinting (no MAC address or vendor identification).
                  </p>
                  <a
                    href="https://github.com/vedetta-network/vedetta/wiki/Deploying-Sensors"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-amber-400 hover:text-amber-300 mt-1 inline-block"
                  >
                    Learn how to deploy a sensor →
                  </a>
                </div>
              </div>
            </div>

            <div className="flex gap-2 mt-4">
              <button onClick={addTarget} disabled={!name || !cidr}
                className="flex-1 bg-amber-500 hover:bg-amber-400 disabled:bg-gray-700 disabled:text-gray-500 text-gray-950 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                Add Target
              </button>
              <button onClick={() => { setShowAdd(false); setDnsCapture(false); setDnsInterface(''); }}
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
      sensor: 'bg-teal-500/20 text-teal-300',
      scan: 'bg-teal-500/20 text-teal-300',
      device: 'bg-amber-500/20 text-amber-300',
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
          <h2 className="text-2xl font-display">Activity Log</h2>
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
                filter === cat ? 'bg-amber-500 text-gray-950' : 'bg-gray-800 text-gray-400 hover:text-white'
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

// --- Whitelist Management View ---

function WhitelistManagementView({ whitelistRules, onRefresh }) {
  const [actionError, setActionError] = useState(null);

  const toggleRule = (ruleId, enabled) => {
    fetch(`/api/v1/whitelist/${ruleId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    }).then(r => {
      if (r.ok) onRefresh();
      else setActionError('Failed to update whitelist rule');
    }).catch(() => setActionError('Failed to update whitelist rule'));
  };

  const deleteRule = (ruleId) => {
    fetch(`/api/v1/whitelist/${ruleId}`, { method: 'DELETE' })
      .then(r => {
        if (r.ok) onRefresh();
        else r.text().then(t => setActionError(t || 'Cannot delete default rules'));
      }).catch(() => setActionError('Failed to delete whitelist rule'));
  };

  const categories = [...new Set((whitelistRules || []).map(r => r.category))].sort();
  const categoryLabels = {
    apple: 'Apple',
    mdns: 'mDNS / Bonjour',
    cloud: 'Cloud Services',
    os_updates: 'OS Updates',
    iot: 'IoT / Smart Home',
    custom: 'Custom'
  };

  return (
    <>
      <div className="mb-6">
        <h2 className="text-2xl font-display">Whitelist Rules</h2>
        <p className="text-gray-400 text-sm mt-1">Manage expected home network traffic to reduce alert noise</p>
      </div>

      {/* Error toast */}
      {actionError && (
        <div className="bg-red-950/30 border border-red-900/50 rounded-lg p-3 mb-4 flex items-center justify-between">
          <span className="text-sm text-red-300">{actionError}</span>
          <button onClick={() => setActionError(null)} className="text-red-400 hover:text-red-200 text-sm ml-3">Dismiss</button>
        </div>
      )}

      {categories.length > 0 ? (
        <div className="space-y-6">
          {categories.map(cat => (
            <div key={cat} className="bg-gray-900 border border-gray-800 rounded-lg p-5">
              <h3 className="text-sm font-medium text-gray-300 uppercase tracking-wider mb-4">{categoryLabels[cat] || cat}</h3>
              <div className="space-y-2">
                {whitelistRules.filter(r => r.category === cat).map(rule => (
                  <div key={rule.rule_id} className={`flex items-center justify-between bg-gray-800/50 rounded-lg px-4 py-3 ${
                    rule.enabled ? '' : 'opacity-50'
                  }`}>
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className={`relative w-8 h-4 rounded-full transition-colors cursor-pointer ${rule.enabled ? 'bg-teal-500' : 'bg-gray-700'}`}
                        onClick={() => toggleRule(rule.rule_id, !rule.enabled)}>
                        <div className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${rule.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                      </div>
                      <div className="min-w-0">
                        <span className="text-sm text-gray-200 block">{rule.name}</span>
                        <div className="text-xs text-gray-500 font-mono space-y-0.5">
                          {rule.domain_pattern && <div>Domain: {rule.domain_pattern}</div>}
                          {rule.source_ip_pattern && <div>IP: {rule.source_ip_pattern}</div>}
                          {rule.tag_match && <div>Tag: {rule.tag_match}</div>}
                        </div>
                      </div>
                    </div>
                    {!rule.is_default && (
                      <button onClick={() => deleteRule(rule.rule_id)}
                        className="text-gray-600 hover:text-red-400 text-xs ml-2 shrink-0">
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
            <AddWhitelistRule onAdd={() => onRefresh()} onError={setActionError} />
          </div>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 text-center">
          <p className="text-gray-500 text-sm mb-4">No whitelist rules loaded yet.</p>
          <button
            onClick={() => {
              fetch('/api/v1/whitelist/seed', { method: 'POST' })
                .then(r => { if (r.ok) onRefresh(); })
                .catch(() => {});
            }}
            className="bg-teal-500/20 text-teal-300 border border-teal-500/30 px-4 py-2 rounded-lg text-sm hover:bg-teal-500/30 transition-colors"
          >
            Load Default Rules
          </button>
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
        <h2 className="text-2xl font-display">Settings</h2>
        <p className="text-gray-400 text-sm mt-1">Configure Vedetta Core preferences</p>
      </div>

      <div className="space-y-4">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-medium mb-1">Data Retention</h3>
          <p className="text-xs text-gray-500 mb-3">How long to keep event and device history</p>
          <div className="flex items-center gap-3">
            <input type="number" defaultValue={90} className="w-20 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-center focus:outline-none focus:border-amber-500" />
            <span className="text-sm text-gray-400">days</span>
          </div>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-medium mb-1">Scan Schedule</h3>
          <p className="text-xs text-gray-500 mb-3">Default interval for automatic sensor scans</p>
          <div className="flex items-center gap-3">
            <select defaultValue="5m" className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:border-amber-500">
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

        {/* Real Admin Token Management (Phase 1 of auth hardening) */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-5">
          <h3 className="text-sm font-medium mb-1 flex items-center gap-2">
            Admin Access Tokens
            <span className="text-[10px] px-1.5 py-0.5 bg-emerald-900 text-emerald-400 rounded">LIVE</span>
          </h3>
          <p className="text-xs text-gray-500 mb-3">Manage human admin credentials for this Vedetta Core</p>

          <div className="flex flex-wrap gap-2 mb-3">
            <button
              onClick={async () => {
                try {
                  const res = await fetch('/api/v1/auth/tokens', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scope: 'admin', label: 'Admin (from Settings)' }),
                  });
                  const data = await res.json();
                  if (data.token) {
                    setAdminToken(data.token);
                    alert('New admin token created (shown only once):\n\n' + data.token);
                    window.location.reload();
                  } else {
                    alert(data.error || 'Failed to create token');
                  }
                } catch (e) {
                  alert('Error creating token: ' + e.message);
                }
              }}
              className="text-xs px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 rounded-lg transition-colors"
            >
              Create New Admin Token
            </button>
            <button
              onClick={() => { setShowTokenPrompt(true); setTokenInput(''); }}
              className="text-xs px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors"
            >
              Paste / Recover Token
            </button>
            <button
              onClick={() => { clearAdminToken(); window.location.reload(); }}
              className="text-xs px-3 py-1.5 bg-gray-800 hover:bg-red-900/60 text-red-400 rounded-lg transition-colors"
            >
              Forget Token (this browser)
            </button>
          </div>

          <div className="text-[10px] text-gray-500">
            Tokens are stored only in this browser. Create as many admin tokens as you need.
            The raw token value is shown only once when created.
          </div>
        </div>

        <p className="text-xs text-gray-600 text-center pt-2">
          Some settings are still placeholders in v0.1.0-dev.
        </p>
      </div>
    </>
  );
}

// --- Shared Components ---

// Friendly labels for sensor-provided discovery_source (makes host identification actionable in UI)
function discoveryLabel(src) {
  if (!src) return '—';
  const map = {
    'passive_mdns': 'mDNS (passive)',
    'passive_dhcp': 'DHCP (passive)',
    'passive_ssdp': 'SSDP (passive)',
    'passive_arp': 'ARP (passive)',
    'nmap_active': 'Active (nmap)',
    'active_nmap': 'Active (nmap)', // legacy alias: old sensor binaries still emit this
  };
  return map[src] || src;
}

function DeviceTable({ devices, compact = false, onSelectDevice }) {
  return (
    <table className="w-full">
      <thead>
        <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-800">
          <th className="px-4 py-3">Status</th>
          <th className="px-4 py-3">Name / IP</th>
          <th className="px-4 py-3">Hostname</th>
          <th className="px-4 py-3">Vendor</th>
          <th className="px-4 py-3">Model</th>
          <th className="px-4 py-3 w-28">Discovery Source</th>
          <th className="px-4 py-3">Services</th>
          <th className="px-4 py-3">Segment</th>
          {!compact && <th className="px-4 py-3">MAC</th>}
          {!compact && <th className="px-4 py-3">Ports</th>}
          <th className="px-4 py-3">First Seen</th>
          <th className="px-4 py-3">Last Seen</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((device) => (
          <tr
            key={device.device_id}
            className={`border-b border-gray-800/50 hover:bg-gray-800/30 transition-colors ${onSelectDevice ? 'cursor-pointer' : ''}`}
            onClick={() => onSelectDevice && onSelectDevice(device)}
          >
            <td className="px-4 py-3">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-green-400 rounded-full" />
                {isNewDevice(device.first_seen) && (
                  <span className="bg-amber-500 text-black text-xs font-bold px-1.5 py-0.5 rounded">NEW</span>
                )}
                {device.eol_risk && (
                  <span className="bg-red-500 text-white text-xs font-bold px-1.5 py-0.5 rounded flex items-center gap-1" title={device.eol_model || 'EOL / vulnerable model per IC3 advisory'}>
                    ⚠ EOL
                  </span>
                )}
                {device.risk_category === 'high_risk_iot' && (
                  <span className="bg-orange-500 text-white text-xs font-bold px-1.5 py-0.5 rounded flex items-center gap-1" title={device.risk_model || 'High-risk IoT / camera (common botnet target)'}>
                    ⚠ High Risk
                  </span>
                )}
                {device.risk_category === 'known_exploited' && (
                  <span className="bg-red-600 text-white text-xs font-bold px-1.5 py-0.5 rounded flex items-center gap-1" title={device.risk_model || 'Known exploited device or chipset'}>
                    ⚠ Exploited
                  </span>
                )}
              </div>
            </td>
            <td className="px-4 py-3">
              <div>
                {device.custom_name ? (
                  <>
                    <span className="text-sm font-medium text-amber-300">{device.custom_name}</span>
                    <span className="font-mono text-xs text-gray-500 ml-2">{device.ip_address}</span>
                  </>
                ) : (
                  <span className="font-mono text-sm">{device.ip_address}</span>
                )}
              </div>
            </td>
            <td className="px-4 py-3 text-sm">{device.hostname || <span className="text-gray-600">—</span>}</td>
            <td className="px-4 py-3 text-sm text-gray-400">{device.vendor || '—'}</td>
            <td className="px-4 py-3 text-sm text-gray-200">{device.model || '—'}</td>
            <td className="px-4 py-3 text-xs text-gray-400">{discoveryLabel(device.discovery_source)}</td>
            <td className="px-4 py-3 text-xs text-gray-400" title={device.services && device.services.length > 0 ? device.services.join(', ') : ''}>
              {device.services && device.services.length > 0 ? (
                device.services.length > 2 ? `${device.services.slice(0,2).join(', ')} +${device.services.length-2}` : device.services.join(', ')
              ) : '—'}
            </td>
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

function StatCard({ label, value, sub, highlight = false, onClick }) {
  return (
    <div
      className={`bg-gray-900 border rounded-lg p-4 ${highlight ? 'border-amber-500/40' : 'border-gray-800'} ${onClick ? 'cursor-pointer hover:bg-gray-800/50 transition-colors' : ''}`}
      onClick={onClick}
    >
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
