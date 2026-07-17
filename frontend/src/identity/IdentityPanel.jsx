import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { confirmDeviceIdentity, listActiveDeviceMerges, mergeDevices, splitDeviceMerge } from './api';

const LOW_CONFIDENCE = 0.75;
// Above this many candidates the panel would dominate the Devices page, so it starts
// collapsed (the operator expands it deliberately). See the redeploy/MAC-sprawl UX notes.
const COLLAPSE_THRESHOLD = 8;
const CONFIRMABLE_EVIDENCE = new Set([
  'dhcp_client_id', 'dhcp_option_55', 'ssdp_uuid', 'ssdp_device_type',
  'mdns_name', 'mdns_service', 'hostname', 'mac',
]);

function deviceName(device) {
  return device.display_name || device.custom_name || device.friendly_name || device.hostname ||
    (device.device_id ? `Device ${device.device_id.slice(0, 8)}` : 'Unidentified device');
}

function identityConfidence(device) {
  const value = device.identity_confidence ?? device.identity?.confidence;
  return value == null || value === '' ? null : Number(value);
}

function needsIdentification(device) {
  const confidence = identityConfidence(device);
  const status = String(device.identity_status || device.identity?.status || '').toLowerCase();
  return device.needs_identification === true || device.identity_conflict === true ||
    (Number.isFinite(confidence) && confidence < LOW_CONFIDENCE) ||
    ['unresolved', 'low_confidence', 'conflict', 'ambiguous'].includes(status);
}

function evidenceChoices(device) {
  const choices = [];
  const seen = new Set();
  const add = (type, value, label, sensitive = false) => {
    type = String(type || '').toLowerCase();
    if (!CONFIRMABLE_EVIDENCE.has(type)) return;
    const clean = String(value || '').trim();
    const key = `${type}\u0000${clean}`;
    if (!clean || seen.has(key)) return;
    seen.add(key);
    choices.push({ type, value: clean, display_value: clean, label, sensitive });
  };
  (Array.isArray(device.signals) ? device.signals : []).forEach((signal) =>
    add(signal.field || signal.type, signal.value, `${signal.field || signal.type}: ${signal.value}`, ['mac', 'dhcp_client_id', 'ssdp_uuid'].includes(signal.field || signal.type))
  );
  add('mac', device.mac_address, `MAC: ${device.mac_address}`, true);
  add('hostname', device.hostname, `Hostname: ${device.hostname}`);
  add('mdns_name', device.friendly_name, `mDNS name: ${device.friendly_name}`);
  return choices;
}

function responseAction(response) {
  return response?.action || response;
}

function undoableActions(serverMerges, recentMerges) {
  const seen = new Set();
  return [...serverMerges, ...recentMerges].filter((action) => {
    if (!action?.action_id || action.undone_by_action_id || seen.has(action.action_id)) return false;
    seen.add(action.action_id);
    return true;
  });
}

export function IdentityPanel({ devices = [], findings = [], events = [], canAdmin, onChanged, onNavigateDevice }) {
  const candidates = useMemo(() => {
    const latestIdentity = new Map();
    events.forEach((event) => {
      if (!event.device_id || event.identity_confidence == null) return;
      const observedAt = new Date(event.timestamp || event.created_at || 0).getTime();
      const current = latestIdentity.get(event.device_id);
      if (!current || observedAt >= current.observedAt) {
        latestIdentity.set(event.device_id, {
          observedAt,
          confidence: Number(event.identity_confidence),
          reason: String(event.identity_reason || ''),
        });
      }
    });
    return devices
      .map((device) => {
        const observation = latestIdentity.get(device.device_id);
        if (!observation) return device;
        return {
          ...device,
          identity_confidence: device.identity_confidence ?? observation.confidence,
          identity_status: device.identity_status || (/conflict|ambiguous|unresolved/i.test(observation.reason) ? 'conflict' : ''),
        };
      })
      .filter(needsIdentification);
  }, [devices, events]);
  const unresolvedCount = findings.filter((finding) => !finding.device_id && !finding.canonical_device_id).length;
  const [selectedID, setSelectedID] = useState('');
  const [evidenceIndex, setEvidenceIndex] = useState('0');
  const [confirmReason, setConfirmReason] = useState('');
  const [mergeSourceID, setMergeSourceID] = useState('');
  const [mergeTargetID, setMergeTargetID] = useState('');
  const [mergeReason, setMergeReason] = useState('');
  const [serverMerges, setServerMerges] = useState([]);
  const [recentMerges, setRecentMerges] = useState([]);
  const [mergesLoading, setMergesLoading] = useState(true);
  const [mergesError, setMergesError] = useState('');
  const [splitReasons, setSplitReasons] = useState({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [collapsed, setCollapsed] = useState(false);
  const collapseDecided = useRef(false);

  // Start collapsed the first time the queue is large enough to dominate the page. Only auto-
  // decide once, so a manual expand/collapse afterwards sticks.
  useEffect(() => {
    if (!collapseDecided.current && candidates.length > COLLAPSE_THRESHOLD) {
      setCollapsed(true);
      collapseDecided.current = true;
    }
  }, [candidates.length]);

  useEffect(() => {
    if (!selectedID || !candidates.some((device) => device.device_id === selectedID)) {
      setSelectedID(candidates[0]?.device_id || '');
    }
  }, [candidates, selectedID]);

  const selected = candidates.find((device) => device.device_id === selectedID);
  const evidence = selected ? evidenceChoices(selected) : [];
  const mergeSource = devices.find((device) => device.device_id === mergeSourceID);
  const targets = useMemo(() => {
    if (!mergeSource) return [];
    const seen = new Set();
    return devices.filter((device) => {
      const canonicalID = device.canonical_device_id || device.device_id;
      if (!canonicalID || canonicalID === mergeSource.device_id || seen.has(canonicalID)) return false;
      if (device.merged_into_device_id) return false;
      seen.add(canonicalID);
      return true;
    });
  }, [devices, mergeSource]);
  const merges = useMemo(() => undoableActions(serverMerges, recentMerges), [serverMerges, recentMerges]);

  const refreshMerges = useCallback(async () => {
    setMergesLoading(true);
    setMergesError('');
    try {
      const response = await listActiveDeviceMerges();
      setServerMerges(Array.isArray(response?.actions) ? response.actions : []);
    } catch (cause) {
      setMergesError(cause?.message || 'Unable to load active merge audit.');
    } finally {
      setMergesLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshMerges();
  }, [refreshMerges]);

  useEffect(() => {
    if (!mergeSourceID || !devices.some((device) => device.device_id === mergeSourceID)) {
      setMergeSourceID(devices[0]?.device_id || '');
    }
  }, [devices, mergeSourceID]);

  useEffect(() => {
    setEvidenceIndex('0');
    setError('');
  }, [selectedID]);

  useEffect(() => {
    setMergeTargetID(targets[0]?.canonical_device_id || targets[0]?.device_id || '');
    setError('');
  }, [mergeSourceID, targets]);

  const confirm = async (event) => {
    event.preventDefault();
    const chosen = evidence[Number(evidenceIndex)];
    if (!selected || !chosen) {
      setError('Select identity evidence to confirm.');
      return;
    }
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const response = await confirmDeviceIdentity(selected.device_id, {
        evidence: chosen,
        segment: selected.segment || '',
        sensorID: selected.sensor_id || '',
        reason: confirmReason,
      });
      const action = responseAction(response);
      setMessage(`Identity confirmed${action?.action_id ? ` · audit ${action.action_id}` : ''}.`);
      setConfirmReason('');
      await onChanged?.(action);
    } catch (cause) {
      setError(cause?.message || 'Unable to confirm identity.');
    } finally {
      setSaving(false);
    }
  };

  const merge = async (event) => {
    event.preventDefault();
    if (!mergeSource || !mergeTargetID || !mergeReason.trim()) {
      setError('Choose the canonical device and provide a merge reason.');
      return;
    }
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const response = await mergeDevices(mergeSource.device_id, mergeTargetID, mergeReason);
      const action = responseAction(response);
      const canonicalID = action?.canonical_target_device_id || action?.target_device_id || mergeTargetID;
      if (action?.action_id) setRecentMerges((current) => [action, ...current]);
      setMessage(`Devices merged${action?.action_id ? ` · audit ${action.action_id}` : ''}.`);
      setMergeReason('');
      await onChanged?.(action);
      await refreshMerges();
      onNavigateDevice?.(canonicalID);
    } catch (cause) {
      setError(cause?.message || 'Unable to merge devices.');
    } finally {
      setSaving(false);
    }
  };

  const split = async (action) => {
    const reason = splitReasons[action.action_id] || '';
    if (!reason.trim()) {
      setError('Provide a reason before undoing a merge.');
      return;
    }
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const response = await splitDeviceMerge(action.action_id, reason);
      const splitAction = responseAction(response);
      setRecentMerges((current) => current.filter((entry) => entry.action_id !== action.action_id));
      setServerMerges((current) => current.filter((entry) => entry.action_id !== action.action_id));
      setMessage(`Merge undone${splitAction?.action_id ? ` · audit ${splitAction.action_id}` : ''}.`);
      setSplitReasons((current) => ({ ...current, [action.action_id]: '' }));
      await onChanged?.(splitAction);
      await refreshMerges();
    } catch (cause) {
      setError(cause?.message || 'Unable to undo merge.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="bg-gray-900 border border-gray-800 rounded-lg p-4 mb-5" aria-label="Needs Identification">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="font-medium text-gray-100">Needs Identification</h3>
          <p className="text-xs text-gray-500 mt-1">Confirm ambiguous evidence or reversibly merge duplicate asset records.</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-xs px-2 py-1 rounded ${candidates.length + unresolvedCount > 0 ? 'bg-amber-500/15 text-amber-300' : 'bg-emerald-500/10 text-emerald-300'}`}>
            {candidates.length} device{candidates.length === 1 ? '' : 's'} · {unresolvedCount} unresolved finding{unresolvedCount === 1 ? '' : 's'}
          </span>
          <button
            type="button"
            onClick={() => { setCollapsed((value) => !value); collapseDecided.current = true; }}
            aria-expanded={!collapsed}
            className="text-xs border border-gray-700 hover:border-gray-500 text-gray-300 px-2 py-1 rounded"
          >
            {collapsed ? 'Expand' : 'Collapse'}
          </button>
        </div>
      </div>

      {!collapsed && (<>
      {unresolvedCount > 0 && (
        <p className="mt-3 text-xs text-amber-200/80 bg-amber-500/10 border border-amber-500/20 rounded p-2">
          {unresolvedCount} finding{unresolvedCount === 1 ? '' : 's'} cannot yet be attached to a stable device. More identity evidence is required before an operator action is safe.
        </p>
      )}

      {candidates.length === 0 ? (
        <p className="text-sm text-gray-500 mt-3">No device currently reports an unresolved, conflicting, or low-confidence identity.</p>
      ) : (
        <div className="mt-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="space-y-2">
            {candidates.map((device) => {
              const confidence = identityConfidence(device);
              return (
                <button key={device.device_id} type="button" onClick={() => setSelectedID(device.device_id)} className={`w-full text-left border rounded-lg p-3 ${selectedID === device.device_id ? 'border-amber-500/50 bg-amber-500/5' : 'border-gray-800 bg-gray-950/40'}`}>
                  <p className="text-sm text-gray-200">{deviceName(device)}</p>
                  <p className="text-[11px] text-gray-500 font-mono mt-1">{device.device_id}</p>
                  <p className="text-xs text-amber-300 mt-1">{device.identity_conflict ? 'Conflicting evidence' : confidence == null ? 'Identity review requested' : `${Math.round(confidence * 100)}% identity confidence`}</p>
                </button>
              );
            })}
          </div>

          <div className="lg:col-span-2">
            {canAdmin === false ? (
              <p className="text-sm text-gray-400 bg-gray-950/50 rounded-lg p-4">Admin access is required to confirm device identities.</p>
            ) : selected && (
              <form onSubmit={confirm} className="space-y-3" aria-label="Confirm device identity">
                <label className="text-xs text-gray-400 block">Evidence binding
                  <select value={evidenceIndex} onChange={(event) => setEvidenceIndex(event.target.value)} className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm">
                    {evidence.map((choice, index) => <option key={`${choice.type}-${choice.value}`} value={index}>{choice.label}</option>)}
                  </select>
                </label>
                {evidence.length === 0 && <p className="text-xs text-amber-300">This device has no confirmable identity evidence yet.</p>}
                <label className="text-xs text-gray-400 block">Confirmation reason <span className="text-gray-600">(optional)</span>
                  <input value={confirmReason} onChange={(event) => setConfirmReason(event.target.value)} className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm" placeholder="Why this evidence belongs to this asset" />
                </label>
                <button type="submit" disabled={saving || evidence.length === 0} className="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-700 text-gray-950 px-3 py-2 rounded text-sm font-medium">Confirm identity</button>
              </form>
            )}
          </div>
        </div>
      )}

      <div className="mt-4 pt-4 border-t border-gray-800">
        <p className="text-sm font-medium text-gray-200">Merge duplicate device records</p>
        <p className="text-xs text-gray-500 mt-1">Available for any device pair. The source becomes a reversible redirect; the target remains canonical.</p>
        {canAdmin === true ? (
          devices.length >= 2 ? (
            <form onSubmit={merge} className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3" aria-label="Merge duplicate device">
              <label className="text-xs text-gray-400">Duplicate source device
                <select value={mergeSourceID} onChange={(event) => setMergeSourceID(event.target.value)} className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm">
                  {devices.map((device) => <option key={device.device_id} value={device.device_id}>{deviceName(device)}</option>)}
                </select>
              </label>
              <label className="text-xs text-gray-400">Canonical target device
                <select value={mergeTargetID} onChange={(event) => setMergeTargetID(event.target.value)} className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm">
                  {targets.map((target) => <option key={target.device_id} value={target.canonical_device_id || target.device_id}>{deviceName(target)}</option>)}
                </select>
              </label>
              <label className="text-xs text-gray-400 md:col-span-2">Merge reason
                <input value={mergeReason} onChange={(event) => setMergeReason(event.target.value)} className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm" placeholder="Why these records represent the same asset" />
              </label>
              <div className="md:col-span-2">
                <button type="submit" disabled={saving || targets.length === 0} className="bg-amber-500 hover:bg-amber-400 disabled:bg-gray-700 text-gray-950 px-3 py-2 rounded text-sm font-medium">Merge as same asset</button>
              </div>
            </form>
          ) : <p className="text-xs text-gray-600 mt-3">At least two devices are required to merge records.</p>
        ) : (
          <p className="text-sm text-gray-400 bg-gray-950/50 rounded-lg p-3 mt-3">Admin access is required to merge device records.</p>
        )}
      </div>

      {(mergesLoading || mergesError || merges.length > 0) && (
        <div className="mt-4 pt-4 border-t border-gray-800 space-y-3">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-wide text-gray-500">Active reversible merges</p>
            <button type="button" onClick={refreshMerges} disabled={mergesLoading} className="text-xs text-sky-400 hover:text-sky-300 disabled:text-gray-600">{mergesLoading ? 'Refreshing…' : 'Refresh'}</button>
          </div>
          {mergesError && <p className="text-xs text-red-400">{mergesError}</p>}
          {merges.map((action) => (
            <div key={action.action_id} className="grid grid-cols-1 md:grid-cols-[1fr_2fr_auto] gap-2 items-end bg-gray-950/40 rounded p-3">
              <div className="text-xs text-gray-400">
                <p>{action.source_display_name || action.source_device_id} → {action.target_display_name || action.canonical_target_device_id || action.target_device_id}</p>
                <p className="font-mono text-gray-600 mt-1">{action.source_device_id} → {action.canonical_target_device_id || action.target_device_id}</p>
                <p className="text-gray-600 mt-1">audit {action.action_id}</p>
              </div>
              {canAdmin === true ? (
                <label className="text-xs text-gray-400">Undo reason
                  <input value={splitReasons[action.action_id] || ''} onChange={(event) => setSplitReasons((current) => ({ ...current, [action.action_id]: event.target.value }))} className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm" placeholder="Why this merge was incorrect" />
                </label>
              ) : <span className="text-xs text-gray-600">{action.reason || 'Audited merge'}</span>}
              <div className="flex items-center gap-2">
                <button type="button" onClick={() => onNavigateDevice?.(action.canonical_target_device_id || action.target_device_id)} className="text-xs text-sky-400 hover:text-sky-300">View target</button>
                {canAdmin === true && <button type="button" disabled={saving} onClick={() => split(action)} className="text-sm border border-gray-700 hover:border-amber-500 text-gray-300 px-3 py-2 rounded">Undo merge</button>}
              </div>
            </div>
          ))}
        </div>
      )}
      </>)}

      {error && <p role="alert" className="text-xs text-red-400 mt-3">{error}</p>}
      {message && <p role="status" className="text-xs text-emerald-300 mt-3">{message}</p>}
    </section>
  );
}
