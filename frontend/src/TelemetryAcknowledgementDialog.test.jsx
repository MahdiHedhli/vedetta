import React, { useState } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { TelemetryAcknowledgementDialog, TelemetryInertBackground } from './TelemetryAcknowledgementDialog';
import {
  persistTelemetryNoticeAcknowledgement,
  readTelemetryDisclosureSetting,
  TELEMETRY_NOTICE_STORAGE_KEY,
  TELEMETRY_NOTICE_VERSION,
  TELEMETRY_STATUS_UNAVAILABLE_MESSAGE,
  telemetryNoticeAcknowledged,
  telemetrySettingsAccessAction,
} from './telemetryDisclosure';
import { useAdminPromptFocus, useTelemetryDisclosureFlow } from './useTelemetryDisclosureFlow';

const readyOn = { phase: 'ready', setting: { effective: true, source: 'env' } };

function renderDialog(overrides = {}) {
  const props = {
    ...readyOn,
    onAcknowledge: vi.fn(),
    onManageSettings: vi.fn(),
    onRetry: vi.fn(),
    ...overrides,
  };
  return { ...render(<TelemetryAcknowledgementDialog {...props} />), props };
}

describe('TelemetryAcknowledgementDialog', () => {
  it('makes background application content inert and hidden from assistive technology', () => {
    const view = render(<TelemetryInertBackground active><button>Background action</button></TelemetryInertBackground>);
    const background = screen.getByText('Background action').parentElement;
    expect(background).toHaveAttribute('inert');
    expect(background).toHaveAttribute('aria-hidden', 'true');

    view.rerender(<TelemetryInertBackground active={false}><button>Background action</button></TelemetryInertBackground>);
    expect(background).not.toHaveAttribute('inert');
    expect(background).not.toHaveAttribute('aria-hidden');
  });

  it('states the exact enabled privacy boundary and local-impact behavior', async () => {
    renderDialog();

    expect(screen.getByRole('heading', { name: 'Core telemetry gate is currently enabled' })).toBeInTheDocument();
    expect(screen.getByText(/separate telemetry-service process is running/i)).toBeInTheDocument();
    expect(screen.getByText(/matched public block-list domain/i)).toBeInTheDocument();
    expect(screen.getByText(/observation\/distinct-asset\/blocked counts/i)).toBeInTheDocument();
    expect(screen.getByText(/random signal and batch IDs/i)).toBeInTheDocument();
    expect(screen.getByText(/No internal\/device IP/i)).toBeInTheDocument();
    expect(screen.getByText(/does not retain that install UUID/i)).toBeInTheDocument();
    expect(screen.getByText(/Signal rows and batch receipts expire after 30 days/i)).toBeInTheDocument();
    expect(screen.getByText(/community service also holds that address/i)).toBeInTheDocument();
    expect(screen.getByText(/not written to SQLite or application logs/i)).toBeInTheDocument();
    expect(screen.getByText(/Local monitoring and public threat-feed downloads continue normally/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Read our Privacy Notice' })).toHaveAttribute('rel', 'noreferrer');
    await waitFor(() => expect(screen.getByRole('button', { name: 'ACKNOWLEDGED' })).toHaveFocus());
  });

  it('renders honest loading, disabled, and unavailable states', () => {
    const view = renderDialog({ phase: 'loading', setting: null });
    expect(screen.getByRole('heading', { name: 'Checking telemetry status' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'CHECKING…' })).toBeDisabled();

    view.rerender(<TelemetryAcknowledgementDialog {...view.props} phase="ready" setting={{ effective: false }} />);
    expect(screen.getByRole('heading', { name: 'Core telemetry gate is currently disabled' })).toBeInTheDocument();
    expect(screen.getByText(/No community contributions are sent/i)).toBeInTheDocument();
    expect(screen.getByText(/When telemetry is enabled, each beta signal/i)).toBeInTheDocument();
    expect(screen.getByText(/Signal rows and batch receipts expire after 30 days/i)).toBeInTheDocument();

    view.rerender(<TelemetryAcknowledgementDialog {...view.props} phase="error" setting={null} />);
    expect(screen.getByRole('heading', { name: 'Telemetry status could not be verified' })).toBeInTheDocument();
    expect(screen.getByText(/do not infer that contribution is either enabled or disabled/i)).toBeInTheDocument();
    expect(screen.getByText(/When telemetry is enabled, each beta signal/i)).toBeInTheDocument();
    expect(screen.getByText(/not written to SQLite or application logs/i)).toBeInTheDocument();
    expect(screen.getByText('VEDETTA_TELEMETRY_OPTIN=false')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry status check' })).toBeInTheDocument();
  });

  it('keeps both Tab directions inside the dialog while status is loading', async () => {
    renderDialog({ phase: 'loading', setting: null });
    const dialog = screen.getByRole('dialog');
    const privacyLink = screen.getByRole('link', { name: 'Read our Privacy Notice' });

    await waitFor(() => expect(dialog).toHaveFocus());
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(privacyLink).toHaveFocus();

    dialog.focus();
    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(privacyLink).toHaveFocus();
  });

  it('traps Tab in both directions and does not dismiss on Escape or backdrop click', async () => {
    const { props } = renderDialog();
    const first = screen.getByRole('button', { name: 'Manage in Settings' });
    const last = screen.getByRole('button', { name: 'ACKNOWLEDGED' });
    const dialog = screen.getByRole('dialog');

    expect(dialog).toHaveClass('overflow-y-auto');
    expect(dialog.firstElementChild).toHaveClass('max-h-[90dvh]', 'overflow-y-auto');

    await waitFor(() => expect(last).toHaveFocus());
    fireEvent.keyDown(last, { key: 'Tab' });
    expect(first).toHaveFocus();
    fireEvent.keyDown(first, { key: 'Tab', shiftKey: true });
    expect(last).toHaveFocus();

    fireEvent.keyDown(dialog, { key: 'Escape' });
    fireEvent.click(dialog);
    fireEvent.click(screen.getByRole('link', { name: 'Read our Privacy Notice' }));
    expect(props.onAcknowledge).not.toHaveBeenCalled();
  });

  it('locks body scrolling and restores prior focus after acknowledgement', async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Open notice</button>
          {open && (
            <TelemetryAcknowledgementDialog
              {...readyOn}
              onAcknowledge={() => setOpen(false)}
              onManageSettings={() => setOpen(false)}
              onRetry={vi.fn()}
            />
          )}
        </>
      );
    }

    const user = userEvent.setup();
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: 'Open notice' });
    await user.click(trigger);
    expect(document.body.style.overflow).toBe('hidden');
    await user.click(screen.getByRole('button', { name: 'ACKNOWLEDGED' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(document.body.style.overflow).toBe('');
  });

  it('retains normal focus restoration when a Settings handoff is deferred', async () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Open deferred notice</button>
          {open && (
            <TelemetryAcknowledgementDialog
              {...readyOn}
              onAcknowledge={() => setOpen(false)}
              onManageSettings={() => false}
              onRetry={vi.fn()}
            />
          )}
        </>
      );
    }

    const user = userEvent.setup();
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: 'Open deferred notice' });
    await user.click(trigger);
    await user.click(screen.getByRole('button', { name: 'Manage in Settings' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'ACKNOWLEDGED' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('preserves an explicit focus handoff when opening Settings', async () => {
    function Harness() {
      const [open, setOpen] = useState(true);
      const destination = React.useRef(null);
      return (
        <>
          <button ref={destination}>Telemetry setting destination</button>
          {open && (
            <TelemetryAcknowledgementDialog
              {...readyOn}
              onAcknowledge={() => setOpen(false)}
              onManageSettings={() => {
                setOpen(false);
                destination.current?.focus();
              }}
              onRetry={vi.fn()}
            />
          )}
        </>
      );
    }

    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Manage in Settings' }));
    expect(screen.getByRole('button', { name: 'Telemetry setting destination' })).toHaveFocus();
  });
});

describe('telemetry disclosure state helpers', () => {
  it('versions acknowledgement so an old banner dismissal is re-prompted', () => {
    const values = new Map([[TELEMETRY_NOTICE_STORAGE_KEY, '1']]);
    const storage = {
      getItem: vi.fn((key) => values.get(key) || null),
      setItem: vi.fn((key, value) => values.set(key, value)),
    };

    expect(telemetryNoticeAcknowledged(storage)).toBe(false);
    expect(persistTelemetryNoticeAcknowledgement(storage)).toBe(true);
    expect(values.get(TELEMETRY_NOTICE_STORAGE_KEY)).toBe(TELEMETRY_NOTICE_VERSION);
    expect(telemetryNoticeAcknowledged(storage)).toBe(true);
  });

  it('fails safe when origin-local storage is unavailable', () => {
    const storage = {
      getItem: vi.fn(() => { throw new Error('blocked'); }),
      setItem: vi.fn(() => { throw new Error('blocked'); }),
    };
    expect(telemetryNoticeAcknowledged(storage)).toBe(false);
    expect(persistTelemetryNoticeAcknowledgement(storage)).toBe(false);
  });

  it('validates the authoritative Core telemetry response', async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue({ effective: false, source: 'persisted' }),
    });
    await expect(readTelemetryDisclosureSetting(fetchImpl)).resolves.toMatchObject({ effective: false });
    expect(fetchImpl).toHaveBeenCalledWith('/api/v1/settings/telemetry', { signal: undefined });

    fetchImpl.mockResolvedValueOnce({ ok: true, status: 200, json: vi.fn().mockResolvedValue({}) });
    await expect(readTelemetryDisclosureSetting(fetchImpl)).rejects.toThrow(/effective setting/);
    fetchImpl.mockResolvedValueOnce({ ok: false, status: 401 });
    await expect(readTelemetryDisclosureSetting(fetchImpl)).rejects.toMatchObject({ status: 401 });
  });

  it('keeps a Settings fetch failure unknown instead of substituting the product default', () => {
    expect(TELEMETRY_STATUS_UNAVAILABLE_MESSAGE).toMatch(/unknown/i);
    expect(TELEMETRY_STATUS_UNAVAILABLE_MESSAGE).toMatch(/do not infer enabled or disabled/i);
    expect(TELEMETRY_STATUS_UNAVAILABLE_MESSAGE).not.toMatch(/default.*on/i);
  });

  it('waits for authoritative scope before completing Settings navigation', () => {
    expect(telemetrySettingsAccessAction({ canAdmin: true, tokenPresent: true, session: { authenticated: true, can_admin: true }, phase: 'healthy' })).toBe('navigate');
    expect(telemetrySettingsAccessAction({ canAdmin: true, tokenPresent: false, session: { authenticated: true, can_admin: true }, phase: 'healthy' })).toBe('prompt');
    expect(telemetrySettingsAccessAction({ canAdmin: true, tokenPresent: true, session: { authenticated: true, can_admin: false }, phase: 'healthy' })).toBe('prompt');
    expect(telemetrySettingsAccessAction({ canAdmin: false, tokenPresent: true, session: null, phase: 'loading' })).toBe('wait');
    expect(telemetrySettingsAccessAction({ canAdmin: false, tokenPresent: false, session: null, phase: 'loading' })).toBe('prompt');
    expect(telemetrySettingsAccessAction({ canAdmin: false, tokenPresent: true, session: { can_admin: false }, phase: 'healthy' })).toBe('prompt');
  });

  it('does not persist Manage until Settings succeeds and restores the notice after auth failure', async () => {
    const values = new Map();
    const storage = {
      getItem: vi.fn((key) => values.get(key) || null),
      setItem: vi.fn((key, value) => values.set(key, value)),
    };

    function Harness() {
      const flow = useTelemetryDisclosureFlow(storage);
      return (
        <>
          <output>{flow.showTelemetryNotice ? 'notice-visible' : 'notice-hidden'}</output>
          <output>{flow.settingsHandoffPending ? 'settings-pending' : 'settings-idle'}</output>
          <button onClick={flow.beginTelemetrySettingsHandoff}>Manage</button>
          <button onClick={flow.cancelTelemetrySettingsHandoff}>Authentication failed</button>
          <button onClick={flow.completeTelemetrySettingsHandoff}>Settings reached</button>
        </>
      );
    }

    const user = userEvent.setup();
    render(<Harness />);
    expect(screen.getByText('notice-visible')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Manage' }));
    expect(screen.getByText('notice-hidden')).toBeInTheDocument();
    expect(screen.getByText('settings-pending')).toBeInTheDocument();
    expect(storage.setItem).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Authentication failed' }));
    expect(screen.getByText('notice-visible')).toBeInTheDocument();
    expect(screen.getByText('settings-idle')).toBeInTheDocument();
    expect(storage.setItem).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Manage' }));
    await user.click(screen.getByRole('button', { name: 'Settings reached' }));
    expect(screen.getByText('notice-hidden')).toBeInTheDocument();
    expect(storage.setItem).toHaveBeenCalledWith(
      TELEMETRY_NOTICE_STORAGE_KEY,
      TELEMETRY_NOTICE_VERSION,
    );
  });

  it('focuses an admin prompt that was already mounted behind the blocking notice', async () => {
    function FocusHarness({ noticeVisible }) {
      const setupRef = React.useRef(null);
      const tokenRef = React.useRef(null);
      const fallbackRef = React.useRef(null);
      useAdminPromptFocus({
        promptVisible: true,
        blockingNoticeVisible: noticeVisible,
        preferSetupCode: false,
        setupCodeRef: setupRef,
        tokenInputRef: tokenRef,
        fallbackRef,
      });
      return (
        <>
          <button ref={fallbackRef}>Prompt close</button>
          <input ref={setupRef} aria-label="Setup code" />
          <input ref={tokenRef} aria-label="Admin token" />
        </>
      );
    }

    const view = render(<FocusHarness noticeVisible />);
    const fallback = screen.getByRole('button', { name: 'Prompt close' });
    const token = screen.getByRole('textbox', { name: 'Admin token' });
    fallback.focus();
    expect(token).not.toHaveFocus();

    view.rerender(<FocusHarness noticeVisible={false} />);
    await waitFor(() => expect(token).toHaveFocus());
  });
});
