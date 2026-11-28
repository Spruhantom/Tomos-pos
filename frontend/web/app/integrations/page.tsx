"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";

type Tenant = { tenant_id: string; display_name: string };
type Business = { id: string; legal_name: string; trading_name: string | null };
type SumUpStatus = { status: string; merchant_code: string | null; merchants: { merchant_code: string; name: string }[] };
type Appointment = { id: string; summary: string; description: string | null; location: string | null; start_at: string; end_at: string; status: string; source: string };

function messageOf(error: unknown) {
  return error instanceof ApiError ? error.message : "The request could not be completed. Check your connection and try again.";
}
function localDate(value: string) {
  return new Date(value).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
}

export default function IntegrationsPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [businessId, setBusinessId] = useState("");
  const [sumup, setSumup] = useState<SumUpStatus>({ status: "not_connected", merchant_code: null, merchants: [] });
  const [calendarStatus, setCalendarStatus] = useState("not_connected");
  const [readers, setReaders] = useState<unknown[]>([]);
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [summary, setSummary] = useState("");
  const [startAt, setStartAt] = useState("");
  const [endAt, setEndAt] = useState("");
  const [location, setLocation] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;
    Promise.all([api<{ tenants: Tenant[] }>("auth/tenants"), api("auth/me")])
      .then(([result]) => {
        if (!active) return;
        setTenants(result.tenants);
        if (result.tenants[0]) setTenantId(result.tenants[0].tenant_id);
      })
      .catch((reason) => { if (active) setError(messageOf(reason)); })
      .finally(() => { if (active) setLoading(false); });
    const params = new URLSearchParams(window.location.search);
    if (params.get("sumup")) setNotice("SumUp connection result: " + params.get("sumup") + ".");
    if (params.get("calendar")) setNotice("Google Calendar connection result: " + params.get("calendar") + ".");
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    setBusinesses([]); setBusinessId("");
    if (!tenantId) return;
    api<{ businesses: Business[] }>("businesses", { tenantId })
      .then((result) => {
        if (!active) return;
        setBusinesses(result.businesses);
        if (result.businesses[0]) setBusinessId(result.businesses[0].id);
      })
      .catch((reason) => { if (active) setError(messageOf(reason)); });
    return () => { active = false; };
  }, [tenantId]);

  async function loadIntegrationState() {
    if (!tenantId || !businessId) return;
    const [sumupState, calendarState, events] = await Promise.all([
      api<SumUpStatus>(`sumup/status?business_id=${businessId}`, { tenantId }),
      api<{ status: string }>(`calendar/status?business_id=${businessId}`, { tenantId }),
      api<Appointment[]>(`calendar/appointments?business_id=${businessId}`, { tenantId }),
    ]);
    setSumup(sumupState);
    setCalendarStatus(calendarState.status);
    setAppointments(events);
  }

  useEffect(() => {
    let active = true;
    if (!tenantId || !businessId) return;
    Promise.all([
      api<SumUpStatus>(`sumup/status?business_id=${businessId}`, { tenantId }),
      api<{ status: string }>(`calendar/status?business_id=${businessId}`, { tenantId }),
      api<Appointment[]>(`calendar/appointments?business_id=${businessId}`, { tenantId }),
    ]).then(([sumupState, calendarState, events]) => {
      if (!active) return;
      setSumup(sumupState); setCalendarStatus(calendarState.status); setAppointments(events);
    }).catch((reason) => { if (active) setError(messageOf(reason)); });
    return () => { active = false; };
  }, [tenantId, businessId]);

  async function connect(path: "sumup/connect" | "calendar/connect") {
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await api<{ action_url: string }>(path, { method: "POST", tenantId, body: { business_id: businessId } });
      window.location.assign(result.action_url);
    } catch (reason) { setError(messageOf(reason)); setBusy(false); }
  }

  async function chooseMerchant(merchantCode: string) {
    setBusy(true); setError("");
    try {
      await api("sumup/select-merchant", { method: "POST", tenantId, body: { business_id: businessId, merchant_code: merchantCode } });
      await loadIntegrationState();
      setNotice("SumUp merchant account connected.");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function loadReaders() {
    setBusy(true); setError("");
    try {
      const result = await api<{ items?: unknown[] } | unknown[]>(`sumup/readers?business_id=${businessId}`, { tenantId });
      setReaders(Array.isArray(result) ? result : result.items ?? []);
      setNotice("SumUp reader list refreshed.");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function syncCalendar() {
    setBusy(true); setError(""); setNotice("");
    try {
      const now = new Date();
      const later = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
      const result = await api<{ synced: number }>("calendar/sync", {
        method: "POST", tenantId,
        body: { business_id: businessId, time_min: now.toISOString(), time_max: later.toISOString() },
      });
      await loadIntegrationState();
      setNotice(`Calendar synchronised. ${result.synced} Google Calendar events were imported or updated.`);
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function createAppointment(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!summary.trim() || !startAt || !endAt) { setError("Enter an appointment title, start and end time."); return; }
    setBusy(true); setError(""); setNotice("");
    try {
      await api("calendar/appointments/create", {
        method: "POST", tenantId,
        body: {
          business_id: businessId,
          summary: summary.trim(),
          location: location.trim() || null,
          start_at: new Date(startAt).toISOString(),
          end_at: new Date(endAt).toISOString(),
        },
      });
      setSummary(""); setLocation(""); setStartAt(""); setEndAt("");
      await loadIntegrationState();
      setNotice("Appointment added to TomOS and Google Calendar. If SumUp Bookings is synchronised with this Google calendar, it can receive the change there.");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  if (loading) return <main className="pos-loading">Loading integrations…</main>;
  return (
    <main className="pos-shell">
      <header className="pos-header">
        <div><a href="/" className="pos-back">← Management</a><h1>Business integrations</h1><p>Connect payments and synchronise appointments.</p></div>
        <div className="pos-selectors">
          <label>Workspace<select value={tenantId} onChange={(event) => setTenantId(event.target.value)}>{tenants.map((tenant) => <option key={tenant.tenant_id} value={tenant.tenant_id}>{tenant.display_name}</option>)}</select></label>
          <label>Business<select value={businessId} onChange={(event) => setBusinessId(event.target.value)}>{businesses.map((business) => <option key={business.id} value={business.id}>{business.trading_name || business.legal_name}</option>)}</select></label>
        </div>
      </header>
      {error && <p className="pos-alert error">{error}</p>}
      {notice && <p className="pos-alert success">{notice}</p>}
      <div className="pos-workspace">
        <section className="pos-products">
          <section className="pos-panel">
            <p className="pos-eyebrow">CARD PAYMENTS</p>
            <h2>SumUp</h2>
            <p>Connect each business to its own SumUp merchant account. Pair Solo readers in SumUp, then select a reader when taking a sale.</p>
            <p><strong>Connection:</strong> {sumup.status}{sumup.merchant_code ? ` · ${sumup.merchant_code}` : ""}</p>
            {sumup.status !== "connected" && <button disabled={busy || !businessId} onClick={() => void connect("sumup/connect")}>Connect SumUp business</button>}
            {sumup.merchants.length > 1 && <label>Choose merchant account<select defaultValue="" onChange={(event) => event.target.value && void chooseMerchant(event.target.value)}><option value="" disabled>Select an authorised SumUp merchant</option>{sumup.merchants.map((merchant) => <option key={merchant.merchant_code} value={merchant.merchant_code}>{merchant.name} · {merchant.merchant_code}</option>)}</select></label>}
            {sumup.status === "connected" && <button className="pos-secondary-button" disabled={busy} onClick={() => void loadReaders()}>Load paired readers</button>}
            {!!readers.length && <pre className="pos-payment-note">{JSON.stringify(readers, null, 2)}</pre>}
            <small>Live reader payments require a SumUp OAuth application, approval for the payments scope, and an affiliate key for Cloud API card-present processing.</small>
          </section>
          <section className="pos-panel">
            <p className="pos-eyebrow">APPOINTMENT SYNCHRONISATION</p>
            <h2>SumUp Bookings ↔ Google Calendar ↔ TomOS</h2>
            <p>First enable SumUp Bookings calendar sync with the same Google Calendar in SumUp. TomOS then imports the calendar events and sends TomOS-created or edited appointments back to Google Calendar.</p>
            <p><strong>Google Calendar:</strong> {calendarStatus}</p>
            {calendarStatus !== "connected" && <button disabled={busy || !businessId} onClick={() => void connect("calendar/connect")}>Connect Google Calendar</button>}
            {calendarStatus === "connected" && <button className="pos-secondary-button" disabled={busy} onClick={() => void syncCalendar()}>Synchronise appointments</button>}
            <p><small>Sync imports events from the next 365 days. TomOS appointment edits update Google Calendar; SumUp Bookings receives them through its own calendar sync.</small></p>
            {calendarStatus === "connected" && <form className="pos-till-tools" onSubmit={(event) => void createAppointment(event)}>
              <h3>New appointment</h3>
              <label>Title<input value={summary} onChange={(event) => setSummary(event.target.value)} required /></label>
              <label>Location<input value={location} onChange={(event) => setLocation(event.target.value)} /></label>
              <label>Starts<input type="datetime-local" value={startAt} onChange={(event) => setStartAt(event.target.value)} required /></label>
              <label>Ends<input type="datetime-local" value={endAt} onChange={(event) => setEndAt(event.target.value)} required /></label>
              <button disabled={busy}>Create appointment</button>
            </form>}
            <h3>Upcoming appointments</h3>
            {appointments.length ? appointments.slice(0, 25).map((item) => <article className="pos-cart-line" key={item.id}><div><b>{item.summary}</b><small>{localDate(item.start_at)} – {localDate(item.end_at)}</small><small>{item.source === "google" ? "Imported calendar event" : "TomOS appointment"} · {item.status}</small></div></article>) : <p className="pos-empty">No appointments have been synchronised yet.</p>}
          </section>
        </section>
        <aside className="pos-cart">
          <p className="pos-eyebrow">TOMOS MODULES</p>
          <h2>Other business tools</h2>
          <p>Manage the POS and loyalty system from their own workspaces.</p>
          <a className="pos-secondary-button" href="/pos">Open checkout</a>
          <a className="pos-secondary-button" href="/loyalty">Open loyalty</a>
          <a className="pos-secondary-button" href="/calendar">Open calendar</a>
        </aside>
      </div>
    </main>
  );
}
