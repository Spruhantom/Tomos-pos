"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, api } from "@/lib/api";

type User = { id: string; email: string; display_name: string };
type Tenant = { tenant_id: string; membership_id: string; display_name: string; slug: string };
type Business = { id: string; legal_name: string; trading_name: string | null; company_number: string | null; vat_number: string | null; country_code: string; currency_code: string; timezone: string };
type Location = { id: string; name: string; location_code: string | null; address: Record<string, unknown>; is_active: boolean };
type Member = { membership_id: string; email: string; display_name: string; status: string; roles: string[] };
type Invitation = { id: string; email: string; expires_at: string; status: string };
type Role = { id: string; key: string; display_name: string; is_system: boolean; permissions: string[] };
type Permission = { key: string; description: string };
type Section = "overview" | "business" | "staff" | "roles";

function errorText(reason: unknown) {
  if (reason instanceof ApiError && reason.status === 401) return "Your session has expired. Sign in again.";
  return reason instanceof Error ? reason.message : "Something went wrong. Please try again.";
}

function Input({ label, value, onChange, required = false, type = "text" }: { label: string; value: string; onChange: (value: string) => void; required?: boolean; type?: string }) {
  return <label className="field"><span>{label}</span><input type={type} value={value} onChange={(event) => onChange(event.target.value)} required={required} /></label>;
}

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [businessId, setBusinessId] = useState("");
  const [locations, setLocations] = useState<Location[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<Permission[]>([]);
  const [section, setSection] = useState<Section>("overview");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [token, setToken] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [businessForm, setBusinessForm] = useState({ legal_name: "", trading_name: "", company_number: "", vat_number: "", country_code: "GB", currency_code: "GBP", timezone: "Europe/London" });
  const [newBusinessName, setNewBusinessName] = useState("");
  const [locationName, setLocationName] = useState("");
  const [locationCode, setLocationCode] = useState("");
  const [locationAddress, setLocationAddress] = useState("{}");
  const [inviteEmail, setInviteEmail] = useState("");
  const [roleKey, setRoleKey] = useState("");
  const [roleName, setRoleName] = useState("");
  const [rolePermissions, setRolePermissions] = useState<string[]>([]);

  const selectedBusiness = useMemo(() => businesses.find((business) => business.id === businessId) ?? null, [businesses, businessId]);

  useEffect(() => {
    if (selectedBusiness) setBusinessForm({
      legal_name: selectedBusiness.legal_name,
      trading_name: selectedBusiness.trading_name ?? "",
      company_number: selectedBusiness.company_number ?? "",
      vat_number: selectedBusiness.vat_number ?? "",
      country_code: selectedBusiness.country_code,
      currency_code: selectedBusiness.currency_code,
      timezone: selectedBusiness.timezone,
    });
  }, [selectedBusiness]);

  const loadSession = useCallback(async () => {
    try {
      const current = await api<User>("auth/me");
      setUser(current);
      const result = await api<{ tenants: Tenant[] }>("auth/tenants");
      setTenants(result.tenants);
      setTenantId((old) => result.tenants.some((item) => item.tenant_id === old) ? old : (result.tenants[0]?.tenant_id ?? ""));
    } catch (reason) {
      setUser(null);
      setTenants([]);
      setTenantId("");
      if (!(reason instanceof ApiError && reason.status === 401)) setError(errorText(reason));
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadSession(); }, [loadSession]);

  const loadBusinesses = useCallback(async () => {
    if (!tenantId) return;
    setBusy(true); setError("");
    try {
      await api("tenant/context", { tenantId });
      const result = await api<{ businesses: Business[] }>("businesses", { tenantId });
      setBusinesses(result.businesses);
      setBusinessId((old) => result.businesses.some((item) => item.id === old) ? old : (result.businesses[0]?.id ?? ""));
    } catch (reason) { setError(errorText(reason)); setBusinesses([]); setBusinessId(""); }
    finally { setBusy(false); }
  }, [tenantId]);

  useEffect(() => { if (user && tenantId) void loadBusinesses(); }, [user, tenantId, loadBusinesses]);

  const loadLocations = useCallback(async () => {
    if (!tenantId || !businessId) { setLocations([]); return; }
    try {
      const result = await api<{ locations: Location[] }>("businesses/" + businessId + "/locations", { tenantId });
      setLocations(result.locations);
    } catch (reason) { setError(errorText(reason)); }
  }, [tenantId, businessId]);

  useEffect(() => { void loadLocations(); }, [loadLocations]);

  const loadStaff = useCallback(async () => {
    if (!tenantId) return;
    const results = await Promise.allSettled([
      api<{ members: Member[] }>("staff/memberships", { tenantId }),
      api<{ invitations: Invitation[] }>("staff/invitations", { tenantId }),
      api<{ roles: Role[] }>("staff/roles", { tenantId }),
      api<{ permissions: Permission[] }>("staff/permissions", { tenantId }),
    ]);
    if (results[0].status === "fulfilled") setMembers(results[0].value.members);
    if (results[1].status === "fulfilled") setInvitations(results[1].value.invitations);
    if (results[2].status === "fulfilled") setRoles(results[2].value.roles);
    if (results[3].status === "fulfilled") setPermissions(results[3].value.permissions);
    const failed = results.find((item) => item.status === "rejected");
    if (failed?.status === "rejected") setError(errorText(failed.reason));
  }, [tenantId]);

  useEffect(() => { if (section === "staff" || section === "roles") void loadStaff(); }, [section, loadStaff]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    try { await api("auth/login", { method: "POST", body: { email, password } }); setPassword(""); await loadSession(); }
    catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  async function logout() {
    setBusy(true);
    try { await api("auth/logout", { method: "POST" }); } catch { /* Clear local state if the session already expired. */ }
    setUser(null); setTenants([]); setTenantId(""); setBusinesses([]); setBusinessId(""); setBusy(false);
  }

  async function saveBusiness(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!selectedBusiness) return; setBusy(true); setError("");
    try {
      await api("businesses/" + selectedBusiness.id, { method: "PUT", tenantId, body: {
        legal_name: businessForm.legal_name || selectedBusiness.legal_name,
        trading_name: businessForm.trading_name || null,
        company_number: businessForm.company_number || null,
        vat_number: businessForm.vat_number || null,
        country_code: businessForm.country_code,
        currency_code: businessForm.currency_code,
        timezone: businessForm.timezone,
      }});
      await loadBusinesses(); setNotice("Business settings saved.");
    } catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  async function createBusiness(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      await api("businesses/create", { method: "POST", tenantId, body: { legal_name: newBusinessName, trading_name: null, company_number: null, vat_number: null, country_code: "GB", currency_code: "GBP", timezone: "Europe/London" } });
      setNewBusinessName(""); await loadBusinesses(); setNotice("Business created.");
    } catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  async function createLocation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!businessId) return; setBusy(true); setError("");
    try {
      const address = JSON.parse(locationAddress) as Record<string, unknown>;
      await api("businesses/" + businessId + "/locations/create", { method: "POST", tenantId, body: { name: locationName, location_code: locationCode || null, address } });
      setLocationName(""); setLocationCode(""); setLocationAddress("{}"); await loadLocations(); setNotice("Location created.");
    } catch (reason) { setError(reason instanceof SyntaxError ? "Address must be valid JSON." : errorText(reason)); }
    finally { setBusy(false); }
  }

  async function changeLocation(location: Location) {
    setBusy(true); setError("");
    try {
      await api("business-locations/" + location.id, { method: "PUT", tenantId, body: { name: location.name, location_code: location.location_code, address: location.address, is_active: !location.is_active } });
      await loadLocations(); setNotice(location.is_active ? "Location deactivated." : "Location reactivated.");
    } catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); setToken("");
    try {
      const result = await api<{ token: string }>("staff/invitations", { method: "POST", tenantId, body: { email: inviteEmail } });
      setToken(result.token); setInviteEmail(""); await loadStaff(); setNotice("Invitation created. Deliver its token securely; email delivery is not configured.");
    } catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  async function revokeInvitation(id: string) {
    setBusy(true);
    try { await api("staff/invitations/" + id, { method: "DELETE", tenantId }); await loadStaff(); setNotice("Invitation revoked."); }
    catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  async function removeMember(id: string) {
    if (!window.confirm("Remove this person's membership from the selected tenant?")) return;
    setBusy(true);
    try { await api("staff/memberships/" + id, { method: "DELETE", tenantId }); await loadStaff(); setNotice("Membership removed."); }
    catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  async function createRole(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true);
    try {
      await api("staff/roles", { method: "POST", tenantId, body: { role_key: roleKey, display_name: roleName, permission_keys: rolePermissions } });
      setRoleKey(""); setRoleName(""); setRolePermissions([]); await loadStaff(); setNotice("Custom role created.");
    } catch (reason) { setError(errorText(reason)); }
    finally { setBusy(false); }
  }

  if (loading) return <main className="center"><div className="spinner" /><p>Loading TomOS POS…</p></main>;

  if (!user) return <main className="login-wrap"><section className="login-card">
    <div className="mark">T</div><p className="eyebrow">BUSINESS MANAGEMENT</p><h1>Welcome to TomOS POS</h1>
    <p className="muted">Sign in to manage your business, locations and team.</p>
    {error && <p className="alert error">{error}</p>}
    <form onSubmit={login} className="stack">
      <Input label="Email address" value={email} onChange={setEmail} required type="email" />
      <Input label="Password" value={password} onChange={setPassword} required type="password" />
      <button className="primary full" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
    <p className="fine">Accounts are created by a workspace administrator.</p>
  </section></main>;

  const nav: { id: Section; label: string }[] = [
    { id: "overview", label: "Overview" }, { id: "business", label: "Business & locations" },
    { id: "staff", label: "Staff" }, { id: "roles", label: "Roles & permissions" },
  ];

  return <main className="shell">
    <aside className="sidebar">
      <div className="brand"><span className="mark small">T</span><span><b>TomOS</b><small>POINT OF SALE</small></span></div>
      <p className="side-label">WORKSPACE</p>
      {nav.map((item) => <button key={item.id} className={"nav-item " + (section === item.id ? "active" : "")} onClick={() => { setSection(item.id); setError(""); setNotice(""); }}><i />{item.label}</button>)}
      <div className="side-foot">● &nbsp; Self-hosted workspace</div>
    </aside>
    <section className="main">
      <header className="topbar">
        <div><p className="eyebrow">TOMOS POS / MANAGEMENT</p><h2>{nav.find((item) => item.id === section)?.label}</h2></div>
        <div className="actions">
          <select aria-label="Select workspace" value={tenantId} onChange={(event) => setTenantId(event.target.value)}>{tenants.map((tenant) => <option key={tenant.tenant_id} value={tenant.tenant_id}>{tenant.display_name}</option>)}</select>
          <span className="user-chip">{user.display_name}</span><a className="quiet" href="/pos">Open checkout</a><button className="quiet" onClick={logout} disabled={busy}>Sign out</button>
        </div>
      </header>
      {error && <p className="alert error">{error}</p>}{notice && <p className="alert success">{notice}</p>}
      {!tenants.length ? <section className="panel"><h3>No active workspace</h3><p className="muted">Your account has no active tenant membership. Ask an administrator for an invitation.</p></section> : <>
        {section === "overview" && <div className="stack">
          <section className="welcome"><p className="eyebrow">YOUR WORKSPACE</p><h1>Good to see you, {user.display_name.split(" ")[0]}.</h1><p>Manage business details, locations and team access from one place.</p></section>
          <div className="stats">
            <article className="stat"><span>Businesses</span><b>{businesses.length}</b><small>In this workspace</small></article>
            <article className="stat"><span>Locations</span><b>{locations.length}</b><small>For the selected business</small></article>
            <article className="stat"><span>Team members</span><b>{members.length || "—"}</b><small>Staff list loads when opened</small></article>
          </div>
          <section className="panel"><p className="eyebrow">SELECTED BUSINESS</p><h3>{selectedBusiness?.trading_name || selectedBusiness?.legal_name || "No business selected"}</h3><p className="muted">{selectedBusiness ? selectedBusiness.country_code + " · " + selectedBusiness.currency_code + " · " + selectedBusiness.timezone : "Create a business to get started."}</p><button className="secondary" onClick={() => setSection("business")}>Manage business</button></section>
        </div>}

        {section === "business" && <div className="columns">
          <section className="panel">
            <p className="eyebrow">BUSINESS PROFILE</p><h3>Legal and trading details</h3>
            <label className="field"><span>Select business</span><select value={businessId} onChange={(event) => { setBusinessId(event.target.value); setBusinessForm({ legal_name: "", trading_name: "", company_number: "", vat_number: "", country_code: "GB", currency_code: "GBP", timezone: "Europe/London" }); }}><option value="">Choose a business</option>{businesses.map((item) => <option key={item.id} value={item.id}>{item.trading_name || item.legal_name}</option>)}</select></label>
            {selectedBusiness && <form className="stack form-space" onSubmit={saveBusiness}>
              <Input label="Legal business name" value={businessForm.legal_name || selectedBusiness.legal_name} onChange={(v) => setBusinessForm((s) => ({ ...s, legal_name: v }))} required />
              <Input label="Trading name" value={businessForm.trading_name || selectedBusiness.trading_name || ""} onChange={(v) => setBusinessForm((s) => ({ ...s, trading_name: v }))} />
              <Input label="Company number" value={businessForm.company_number || selectedBusiness.company_number || ""} onChange={(v) => setBusinessForm((s) => ({ ...s, company_number: v }))} />
              <Input label="VAT number" value={businessForm.vat_number || selectedBusiness.vat_number || ""} onChange={(v) => setBusinessForm((s) => ({ ...s, vat_number: v }))} />
              <Input label="Country code" value={businessForm.country_code} onChange={(v) => setBusinessForm((s) => ({ ...s, country_code: v.toUpperCase() }))} required />
              <Input label="Currency code" value={businessForm.currency_code} onChange={(v) => setBusinessForm((s) => ({ ...s, currency_code: v.toUpperCase() }))} required />
              <Input label="Timezone" value={businessForm.timezone} onChange={(v) => setBusinessForm((s) => ({ ...s, timezone: v }))} required />
              <button className="primary" disabled={busy}>Save business settings</button>
            </form>}
            <form className="stack divider" onSubmit={createBusiness}><h4>Add another business</h4><Input label="Legal business name" value={newBusinessName} onChange={setNewBusinessName} required /><button className="secondary" disabled={busy}>Create business (GB / GBP)</button></form>
          </section>
          <section className="panel">
            <p className="eyebrow">LOCATIONS</p><h3>Business locations</h3>
            {locations.map((location) => <div className="list-row" key={location.id}><div><b>{location.name}</b><small>{location.location_code || "No code"} · {location.is_active ? "Active" : "Inactive"}</small></div><button className="quiet" disabled={busy} onClick={() => void changeLocation(location)}>{location.is_active ? "Deactivate" : "Reactivate"}</button></div>)}
            {!locations.length && <p className="muted">No locations found for this business.</p>}
            <form className="stack divider" onSubmit={createLocation}><h4>Add a location</h4><Input label="Location name" value={locationName} onChange={setLocationName} required /><Input label="Location code (optional)" value={locationCode} onChange={setLocationCode} /><label className="field"><span>Address JSON</span><textarea rows={4} value={locationAddress} onChange={(event) => setLocationAddress(event.target.value)} /></label><button className="secondary" disabled={busy || !businessId}>Add location</button></form>
          </section>
        </div>}

        {section === "staff" && <div className="columns">
          <section className="panel"><p className="eyebrow">TEAM ACCESS</p><h3>Staff members</h3>
            {members.map((member) => <div className="list-row" key={member.membership_id}><div><b>{member.display_name}</b><small>{member.email} · {member.roles.join(", ") || "No role"} · {member.status}</small></div><button className="quiet danger" disabled={busy || member.status !== "active"} onClick={() => void removeMember(member.membership_id)}>Remove</button></div>)}
            {!members.length && <p className="muted">No staff list available, or this account lacks staff.read permission.</p>}
          </section>
          <section className="panel"><p className="eyebrow">INVITATIONS</p><h3>Invite a team member</h3>
            <form className="stack" onSubmit={invite}><Input label="Email address" type="email" value={inviteEmail} onChange={setInviteEmail} required /><button className="primary" disabled={busy}>Create invitation</button></form>
            {token && <div className="token"><b>Invitation token — shown once</b><code>{token}</code><p>Send this token to the invited person over a secure channel. Email delivery is not configured.</p><button className="quiet" onClick={() => void navigator.clipboard?.writeText(token)}>Copy token</button></div>}
            <div className="divider"><h4>Recent invitations</h4>{invitations.map((item) => <div className="list-row" key={item.id}><div><b>{item.email}</b><small>{item.status} · expires {new Date(item.expires_at).toLocaleDateString("en-GB")}</small></div>{item.status === "pending" && <button className="quiet danger" onClick={() => void revokeInvitation(item.id)} disabled={busy}>Revoke</button>}</div>)}</div>
          </section>
        </div>}

        {section === "roles" && <div className="columns">
          <section className="panel"><p className="eyebrow">ACCESS CONTROL</p><h3>Existing roles</h3>
            {roles.map((role) => <article className="role" key={role.id}><div><b>{role.display_name}</b><span className="tag">{role.is_system ? "Built-in" : "Custom"}</span></div><small>{role.key}</small><p>{role.permissions.join(" · ") || "No permissions"}</p></article>)}
            {!roles.length && <p className="muted">Roles unavailable or roles.manage permission required.</p>}
          </section>
          <section className="panel"><p className="eyebrow">CUSTOM ROLE</p><h3>Create a role</h3>
            <form className="stack" onSubmit={createRole}><Input label="Role key (lowercase)" value={roleKey} onChange={(v) => setRoleKey(v.toLowerCase().replaceAll(" ", "-"))} required /><Input label="Display name" value={roleName} onChange={setRoleName} required />
              <div className="permissions"><b>Permissions</b>{permissions.map((permission) => <label className="check" key={permission.key}><input type="checkbox" checked={rolePermissions.includes(permission.key)} onChange={(event) => setRolePermissions((old) => event.target.checked ? [...old, permission.key] : old.filter((key) => key !== permission.key))} /><span><b>{permission.key}</b><small>{permission.description}</small></span></label>)}</div>
              <button className="primary" disabled={busy}>Create custom role</button>
            </form>
          </section>
        </div>}
      </>}
      <footer className="footer">TomOS POS · Early development · Not for live payment processing or tax submissions.</footer>
    </section>
  </main>;
}
