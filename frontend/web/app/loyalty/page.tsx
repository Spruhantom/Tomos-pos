"use client";

import { useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";

type Tenant = { tenant_id: string; display_name: string };
type Business = { id: string; legal_name: string; trading_name: string | null };
type Customer = { id: string; display_name: string; email: string | null; phone: string | null; balance_points: number; lifetime_earned: number; lifetime_redeemed: number };
type Program = { enabled: boolean; points_per_major_unit: number; redemption_points_per_major_unit: number };

function messageOf(error: unknown) {
  return error instanceof ApiError ? error.message : "The request could not be completed. Check your connection and try again.";
}

export default function LoyaltyPage() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [businessId, setBusinessId] = useState("");
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [program, setProgram] = useState<Program>({ enabled: false, points_per_major_unit: 1, redemption_points_per_major_unit: 100 });
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [selectedCustomer, setSelectedCustomer] = useState("");
  const [redeemPoints, setRedeemPoints] = useState("100");
  const [reward, setReward] = useState<{ reward_code: string; reward_value_minor: number; points_redeemed: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function reload() {
    if (!tenantId || !businessId) return;
    const [customerRows, settings] = await Promise.all([
      api<Customer[]>(`loyalty/customers?business_id=${businessId}`, { tenantId }),
      api<Program>(`loyalty/programs?business_id=${businessId}`, { tenantId }),
    ]);
    setCustomers(customerRows);
    setProgram(settings);
    if (!selectedCustomer && customerRows[0]) setSelectedCustomer(customerRows[0].id);
  }

  useEffect(() => {
    let active = true;
    api<{ tenants: Tenant[] }>("auth/tenants")
      .then((result) => {
        if (!active) return;
        setTenants(result.tenants);
        if (result.tenants[0]) setTenantId(result.tenants[0].tenant_id);
      })
      .catch((reason) => { if (active) setError(messageOf(reason)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    setBusinesses([]); setBusinessId(""); setCustomers([]);
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

  useEffect(() => {
    let active = true;
    if (!tenantId || !businessId) return;
    Promise.all([
      api<Customer[]>(`loyalty/customers?business_id=${businessId}`, { tenantId }),
      api<Program>(`loyalty/programs?business_id=${businessId}`, { tenantId }),
    ]).then(([rows, settings]) => {
      if (!active) return;
      setCustomers(rows); setProgram(settings);
      if (rows[0]) setSelectedCustomer(rows[0].id);
    }).catch((reason) => { if (active) setError(messageOf(reason)); });
    return () => { active = false; };
  }, [tenantId, businessId]);

  async function saveProgram() {
    setBusy(true); setError(""); setNotice("");
    try {
      await api("loyalty/programs", { method: "POST", tenantId, body: { business_id: businessId, ...program } });
      setNotice("Loyalty programme saved. New completed sales with a linked customer will earn points automatically.");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function addCustomer(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!name.trim()) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const created = await api<{ id: string }>("loyalty/customers/create", {
        method: "POST", tenantId,
        body: { business_id: businessId, display_name: name.trim(), email: email.trim() || null, phone: phone.trim() || null },
      });
      setName(""); setEmail(""); setPhone(""); setSelectedCustomer(created.id);
      await reload();
      setNotice("Customer added to this business.");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function redeem() {
    const points = Number(redeemPoints);
    if (!selectedCustomer || !Number.isSafeInteger(points) || points <= 0) { setError("Choose a customer and enter a positive whole number of points."); return; }
    setBusy(true); setError(""); setNotice(""); setReward(null);
    try {
      const result = await api<{ reward_code: string; reward_value_minor: number; points_redeemed: number }>(`loyalty/customers/${selectedCustomer}/redeem`, {
        method: "POST", tenantId, body: { points },
      });
      setReward(result);
      await reload();
      setNotice("Reward issued. Record the reward code against the customer's redemption.");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  if (loading) return <main className="pos-loading">Loading loyalty…</main>;
  const currentCustomer = customers.find((customer) => customer.id === selectedCustomer);
  return (
    <main className="pos-shell">
      <header className="pos-header">
        <div><a href="/" className="pos-back">← Management</a><h1>Customer loyalty</h1><p>Customer records, points, rewards and purchase-linked earning.</p></div>
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
            <p className="pos-eyebrow">PROGRAMME RULES</p>
            <h2>Points scheme</h2>
            <label className="pos-check-label"><input type="checkbox" checked={program.enabled} onChange={(event) => setProgram({ ...program, enabled: event.target.checked })} /> Enable loyalty earning</label>
            <label>Points earned per £1 spent<input type="number" min="0" max="10000" value={program.points_per_major_unit} onChange={(event) => setProgram({ ...program, points_per_major_unit: Number(event.target.value) })} /></label>
            <label>Points required for £1 reward<input type="number" min="1" max="100000" value={program.redemption_points_per_major_unit} onChange={(event) => setProgram({ ...program, redemption_points_per_major_unit: Number(event.target.value) })} /></label>
            <p><small>Points are awarded automatically when a linked sale reaches completed status, including successful SumUp and PayPal captures. A sale can only earn points once.</small></p>
            <button disabled={busy || !businessId} onClick={() => void saveProgram()}>Save loyalty programme</button>
          </section>
          <section className="pos-panel">
            <p className="pos-eyebrow">CUSTOMER DIRECTORY</p>
            <h2>Customers</h2>
            <form className="pos-till-tools" onSubmit={(event) => void addCustomer(event)}>
              <label>Customer name<input value={name} onChange={(event) => setName(event.target.value)} required /></label>
              <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
              <label>Phone<input value={phone} onChange={(event) => setPhone(event.target.value)} /></label>
              <button disabled={busy || !businessId}>Add customer</button>
            </form>
            {customers.length ? customers.map((customer) => <article className="pos-cart-line" key={customer.id}><div><b>{customer.display_name}</b><small>{customer.email || customer.phone || "No contact details"}</small><small>{customer.lifetime_earned} lifetime points earned · {customer.lifetime_redeemed} redeemed</small></div><strong>{customer.balance_points} pts</strong></article>) : <p className="pos-empty">No customers yet. Add a customer to start earning loyalty points.</p>}
          </section>
        </section>
        <aside className="pos-cart">
          <p className="pos-eyebrow">REWARD REDEMPTION</p>
          <h2>Issue a reward</h2>
          <label>Customer<select value={selectedCustomer} onChange={(event) => setSelectedCustomer(event.target.value)}><option value="">Choose customer</option>{customers.map((customer) => <option key={customer.id} value={customer.id}>{customer.display_name} · {customer.balance_points} points</option>)}</select></label>
          <p><strong>Available balance:</strong> {currentCustomer?.balance_points ?? 0} points</p>
          <label>Points to redeem<input type="number" min="1" value={redeemPoints} onChange={(event) => setRedeemPoints(event.target.value)} /></label>
          <p><small>At the current conversion, {program.redemption_points_per_major_unit} points equal £1. Rewards are issued as a tracked code. At checkout, select the same customer and enter the reward code to apply its value to the sale.</small></p>
          <button disabled={busy || !selectedCustomer} onClick={() => void redeem()}>Issue reward</button>
          {reward && <section className="pos-result"><b>Reward issued</b><strong>£{(reward.reward_value_minor / 100).toFixed(2)}</strong><p>{reward.points_redeemed} points redeemed</p><code>{reward.reward_code}</code></section>}
          <a className="pos-secondary-button" href="/integrations">Business integrations</a>
        </aside>
      </div>
    </main>
  );
}
