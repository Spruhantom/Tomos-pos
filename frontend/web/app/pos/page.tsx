"use client";

import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "@/lib/api";

type User = { id: string; email: string; display_name: string };
type Tenant = { tenant_id: string; display_name: string };
type Business = { id: string; legal_name: string; trading_name: string | null; currency_code: string };
type Location = { id: string; name: string; is_active: boolean };
type Product = { id: string; sku: string; barcode: string | null; name: string; unit_price_minor: number; currency_code: string; tax_rate_bps: number };
type Till = { id: string; opening_float_minor: number; currency_code: string; opened_at: string };
type CheckoutResult = { sale_id: string; sale_number: number; status: string; tender_id: string; total_minor: number; tax_minor: number; change_due_minor: number; payment_method: string; payment_status: string; message: string };

function money(value: number, currency = "GBP") {
  return new Intl.NumberFormat("en-GB", { style: "currency", currency }).format(value / 100);
}
function poundsToMinor(value: string) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.round(parsed * 100) : -1;
}
function messageOf(error: unknown) {
  return error instanceof ApiError ? error.message : "The request could not be completed. Check your connection and try again.";
}

export default function PosPage() {
  const [user, setUser] = useState<User | null>(null);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [businessId, setBusinessId] = useState("");
  const [locations, setLocations] = useState<Location[]>([]);
  const [locationId, setLocationId] = useState("");
  const [products, setProducts] = useState<Product[]>([]);
  const [till, setTill] = useState<Till | null>(null);
  const [openingFloat, setOpeningFloat] = useState("100.00");
  const [cashMovementType, setCashMovementType] = useState<"paid_in" | "paid_out">("paid_in");
  const [cashMovementAmount, setCashMovementAmount] = useState("");
  const [cashMovementReason, setCashMovementReason] = useState("");
  const [closingCount, setClosingCount] = useState("");
  const [cashReceived, setCashReceived] = useState("");
  const [terminalReference, setTerminalReference] = useState("");
  const [cart, setCart] = useState<Record<string, number>>({});
  const [paymentMethod, setPaymentMethod] = useState<"cash" | "card_terminal">("cash");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [lastSale, setLastSale] = useState<CheckoutResult | null>(null);
  const [checkoutKey, setCheckoutKey] = useState("");
  const [search, setSearch] = useState("");

  useEffect(() => {
    let active = true;
    async function initialise() {
      try {
        const [me, workspaceResult] = await Promise.all([
          api<User>("auth/me"),
          api<{ tenants: Tenant[] }>("auth/tenants"),
        ]);
        if (!active) return;
        setUser(me);
        setTenants(workspaceResult.tenants);
        if (workspaceResult.tenants[0]) setTenantId(workspaceResult.tenants[0].tenant_id);
      } catch (reason) {
        if (active) setError(messageOf(reason));
      } finally {
        if (active) setLoading(false);
      }
    }
    void initialise();
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    setBusinesses([]); setBusinessId(""); setLocations([]); setLocationId(""); setProducts([]); setTill(null);
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
    setLocations([]); setLocationId(""); setProducts([]); setTill(null);
    if (!tenantId || !businessId) return;
    api<{ locations: Location[] }>(`businesses/${businessId}/locations`, { tenantId })
      .then((result) => {
        if (!active) return;
        const available = result.locations.filter((location) => location.is_active);
        setLocations(available);
        setLocationId(available[0]?.id ?? "");
      })
      .catch((reason) => { if (active) setError(messageOf(reason)); });
    return () => { active = false; };
  }, [tenantId, businessId]);

  useEffect(() => {
    let active = true;
    setProducts([]); setTill(null);
    if (!tenantId || !businessId || !locationId) return;
    Promise.all([
      api<{ products: Product[] }>(`pos/catalogue?business_id=${businessId}`, { tenantId }),
      api<{ till: Till | null }>(`pos/tills/current?location_id=${locationId}`, { tenantId }),
    ]).then(([catalogue, current]) => {
      if (!active) return;
      setProducts(catalogue.products);
      setTill(current.till);
    }).catch((reason) => { if (active) setError(messageOf(reason)); });
    return () => { active = false; };
  }, [tenantId, businessId, locationId]);

  const selectedBusiness = businesses.find((business) => business.id === businessId);
  const cartLines = useMemo(() => products.filter((product) => cart[product.id]).map((product) => ({ product, quantity: cart[product.id] })), [products, cart]);
  const totalMinor = cartLines.reduce((sum, line) => sum + line.product.unit_price_minor * line.quantity, 0);
  const taxMinor = cartLines.reduce((sum, line) => {
    const gross = line.product.unit_price_minor * line.quantity;
    const divisor = 10_000 + line.product.tax_rate_bps;
    return sum + Math.floor((gross * line.product.tax_rate_bps + divisor / 2) / divisor);
  }, 0);
  const filteredProducts = products.filter((product) => (product.name + " " + product.sku + " " + (product.barcode ?? "")).toLowerCase().includes(search.toLowerCase()));

  function addProduct(product: Product) {
    setCart((current) => ({ ...current, [product.id]: (current[product.id] ?? 0) + 1 }));
    setLastSale(null); setNotice("");
  }
  function changeQuantity(productId: string, quantity: number) {
    setCart((current) => {
      const next = { ...current };
      if (quantity <= 0) delete next[productId]; else next[productId] = Math.min(10_000, quantity);
      return next;
    });
  }

  async function openTill() {
    const floatMinor = poundsToMinor(openingFloat);
    if (floatMinor < 0) { setError("Enter a valid opening float."); return; }
    setBusy(true); setError(""); setNotice("");
    try {
      await api("pos/tills/open", { method: "POST", tenantId, body: { business_id: businessId, location_id: locationId, opening_float_minor: floatMinor } });
      const current = await api<{ till: Till | null }>(`pos/tills/current?location_id=${locationId}`, { tenantId });
      setTill(current.till); setNotice("Till opened. You can now start a sale.");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function recordCashMovement() {
    if (!till) return;
    const amountMinor = poundsToMinor(cashMovementAmount);
    if (amountMinor <= 0 || !cashMovementReason.trim()) {
      setError("Enter a positive amount and a reason for the cash movement."); return;
    }
    setBusy(true); setError(""); setNotice("");
    try {
      await api(`pos/tills/${till.id}/cash-movements`, {
        method: "POST", tenantId,
        body: { movement_type: cashMovementType, amount_minor: amountMinor, reason: cashMovementReason.trim() },
      });
      setNotice(cashMovementType === "paid_in" ? "Cash paid into the drawer was recorded." : "Cash paid out of the drawer was recorded.");
      setCashMovementAmount(""); setCashMovementReason("");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function closeTill() {
    if (!till) return;
    const countedMinor = poundsToMinor(closingCount);
    if (countedMinor < 0) { setError("Enter the counted cash total."); return; }
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await api<{ expected_cash_minor: number; counted_cash_minor: number; variance_minor: number }>(
        `pos/tills/${till.id}/close`,
        { method: "POST", tenantId, body: { closing_count_minor: countedMinor } },
      );
      setNotice(`Till closed. Expected ${money(result.expected_cash_minor, selectedBusiness?.currency_code)}; variance ${money(result.variance_minor, selectedBusiness?.currency_code)}.`);
      setTill(null); setCart({}); setClosingCount("");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  async function takePayment() {
    if (!till || !cartLines.length) return;
    const receivedMinor = poundsToMinor(cashReceived);
    if (paymentMethod === "cash" && receivedMinor < totalMinor) {
      setError("Cash received must cover the sale total."); return;
    }
    setBusy(true); setError(""); setNotice(""); setLastSale(null);
    const idempotencyKey = checkoutKey || crypto.randomUUID();
    if (!checkoutKey) setCheckoutKey(idempotencyKey);
    try {
      const result = await api<CheckoutResult>("pos/sales", {
        method: "POST", tenantId,
        body: {
          business_id: businessId,
          location_id: locationId,
          till_session_id: till.id,
          idempotency_key: idempotencyKey,
          items: cartLines.map((line) => ({ product_id: line.product.id, quantity: line.quantity })),
          payment_method: paymentMethod,
          ...(paymentMethod === "cash" ? { cash_received_minor: receivedMinor } : { terminal_reference: terminalReference || null }),
        },
      });
      setLastSale(result);
      setNotice(result.message);
      setCart({});
      setCheckoutKey(crypto.randomUUID());
      setCashReceived("");
      setTerminalReference("");
    } catch (reason) { setError(messageOf(reason)); }
    finally { setBusy(false); }
  }

  if (loading) return <main className="pos-loading">Loading TomOS POS…</main>;
  if (!user) return <main className="pos-login"><a href="/">← Back to management</a><h1>Sign in required</h1><p>{error || "Sign in to the management interface before opening the till."}</p></main>;

  return (
    <main className="pos-shell">
      <header className="pos-header">
        <div><a href="/" className="pos-back">← Management</a><h1>Checkout</h1><p>{user.display_name} · {selectedBusiness?.trading_name || selectedBusiness?.legal_name || "Select a business"}</p></div>
        <div className="pos-selectors">
          <label>Workspace<select value={tenantId} onChange={(event) => setTenantId(event.target.value)}>{tenants.map((tenant) => <option key={tenant.tenant_id} value={tenant.tenant_id}>{tenant.display_name}</option>)}</select></label>
          <label>Business<select value={businessId} onChange={(event) => setBusinessId(event.target.value)}>{businesses.map((business) => <option key={business.id} value={business.id}>{business.trading_name || business.legal_name}</option>)}</select></label>
          <label>Location<select value={locationId} onChange={(event) => setLocationId(event.target.value)}>{locations.map((location) => <option key={location.id} value={location.id}>{location.name}</option>)}</select></label>
        </div>
      </header>
      {error && <p className="pos-alert error">{error}</p>}
      {notice && <p className="pos-alert success">{notice}</p>}
      {!locationId ? <section className="pos-panel"><h2>No active location</h2><p>Add an active business location in management before opening a till.</p></section> :
        !till ? <section className="pos-panel pos-open-till"><h2>Open the till</h2><p>Enter the cash float counted into the drawer before trading begins.</p><label>Opening float (£)<input inputMode="decimal" value={openingFloat} onChange={(event) => setOpeningFloat(event.target.value)} /></label><button disabled={busy} onClick={() => void openTill()}>{busy ? "Opening…" : "Open till"}</button></section> :
        <div className="pos-workspace">
          <section className="pos-products">
            <div className="pos-section-heading"><div><p className="pos-eyebrow">PRODUCT CATALOGUE</p><h2>Add items</h2></div><input aria-label="Search products" placeholder="Search name, SKU or barcode" value={search} onChange={(event) => setSearch(event.target.value)} /></div>
            <div className="pos-product-grid">
              {filteredProducts.map((product) => <button className="pos-product" key={product.id} onClick={() => addProduct(product)}><span>{product.name}</span><small>{product.sku}</small><b>{money(product.unit_price_minor, product.currency_code)}</b></button>)}
              {!filteredProducts.length && <p className="pos-empty">No products found. Add products to the catalogue before checkout.</p>}
            </div>
          </section>
          <aside className="pos-cart">
            <div className="pos-cart-heading"><div><p className="pos-eyebrow">ACTIVE TILL</p><h2>Current sale</h2></div><span className="pos-open-pill">Open</span></div>
            <div className="pos-cart-lines">
              {cartLines.map(({ product, quantity }) => <div className="pos-cart-line" key={product.id}><div><b>{product.name}</b><small>{money(product.unit_price_minor, product.currency_code)} each</small></div><div className="pos-quantity"><button aria-label={`Remove one ${product.name}`} onClick={() => changeQuantity(product.id, quantity - 1)}>−</button><span>{quantity}</span><button aria-label={`Add one ${product.name}`} onClick={() => changeQuantity(product.id, quantity + 1)}>+</button></div><strong>{money(product.unit_price_minor * quantity, product.currency_code)}</strong></div>)}
              {!cartLines.length && <p className="pos-empty">Your basket is empty. Select a product to begin.</p>}
            </div>
            <div className="pos-totals"><div><span>VAT included</span><b>{money(taxMinor, selectedBusiness?.currency_code)}</b></div><div className="pos-grand-total"><span>Total</span><b>{money(totalMinor, selectedBusiness?.currency_code)}</b></div></div>
            <div className="pos-payment">
              <p className="pos-eyebrow">PAYMENT METHOD</p>
              <div className="pos-payment-options"><button className={paymentMethod === "cash" ? "selected" : ""} onClick={() => setPaymentMethod("cash")}>Cash</button><button className={paymentMethod === "card_terminal" ? "selected" : ""} onClick={() => setPaymentMethod("card_terminal")}>Card terminal</button></div>
              {paymentMethod === "cash" ? <label>Cash received (£)<input inputMode="decimal" value={cashReceived} onChange={(event) => setCashReceived(event.target.value)} placeholder="0.00" /></label> :
                <label>Terminal reference (optional)<input value={terminalReference} onChange={(event) => setTerminalReference(event.target.value)} placeholder="Terminal or lane reference" /><small>Card payments remain pending until a connected terminal provider confirms approval.</small></label>}
              <button className="pos-pay-button" onClick={() => void takePayment()} disabled={busy || !cartLines.length}>{busy ? "Processing…" : paymentMethod === "cash" ? "Complete cash sale" : "Start card terminal payment"}</button>
              <button className="pos-clear" disabled={busy || !cartLines.length} onClick={() => setCart({})}>Clear basket</button>
            </div>
            <div className="pos-till-tools">
              <p className="pos-eyebrow">TILL OPERATIONS</p>
              <label>Cash movement<select value={cashMovementType} onChange={(event) => setCashMovementType(event.target.value as "paid_in" | "paid_out")}><option value="paid_in">Paid in</option><option value="paid_out">Paid out</option></select></label>
              <label>Amount (£)<input inputMode="decimal" value={cashMovementAmount} onChange={(event) => setCashMovementAmount(event.target.value)} placeholder="0.00" /></label>
              <label>Reason<input value={cashMovementReason} onChange={(event) => setCashMovementReason(event.target.value)} placeholder="Reason for movement" /></label>
              <button className="pos-secondary-button" disabled={busy} onClick={() => void recordCashMovement()}>Record cash movement</button>
              <div className="pos-close-till">
                <label>Counted drawer cash (£)<input inputMode="decimal" value={closingCount} onChange={(event) => setClosingCount(event.target.value)} placeholder="0.00" /></label>
                <button className="pos-close-button" disabled={busy} onClick={() => void closeTill()}>Close and reconcile till</button>
              </div>
            </div>
          </aside>
        </div>}
      {lastSale && <section className="pos-result"><b>Sale #{lastSale.sale_number}</b><span>{lastSale.status.replaceAll("_", " ")}</span><strong>{money(lastSale.total_minor, selectedBusiness?.currency_code)}</strong>{lastSale.payment_method === "cash" && <p>Change due: {money(lastSale.change_due_minor, selectedBusiness?.currency_code)}</p>}{lastSale.payment_method === "card_terminal" && <p>Do not release the goods until the terminal provider confirms the payment.</p>}</section>}
    </main>
  );
}
