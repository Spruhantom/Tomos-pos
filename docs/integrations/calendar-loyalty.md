# Calendar and loyalty integration

## SumUp Bookings calendar bridge

SumUp Bookings does not expose a public appointment-management API in the public developer reference. SumUp does provide a supported two-way calendar synchronisation feature with Google Calendar.

TomOS therefore uses this supported bridge:

`SumUp Bookings ⇄ Google Calendar ⇄ TomOS POS`

### Configuration

Set these API service secrets:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_CALENDAR_REDIRECT_URI` — exact registered callback ending in `/api/v1/calendar/oauth/callback`
- `TOMOS_INTEGRATION_ENCRYPTION_KEY` — the same 32-byte hexadecimal AES-256-GCM key used for SumUp credentials

Register a Google OAuth web application and enable the Google Calendar API. The app requests the `https://www.googleapis.com/auth/calendar.events` scope and offline access.

For each business:

1. Connect its Google account from **Business integrations** in TomOS.
2. In SumUp, open Bookings → Calendars → Settings → Calendar sync and connect the corresponding Google Calendar.
3. In TomOS, use **Synchronise appointments** to import the next 365 days.
4. TomOS-created appointments are written to Google Calendar. TomOS edits update the same Google Calendar event, which SumUp Bookings can receive through its configured calendar sync.
5. Changes made in SumUp Bookings appear in Google Calendar and are imported into TomOS the next time the sync action is run.

The first implementation uses explicit sync rather than a continuous push subscription. Therefore, SumUp/Google changes are not reflected in TomOS in real time until the business runs a sync. TomOS writes to Google Calendar immediately.

All appointment rows are tenant- and business-scoped. External Google event IDs are stored to avoid duplicate imports. Cancelled Google events are mirrored as cancelled appointments.

## TomOS customer loyalty

The public SumUp Developer API currently documents readers, checkouts, customers, transactions, payouts and receipts, but does not expose endpoints to read or change SumUp's own loyalty balances, stamps or reward campaigns. TomOS does not scrape or modify the private SumUp loyalty dashboard.

TomOS provides an independent, tenant-scoped loyalty ledger:

- Customer records per business.
- Configurable points earned per pound spent.
- Configurable points-to-pound reward conversion.
- Automatic points earning when a linked POS sale becomes completed.
- Append-only earn/redeem ledger entries.
- Reward codes issued against a customer's available points.
- Reward codes applied at checkout as a sale discount.
- A reward is reserved while PayPal or SumUp payment is pending, redeemed only after successful payment, and released if the external payment fails or is cancelled.
- Database uniqueness and sale state transitions prevent duplicate point awards.

At checkout, select the customer and optionally enter an issued reward code. The reward must belong to that same customer and business, must be unused, and cannot exceed the sale total.

TomOS loyalty is separate from SumUp Loyalty / SumUp Connect. Customers can use either scheme independently; automatic cross-account balance synchronisation is not available through the public SumUp API.
