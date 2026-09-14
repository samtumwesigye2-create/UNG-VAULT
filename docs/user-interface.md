# Application interface

GET / and /ui serve the mobile interface. Existing operational APIs remain in place; previous JSON root status is available at /api/status where applicable. Screens invoke same-origin APIs and display actual responses without seeded data.

VECTOR retains the WMS5250 green terminal style, with F5 refresh and F3/F12 return to inventory. APEX creates multimodal shipment plans, compares estimated costs/emissions, resolves ZIP routes, reports disruptions and reroutes existing shipment IDs. APEX plans remain in memory and are lost on service restart. VAULT creates and retrieves objects by ID and verifies the audit chain; returned secret values are masked until explicitly revealed.

VECTOR and VAULT sign-in delegates to the configured JANUS authority. Passwords are not stored by the interface, bearer tokens stay in browser memory, and all original API authorization/clearance checks remain enforced. Reloading requires sign-in. Sign out requests JANUS revocation and clears the screen even when revocation is unavailable. JANUS account passwords are separate from the legacy Warehouse master-code bridge.

Portal checks: python -m unittest discover -s tests -p test_ui_portal.py (requires httpx2 with current Starlette).
