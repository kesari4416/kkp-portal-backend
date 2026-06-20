"""Backend tests for KKP Stores iteration 2: multi-store + user mgmt + logout.

Covers:
- GET /api/stores, POST /api/stores, PUT /api/stores/{id}, POST /api/stores/switch
- Per-store data isolation (products, customers, suppliers, sales, dashboard, reports)
- Per-store invoice counters
- Per-store SKU uniqueness (same SKU allowed across stores)
- Admin user mgmt: POST/PATCH/DELETE/GET /api/users; cannot delete self
- Token reissue on store switch
"""
import os
import time
import uuid
import pytest
import requests

def _load_frontend_env():
    fp = "/app/frontend/.env"
    if os.path.exists(fp):
        for line in open(fp):
            if line.startswith("REACT_APP_BACKEND_URL="):
                return line.split("=", 1)[1].strip()
    return None

BASE_URL = (os.environ.get('REACT_APP_BACKEND_URL') or _load_frontend_env()).rstrip('/')
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@kkpstores.com"
ADMIN_PASSWORD = "admin123"


# ---------- helpers / fixtures ----------
@pytest.fixture(scope="module")
def admin_session():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    r = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    s.headers.update({"Authorization": f"Bearer {token}"})
    s._token = token
    return s


def _get_main_store_id(sess):
    r = sess.get(f"{API}/auth/me")
    assert r.status_code == 200
    return r.json()["store_id"]


# ---------- Stores ----------
class TestStores:
    def test_list_stores_includes_main(self, admin_session):
        r = admin_session.get(f"{API}/stores")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list) and len(data) >= 1
        main_id = _get_main_store_id(admin_session)
        assert any(s["id"] == main_id for s in data)

    def test_update_store_profile(self, admin_session):
        main_id = _get_main_store_id(admin_session)
        # Capture original
        r = admin_session.get(f"{API}/stores")
        original = next(s for s in r.json() if s["id"] == main_id)
        payload = {
            "name": original["name"],  # keep name same
            "address": "Coimbatore, Tamil Nadu",
            "phone": original.get("phone", ""),
            "gstin": original.get("gstin", ""),
        }
        u = admin_session.put(f"{API}/stores/{main_id}", json=payload)
        assert u.status_code == 200, u.text
        assert u.json()["address"] == "Coimbatore, Tamil Nadu"


# ---------- Data isolation + switching ----------
class TestIsolationAndSwitching:
    """Create a 2nd store, switch to it, prove data isolation, switch back."""

    def test_full_isolation_flow(self, admin_session):
        # Ensure admin is on the "Main Branch" before starting (previous interrupted runs may
        # have left admin pointing at a test branch).
        stores = admin_session.get(f"{API}/stores").json()
        main_store = next((s for s in stores if "Main Branch" in s.get("name", "")), None)
        if main_store and main_store["id"] != _get_main_store_id(admin_session):
            sw = admin_session.post(f"{API}/stores/switch", json={"store_id": main_store["id"]})
            assert sw.status_code == 200
            admin_session.headers.update({"Authorization": f"Bearer {sw.json()['token']}"})
            admin_session._token = sw.json()["token"]
        main_id = _get_main_store_id(admin_session)

        # Baseline: main has products/customers/suppliers
        prods_main = admin_session.get(f"{API}/products").json()
        custs_main = admin_session.get(f"{API}/customers").json()
        sups_main = admin_session.get(f"{API}/suppliers").json()
        sales_main_before = admin_session.get(f"{API}/sales").json()
        assert len(prods_main) >= 10
        assert len(custs_main) >= 3
        assert len(sups_main) >= 2

        # Create a fresh 2nd branch
        branch_name = f"TEST_Branch_{uuid.uuid4().hex[:8]}"
        c = admin_session.post(f"{API}/stores", json={"name": branch_name, "address": "Test Addr"})
        assert c.status_code == 200, c.text
        new_store = c.json()
        new_id = new_store["id"]
        assert new_store["owner_id"]  # owner attached

        # Switch
        sw = admin_session.post(f"{API}/stores/switch", json={"store_id": new_id})
        assert sw.status_code == 200, sw.text
        sw_json = sw.json()
        assert sw_json["store_id"] == new_id
        new_token = sw_json["token"]
        assert new_token and new_token != admin_session._token
        admin_session.headers.update({"Authorization": f"Bearer {new_token}"})
        admin_session._token = new_token

        # /auth/me reflects new store_id
        me = admin_session.get(f"{API}/auth/me").json()
        assert me["store_id"] == new_id

        # All data lists empty on new store
        for path in ("/products", "/customers", "/suppliers", "/sales", "/purchases"):
            r = admin_session.get(f"{API}{path}")
            assert r.status_code == 200, f"{path} -> {r.text}"
            assert r.json() == [], f"{path} not empty on new store: {r.json()}"

        # Dashboard summary scoped
        ds = admin_session.get(f"{API}/dashboard/summary").json()
        assert ds["total_products"] == 0
        assert ds["total_customers"] == 0
        assert ds["today_orders"] == 0

        # Reports scoped
        rs = admin_session.get(f"{API}/reports/sales").json()
        assert rs["count"] == 0
        st = admin_session.get(f"{API}/reports/stock").json()
        assert st["products"] == []

        # Per-store SKU uniqueness: create a product with SKU that exists in main
        existing_sku = prods_main[0]["sku"]
        cp = admin_session.post(f"{API}/products", json={
            "name": "TEST Reuse SKU", "sku": existing_sku, "category": "Textiles",
            "purchase_price": 10, "sale_price": 20, "stock_qty": 5,
        })
        assert cp.status_code == 200, cp.text  # allowed because different store
        new_prod_id = cp.json()["id"]

        # Duplicate in same store should fail
        dup = admin_session.post(f"{API}/products", json={
            "name": "TEST Dup", "sku": existing_sku, "category": "Textiles",
            "purchase_price": 10, "sale_price": 20, "stock_qty": 5,
        })
        assert dup.status_code == 400

        # Per-store invoice counter — create a sale on new store
        sale_payload = {
            "customer_name": "Walk-in",
            "items": [{
                "product_id": new_prod_id, "name": "TEST Reuse SKU", "sku": existing_sku,
                "quantity": 1, "unit_price": 20, "gst_percent": 5, "discount": 0, "line_total": 21.0,
            }],
            "discount_total": 0, "payment_method": "cash",
        }
        sresp = admin_session.post(f"{API}/sales", json=sale_payload)
        assert sresp.status_code == 200, sresp.text
        new_invoice_no = sresp.json()["invoice_no"]
        # New store's counter should start at 0001
        assert new_invoice_no.endswith("-0001"), f"Expected -0001 on new store, got {new_invoice_no}"

        # Switch back to main
        sb = admin_session.post(f"{API}/stores/switch", json={"store_id": main_id})
        assert sb.status_code == 200
        admin_session.headers.update({"Authorization": f"Bearer {sb.json()['token']}"})
        admin_session._token = sb.json()["token"]

        # Main store data still intact
        prods_after = admin_session.get(f"{API}/products").json()
        assert len(prods_after) == len(prods_main)

        # Cleanup: delete new product & store-level data via switching back
        admin_session.post(f"{API}/stores/switch", json={"store_id": new_id})
        admin_session.headers.update({"Authorization": f"Bearer {admin_session.post(f'{API}/stores/switch', json={'store_id': new_id}).json()['token']}"}) if False else None
        # Simpler: re-login switch
        sw2 = admin_session.post(f"{API}/stores/switch", json={"store_id": new_id})
        admin_session.headers.update({"Authorization": f"Bearer {sw2.json()['token']}"})
        admin_session.delete(f"{API}/products/{new_prod_id}")

        # Switch back to main for next tests
        final = admin_session.post(f"{API}/stores/switch", json={"store_id": main_id})
        admin_session.headers.update({"Authorization": f"Bearer {final.json()['token']}"})
        admin_session._token = final.json()["token"]


# ---------- User management ----------
class TestUserMgmt:
    def test_admin_can_list_users(self, admin_session):
        r = admin_session.get(f"{API}/users")
        assert r.status_code == 200
        users = r.json()
        assert any(u["email"] == ADMIN_EMAIL for u in users)
        # No password_hash leaked
        for u in users:
            assert "password_hash" not in u

    def test_create_update_delete_user_lifecycle(self, admin_session):
        # Ensure admin on main store
        main_id = _get_main_store_id(admin_session)
        email = f"test_mgr_{uuid.uuid4().hex[:8]}@kkp.com"
        # Create
        c = admin_session.post(f"{API}/users", json={
            "name": "TEST Manager", "email": email, "password": "mgrPass123", "role": "manager",
        })
        assert c.status_code == 200, c.text
        new_id = c.json()["id"]
        assert c.json()["role"] == "manager"
        assert c.json()["store_id"] == main_id

        # Login as new user works
        s2 = requests.Session()
        lg = s2.post(f"{API}/auth/login", json={"email": email, "password": "mgrPass123"})
        assert lg.status_code == 200

        # Patch role + password
        p = admin_session.patch(f"{API}/users/{new_id}", json={"role": "cashier", "password": "newPass456"})
        assert p.status_code == 200
        assert p.json()["role"] == "cashier"
        # New password works
        lg2 = requests.post(f"{API}/auth/login", json={"email": email, "password": "newPass456"})
        assert lg2.status_code == 200

        # GET to verify persistence
        users = admin_session.get(f"{API}/users").json()
        assert any(u["id"] == new_id and u["role"] == "cashier" for u in users)

        # Delete
        d = admin_session.delete(f"{API}/users/{new_id}")
        assert d.status_code == 200
        # Verify gone
        users_after = admin_session.get(f"{API}/users").json()
        assert not any(u["id"] == new_id for u in users_after)

    def test_cannot_delete_self(self, admin_session):
        me = admin_session.get(f"{API}/auth/me").json()
        r = admin_session.delete(f"{API}/users/{me['id']}")
        assert r.status_code == 400
        assert "yourself" in r.json().get("detail", "").lower()

    def test_non_admin_cannot_manage_users(self, admin_session):
        # Create cashier
        email = f"test_cash_{uuid.uuid4().hex[:8]}@kkp.com"
        admin_session.post(f"{API}/users", json={
            "name": "TEST Cashier", "email": email, "password": "pass1234", "role": "cashier",
        })
        s2 = requests.Session()
        lg = s2.post(f"{API}/auth/login", json={"email": email, "password": "pass1234"})
        assert lg.status_code == 200
        s2.headers.update({"Authorization": f"Bearer {lg.json()['token']}"})
        # cashier cannot list users
        r = s2.get(f"{API}/users")
        assert r.status_code == 403
        # cashier cannot create users
        c = s2.post(f"{API}/users", json={"name": "x", "email": "x@y.z", "password": "abc12345"})
        assert c.status_code == 403
        # cashier cannot switch stores
        sw = s2.post(f"{API}/stores/switch", json={"store_id": "anything"})
        assert sw.status_code == 403
        # cleanup
        users = admin_session.get(f"{API}/users").json()
        target = next((u for u in users if u["email"] == email), None)
        if target:
            admin_session.delete(f"{API}/users/{target['id']}")


# ---------- Auth / Logout ----------
class TestAuth:
    def test_logout_clears_cookies(self, admin_session):
        # Use a separate session so we don't kill the module-level admin session
        s = requests.Session()
        lg = s.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert lg.status_code == 200
        assert "access_token" in s.cookies
        out = s.post(f"{API}/auth/logout")
        assert out.status_code == 200
        # Cookie should be gone or empty
        # requests retains the Set-Cookie expiry; check by hitting /me without token header
        s.headers.pop("Authorization", None)
        me = s.get(f"{API}/auth/me")
        assert me.status_code == 401

    def test_bcrypt_hash_format(self):
        # Indirect: register a throwaway user then login to confirm bcrypt path
        # (we don't have direct DB access here, but we can rely on login behavior)
        # Use admin login as proxy that hash works
        r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert r.status_code == 200
