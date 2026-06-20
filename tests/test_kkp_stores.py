"""KKP Stores backend integration tests"""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://utility-depot-1.preview.emergentagent.com').rstrip('/')
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@kkpstores.com"
ADMIN_PASSWORD = "admin123"


@pytest.fixture(scope="session")
def admin_token():
    r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "token" in data
    assert data["user"]["email"] == ADMIN_EMAIL if "user" in data else data["email"] == ADMIN_EMAIL
    return data["token"]


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ---------------- Auth ----------------
class TestAuth:
    def test_login_admin(self):
        r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
        assert r.status_code == 200, r.text
        data = r.json()
        assert "token" in data
        assert data["email"] == ADMIN_EMAIL
        assert data["role"] == "admin"
        # cookies set
        assert "access_token" in r.cookies or any("access_token" in c for c in r.headers.get("set-cookie", ""))

    def test_login_bad_credentials(self):
        r = requests.post(f"{API}/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong"})
        assert r.status_code == 401

    def test_me(self, admin_headers):
        r = requests.get(f"{API}/auth/me", headers=admin_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == ADMIN_EMAIL
        assert data["role"] == "admin"
        assert "password_hash" not in data

    def test_register_creates_cashier(self):
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"
        r = requests.post(f"{API}/auth/register", json={
            "name": "TEST User", "email": email, "password": "Test1234!"
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["email"] == email
        # since admin already exists, role should be cashier
        assert data["role"] == "cashier"
        assert "token" in data


# ---------------- Products ----------------
class TestProducts:
    def test_list_products_has_seed(self, admin_headers):
        r = requests.get(f"{API}/products", headers=admin_headers)
        assert r.status_code == 200
        items = r.json()
        assert isinstance(items, list)
        assert len(items) >= 10, f"Expected >=10 seeded products, got {len(items)}"

    def test_search_q(self, admin_headers):
        r = requests.get(f"{API}/products", headers=admin_headers, params={"q": "Saree"})
        assert r.status_code == 200
        items = r.json()
        assert all("saree" in (i["name"]+i["sku"]).lower() or "saree" in i.get("barcode","") for i in items)
        assert len(items) >= 1

    def test_category_filter(self, admin_headers):
        r = requests.get(f"{API}/products", headers=admin_headers, params={"category": "Textiles"})
        assert r.status_code == 200
        items = r.json()
        assert all(i["category"] == "Textiles" for i in items)

    def test_barcode_lookup(self, admin_headers):
        r = requests.get(f"{API}/products/barcode/8901234500011", headers=admin_headers)
        assert r.status_code == 200
        assert r.json()["sku"] == "TEX-SAR-001"

    def test_crud_product(self, admin_headers):
        sku = f"TEST-{uuid.uuid4().hex[:8]}"
        payload = {"name": "TEST Product", "sku": sku, "barcode": "TEST123",
                   "category": "Textiles", "purchase_price": 100, "sale_price": 200,
                   "gst_percent": 5, "stock_qty": 50, "low_stock_threshold": 5}
        r = requests.post(f"{API}/products", headers=admin_headers, json=payload)
        assert r.status_code == 200, r.text
        pid = r.json()["id"]
        # duplicate SKU
        r2 = requests.post(f"{API}/products", headers=admin_headers, json=payload)
        assert r2.status_code == 400
        # update
        payload["sale_price"] = 250
        r3 = requests.put(f"{API}/products/{pid}", headers=admin_headers, json=payload)
        assert r3.status_code == 200
        assert r3.json()["sale_price"] == 250
        # get
        rg = requests.get(f"{API}/products/{pid}", headers=admin_headers)
        assert rg.status_code == 200 and rg.json()["sale_price"] == 250
        # delete
        rd = requests.delete(f"{API}/products/{pid}", headers=admin_headers)
        assert rd.status_code == 200
        rg2 = requests.get(f"{API}/products/{pid}", headers=admin_headers)
        assert rg2.status_code == 404


# ---------------- Customers & Suppliers ----------------
class TestCustomersSuppliers:
    def test_customer_crud(self, admin_headers):
        r = requests.post(f"{API}/customers", headers=admin_headers,
                          json={"name": "TEST Customer", "phone": "9999999999"})
        assert r.status_code == 200
        cid = r.json()["id"]
        rl = requests.get(f"{API}/customers", headers=admin_headers)
        assert rl.status_code == 200 and any(c["id"] == cid for c in rl.json())
        ru = requests.put(f"{API}/customers/{cid}", headers=admin_headers,
                          json={"name": "TEST Customer Updated", "phone": "9999999999"})
        assert ru.status_code == 200 and ru.json()["name"] == "TEST Customer Updated"
        rd = requests.delete(f"{API}/customers/{cid}", headers=admin_headers)
        assert rd.status_code == 200

    def test_supplier_crud(self, admin_headers):
        r = requests.post(f"{API}/suppliers", headers=admin_headers, json={"name": "TEST Supplier"})
        assert r.status_code == 200
        sid = r.json()["id"]
        rl = requests.get(f"{API}/suppliers", headers=admin_headers)
        assert rl.status_code == 200 and any(s["id"] == sid for s in rl.json())
        rd = requests.delete(f"{API}/suppliers/{sid}", headers=admin_headers)
        assert rd.status_code == 200


# ---------------- Sales & Purchases ----------------
class TestSalesPurchases:
    def test_sale_flow_decrements_stock(self, admin_headers):
        # Get a product
        r = requests.get(f"{API}/products", headers=admin_headers, params={"q": "Cotton Saree"})
        prod = r.json()[0]
        before = prod["stock_qty"]

        unit_price = prod["sale_price"]
        gst = prod["gst_percent"]
        qty = 2
        base = unit_price * qty
        line_total = base + base * gst / 100.0

        payload = {
            "customer_name": "Walk-in Customer",
            "items": [{"product_id": prod["id"], "name": prod["name"], "sku": prod["sku"],
                       "quantity": qty, "unit_price": unit_price, "gst_percent": gst,
                       "discount": 0, "line_total": line_total}],
            "payment_method": "cash"
        }
        rs = requests.post(f"{API}/sales", headers=admin_headers, json=payload)
        assert rs.status_code == 200, rs.text
        sale = rs.json()
        assert sale["invoice_no"].startswith("KKP-")
        # Check computed totals
        expected_grand = round(base + base * gst / 100.0, 2)
        assert abs(sale["grand_total"] - expected_grand) < 0.5, f"grand_total={sale['grand_total']} expected={expected_grand}"

        # Verify stock decremented
        rg = requests.get(f"{API}/products/{prod['id']}", headers=admin_headers)
        assert rg.json()["stock_qty"] == before - qty

        # Verify in list
        rl = requests.get(f"{API}/sales", headers=admin_headers)
        assert any(s["invoice_no"] == sale["invoice_no"] for s in rl.json())

    def test_sale_insufficient_stock(self, admin_headers):
        r = requests.get(f"{API}/products", headers=admin_headers)
        prod = r.json()[0]
        payload = {
            "customer_name": "Walk-in", "payment_method": "cash",
            "items": [{"product_id": prod["id"], "name": prod["name"], "sku": prod["sku"],
                       "quantity": 999999, "unit_price": prod["sale_price"],
                       "gst_percent": prod["gst_percent"], "discount": 0, "line_total": 0}],
        }
        rs = requests.post(f"{API}/sales", headers=admin_headers, json=payload)
        assert rs.status_code == 400

    def test_purchase_increments_stock(self, admin_headers):
        rs = requests.get(f"{API}/suppliers", headers=admin_headers)
        sup = rs.json()[0]
        rp = requests.get(f"{API}/products", headers=admin_headers, params={"q": "Pillow"})
        prod = rp.json()[0]
        before = prod["stock_qty"]

        payload = {
            "supplier_id": sup["id"], "supplier_name": sup["name"],
            "items": [{"product_id": prod["id"], "name": prod["name"], "sku": prod["sku"],
                       "quantity": 10, "unit_cost": 70, "line_total": 700}],
        }
        rpo = requests.post(f"{API}/purchases", headers=admin_headers, json=payload)
        assert rpo.status_code == 200, rpo.text
        assert rpo.json()["po_no"].startswith("PO-")
        rg = requests.get(f"{API}/products/{prod['id']}", headers=admin_headers)
        assert rg.json()["stock_qty"] == before + 10


# ---------------- Dashboard & Reports ----------------
class TestDashboardReports:
    def test_dashboard_summary(self, admin_headers):
        r = requests.get(f"{API}/dashboard/summary", headers=admin_headers)
        assert r.status_code == 200
        d = r.json()
        for k in ["today_sales_amount", "today_orders", "stock_value", "low_stock_count",
                  "total_products", "total_customers", "chart_last_7_days", "top_products"]:
            assert k in d
        assert len(d["chart_last_7_days"]) == 7
        assert d["total_products"] >= 10

    def test_sales_report(self, admin_headers):
        r = requests.get(f"{API}/reports/sales", headers=admin_headers, params={"days": 30})
        assert r.status_code == 200
        d = r.json()
        for k in ["period_days", "count", "total", "tax", "sales"]:
            assert k in d
        assert d["period_days"] == 30

    def test_stock_report(self, admin_headers):
        r = requests.get(f"{API}/reports/stock", headers=admin_headers)
        assert r.status_code == 200
        d = r.json()
        for k in ["products", "total_value", "out_of_stock", "low_stock"]:
            assert k in d


# ---------------- AI ----------------
class TestAI:
    def test_ai_insights(self, admin_headers):
        r = requests.post(f"{API}/ai/insights", headers=admin_headers,
                          json={"focus": "general"}, timeout=60)
        assert r.status_code == 200, r.text
        d = r.json()
        assert "insights" in d and isinstance(d["insights"], str) and len(d["insights"]) > 30
        assert "snapshot" in d
        snap = d["snapshot"]
        for k in ["total_products", "total_orders", "total_revenue", "avg_order_value",
                  "low_stock_count", "top_sellers"]:
            assert k in snap


# ---------------- Role Enforcement ----------------
class TestRoles:
    @pytest.fixture(scope="class")
    def cashier_token(self):
        email = f"cashier_{uuid.uuid4().hex[:8]}@example.com"
        r = requests.post(f"{API}/auth/register", json={
            "name": "TEST Cashier", "email": email, "password": "Cashier123!", "role": "cashier"
        })
        assert r.status_code == 200
        return r.json()["token"]

    def test_cashier_cannot_list_users(self, cashier_token):
        r = requests.get(f"{API}/users", headers={"Authorization": f"Bearer {cashier_token}"})
        assert r.status_code == 403

    def test_cashier_cannot_create_supplier(self, cashier_token):
        r = requests.post(f"{API}/suppliers", headers={"Authorization": f"Bearer {cashier_token}"},
                          json={"name": "Bad Supplier"})
        assert r.status_code == 403

    def test_unauthenticated_blocked(self):
        r = requests.get(f"{API}/products")
        assert r.status_code == 401
