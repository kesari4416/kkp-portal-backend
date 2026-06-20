"""Iteration 3: dashboard rollup + customer history endpoints"""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://utility-depot-1.preview.emergentagent.com').rstrip('/')
ADMIN_EMAIL = "admin@kkpstores.com"
ADMIN_PASSWORD = "admin123"


def _login(email, password):
    r = requests.post(f"{BASE_URL}/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["token"]


@pytest.fixture(scope="module")
def admin_token():
    return _login(ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.fixture(scope="module")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="module")
def cashier_headers(admin_headers):
    """Create a cashier user (admin-scope) and login."""
    email = f"TEST_cashier_{uuid.uuid4().hex[:6]}@example.com"
    pwd = "cashier123"
    r = requests.post(f"{BASE_URL}/api/users",
                      headers=admin_headers,
                      json={"name": "TEST Cashier", "email": email, "password": pwd, "role": "cashier"})
    assert r.status_code == 200, r.text
    uid = r.json()["id"]
    tok = _login(email, pwd)
    yield {"Authorization": f"Bearer {tok}"}
    # cleanup
    requests.delete(f"{BASE_URL}/api/users/{uid}", headers=admin_headers)


# ============================================================
# 1) /api/dashboard/rollup
# ============================================================
class TestRollup:
    def test_rollup_admin_ok(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/dashboard/rollup", headers=admin_headers)
        assert r.status_code == 200, r.text
        body = r.json()
        # Shape checks
        for k in ["branches", "totals", "chart_last_7_days", "top_products"]:
            assert k in body, f"missing key {k}"
        totals = body["totals"]
        for k in ["today_sales", "today_orders", "stock_value", "low_stock_count", "total_products", "total_customers"]:
            assert k in totals, f"missing totals.{k}"
        assert isinstance(body["branches"], list)
        # Admin should own >=1 branch
        assert len(body["branches"]) >= 1
        for b in body["branches"]:
            for k in ["id", "name", "today_sales_amount", "today_orders", "stock_value",
                      "low_stock_count", "total_products", "total_customers"]:
                assert k in b
        # chart has 7 days
        assert len(body["chart_last_7_days"]) == 7

    def test_rollup_cashier_forbidden(self, cashier_headers):
        r = requests.get(f"{BASE_URL}/api/dashboard/rollup", headers=cashier_headers)
        assert r.status_code == 403

    def test_rollup_unauth(self):
        r = requests.get(f"{BASE_URL}/api/dashboard/rollup")
        assert r.status_code == 401

    def test_rollup_increments_after_sale(self, admin_headers):
        """Adding a sale in current branch should bump totals.today_sales and the corresponding branch row."""
        # Get current store id
        me = requests.get(f"{BASE_URL}/api/auth/me", headers=admin_headers).json()
        current_store = me["store_id"]

        before = requests.get(f"{BASE_URL}/api/dashboard/rollup", headers=admin_headers).json()
        before_total = before["totals"]["today_sales"]
        before_branch = next((b for b in before["branches"] if b["id"] == current_store), None)
        assert before_branch is not None, "current store missing from rollup branches"
        before_branch_total = before_branch["today_sales_amount"]

        # Pick any product
        prods = requests.get(f"{BASE_URL}/api/products", headers=admin_headers).json()
        assert prods, "need at least one product"
        p = next((x for x in prods if x.get("stock_qty", 0) >= 1), prods[0])
        sale_payload = {
            "customer_id": "",
            "customer_name": "TEST_RollupCustomer",
            "items": [{
                "product_id": p["id"], "name": p["name"], "sku": p["sku"],
                "quantity": 1, "unit_price": p["sale_price"], "gst_percent": p["gst_percent"],
                "discount": 0, "line_total": 0,
            }],
            "discount_total": 0,
            "payment_method": "cash",
        }
        sale_r = requests.post(f"{BASE_URL}/api/sales", headers=admin_headers, json=sale_payload)
        assert sale_r.status_code == 200, sale_r.text
        sale_total = sale_r.json()["grand_total"]
        assert sale_total > 0

        after = requests.get(f"{BASE_URL}/api/dashboard/rollup", headers=admin_headers).json()
        after_branch = next(b for b in after["branches"] if b["id"] == current_store)
        # Branch row reflects sale
        assert round(after_branch["today_sales_amount"] - before_branch_total, 2) >= round(sale_total - 0.05, 2)
        # Grand totals reflect sale
        assert round(after["totals"]["today_sales"] - before_total, 2) >= round(sale_total - 0.05, 2)


# ============================================================
# 2) /api/customers/{cid}/history
# ============================================================
class TestCustomerHistory:
    def test_history_empty(self, admin_headers):
        """Find a customer with no sales (Priya Sharma) and assert stats == 0."""
        custs = requests.get(f"{BASE_URL}/api/customers", headers=admin_headers).json()
        # Find one without sales by trying each
        target = None
        for c in custs:
            r = requests.get(f"{BASE_URL}/api/customers/{c['id']}/history", headers=admin_headers)
            if r.status_code == 200 and r.json()["stats"]["total_orders"] == 0:
                target = (c, r.json())
                break
        assert target is not None, "expected at least one customer with no sales"
        c, body = target
        assert body["customer"]["id"] == c["id"]
        assert body["sales"] == []
        assert body["stats"]["total_orders"] == 0
        assert body["stats"]["total_spent"] == 0
        assert body["stats"]["avg_order_value"] == 0
        assert body["stats"]["last_visit"] is None

    def test_history_with_sales(self, admin_headers):
        """Create a TEST customer, post 2 sales, fetch history → stats populated."""
        cust_payload = {"name": f"TEST_HistCust_{uuid.uuid4().hex[:5]}", "phone": "9999999999"}
        c = requests.post(f"{BASE_URL}/api/customers", headers=admin_headers, json=cust_payload).json()
        cid = c["id"]

        prods = requests.get(f"{BASE_URL}/api/products", headers=admin_headers).json()
        p = next((x for x in prods if x.get("stock_qty", 0) >= 2), prods[0])

        sale_payload = {
            "customer_id": cid, "customer_name": c["name"],
            "items": [{
                "product_id": p["id"], "name": p["name"], "sku": p["sku"],
                "quantity": 1, "unit_price": p["sale_price"], "gst_percent": p["gst_percent"],
                "discount": 0, "line_total": 0,
            }],
            "discount_total": 0, "payment_method": "cash",
        }
        s1 = requests.post(f"{BASE_URL}/api/sales", headers=admin_headers, json=sale_payload)
        assert s1.status_code == 200, s1.text
        s2 = requests.post(f"{BASE_URL}/api/sales", headers=admin_headers, json=sale_payload)
        assert s2.status_code == 200, s2.text

        r = requests.get(f"{BASE_URL}/api/customers/{cid}/history", headers=admin_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["customer"]["id"] == cid
        assert body["stats"]["total_orders"] == 2
        assert body["stats"]["total_spent"] > 0
        assert body["stats"]["avg_order_value"] > 0
        assert body["stats"]["last_visit"] is not None
        assert len(body["sales"]) == 2

        # Cleanup
        requests.delete(f"{BASE_URL}/api/customers/{cid}", headers=admin_headers)

    def test_history_not_in_store_404(self, admin_headers):
        r = requests.get(f"{BASE_URL}/api/customers/{uuid.uuid4()}/history", headers=admin_headers)
        assert r.status_code == 404

    def test_history_unauth(self):
        r = requests.get(f"{BASE_URL}/api/customers/{uuid.uuid4()}/history")
        assert r.status_code == 401
