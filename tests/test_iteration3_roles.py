"""
Iteration 3 backend tests for KKP Stores:
- Low-stock alerts endpoint (admin + manager can view)
- Role gating: manager 403 on delete + export/template endpoints
- Manager allowed: create/update products, import, list, POS sales
- Admin regression: still 200 on the same delete/export endpoints
"""
import os
import uuid
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"


# ---------------- fixtures ----------------
@pytest.fixture(scope="session")
def admin_token():
    r = requests.post(f"{API}/auth/login", json={"email": "admin@kkpstores.com", "password": "admin123"})
    assert r.status_code == 200, f"admin login failed: {r.status_code} {r.text}"
    return r.json()["token"]


@pytest.fixture(scope="session")
def manager_token(admin_token):
    # Ensure manager exists; if not, create via admin
    r = requests.post(f"{API}/auth/login", json={"email": "manager@kkpstores.com", "password": "manager123"})
    if r.status_code != 200:
        # create using admin
        h = {"Authorization": f"Bearer {admin_token}"}
        cr = requests.post(
            f"{API}/users",
            headers=h,
            json={"email": "manager@kkpstores.com", "password": "manager123",
                  "full_name": "Test Manager", "role": "manager"},
        )
        assert cr.status_code in (200, 201), f"manager create failed: {cr.status_code} {cr.text}"
        r = requests.post(f"{API}/auth/login", json={"email": "manager@kkpstores.com", "password": "manager123"})
    assert r.status_code == 200, f"manager login failed: {r.status_code} {r.text}"
    return r.json()["token"]


def H(t):
    return {"Authorization": f"Bearer {t}"}


# ---------------- low stock alerts ----------------
class TestLowStockAlerts:
    def test_admin_can_view(self, admin_token):
        r = requests.get(f"{API}/alerts/low-stock", headers=H(admin_token))
        assert r.status_code == 200, r.text
        data = r.json()
        assert "count" in data and "out_of_stock_count" in data and "items" in data
        assert isinstance(data["items"], list)
        assert data["count"] == len(data["items"])
        assert isinstance(data["count"], int)

    def test_manager_can_view(self, manager_token):
        r = requests.get(f"{API}/alerts/low-stock", headers=H(manager_token))
        assert r.status_code == 200, r.text
        data = r.json()
        assert "count" in data and "items" in data


# ---------------- manager role gating: forbidden ----------------
class TestManagerForbidden:
    @pytest.fixture(scope="class")
    def sample_product_id(self, admin_token):
        # create a product via admin so we have something to attempt delete on
        sku = f"TEST_MGRDEL_{uuid.uuid4().hex[:6]}"
        r = requests.post(
            f"{API}/products",
            headers=H(admin_token),
            json={"name": "MgrDel Prod", "sku": sku, "category": "Test", "unit": "pcs",
                  "purchase_price": 10, "sale_price": 20, "gst_percent": 0,
                  "stock_qty": 1, "low_stock_threshold": 0},
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["id"]

    @pytest.fixture(scope="class")
    def sample_customer_id(self, admin_token):
        r = requests.post(
            f"{API}/customers",
            headers=H(admin_token),
            json={"name": f"TEST_MgrCust_{uuid.uuid4().hex[:5]}", "phone": "9999999999"},
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["id"]

    @pytest.fixture(scope="class")
    def sample_supplier_id(self, admin_token):
        r = requests.post(
            f"{API}/suppliers",
            headers=H(admin_token),
            json={"name": f"TEST_MgrSup_{uuid.uuid4().hex[:5]}", "phone": "8888888888"},
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["id"]

    def test_manager_cannot_delete_product(self, manager_token, sample_product_id):
        r = requests.delete(f"{API}/products/{sample_product_id}", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_delete_customer(self, manager_token, sample_customer_id):
        r = requests.delete(f"{API}/customers/{sample_customer_id}", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_delete_supplier(self, manager_token, sample_supplier_id):
        r = requests.delete(f"{API}/suppliers/{sample_supplier_id}", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_export_products(self, manager_token):
        r = requests.get(f"{API}/products/export", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_download_products_template(self, manager_token):
        r = requests.get(f"{API}/products/template", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_export_customers(self, manager_token):
        r = requests.get(f"{API}/customers/export", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_download_customers_template(self, manager_token):
        r = requests.get(f"{API}/customers/template", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_export_suppliers(self, manager_token):
        r = requests.get(f"{API}/suppliers/export", headers=H(manager_token))
        assert r.status_code == 403, r.text

    def test_manager_cannot_download_suppliers_template(self, manager_token):
        r = requests.get(f"{API}/suppliers/template", headers=H(manager_token))
        assert r.status_code == 403, r.text


# ---------------- manager role gating: allowed ----------------
class TestManagerAllowed:
    def test_manager_can_list_products(self, manager_token):
        r = requests.get(f"{API}/products", headers=H(manager_token))
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), list)

    def test_manager_can_create_product(self, manager_token):
        sku = f"TEST_MGRCREATE_{uuid.uuid4().hex[:6]}"
        payload = {"name": "Mgr Create", "sku": sku, "category": "Test", "unit": "pcs",
                   "purchase_price": 5, "sale_price": 10, "gst_percent": 0,
                   "stock_qty": 5, "low_stock_threshold": 1}
        r = requests.post(f"{API}/products", headers=H(manager_token), json=payload)
        assert r.status_code in (200, 201), r.text
        data = r.json()
        assert data["sku"] == sku
        # GET verify
        g = requests.get(f"{API}/products", headers=H(manager_token))
        assert any(p.get("sku") == sku for p in g.json())

    def test_manager_can_update_product(self, manager_token):
        sku = f"TEST_MGRUPD_{uuid.uuid4().hex[:6]}"
        cr = requests.post(f"{API}/products", headers=H(manager_token),
                           json={"name": "Upd Me", "sku": sku, "category": "T", "unit": "pcs",
                                 "purchase_price": 1, "sale_price": 2, "gst_percent": 0,
                                 "stock_qty": 1, "low_stock_threshold": 0})
        assert cr.status_code in (200, 201), cr.text
        pid = cr.json()["id"]
        ur = requests.put(f"{API}/products/{pid}", headers=H(manager_token),
                          json={"name": "Upd Me 2", "sku": sku, "category": "T", "unit": "pcs",
                                "purchase_price": 1, "sale_price": 3, "gst_percent": 0,
                                "stock_qty": 2, "low_stock_threshold": 0})
        assert ur.status_code == 200, ur.text
        assert ur.json()["name"] == "Upd Me 2"

    def test_manager_can_import_dry_run(self, manager_token):
        csv_data = ("name,sku,category,unit,purchase_price,sale_price,gst_percent,stock_qty,low_stock_threshold\n"
                    f"TEST_MgrImp,TEST_MGRIMP_{uuid.uuid4().hex[:5]},Cat,pcs,1,2,0,3,1\n")
        files = {"file": ("import.csv", csv_data, "text/csv")}
        r = requests.post(f"{API}/products/import?dry_run=true", headers=H(manager_token), files=files)
        assert r.status_code == 200, r.text

    def test_manager_can_import_commit(self, manager_token):
        sku = f"TEST_MGRIMPC_{uuid.uuid4().hex[:5]}"
        csv_data = ("name,sku,category,unit,purchase_price,sale_price,gst_percent,stock_qty,low_stock_threshold\n"
                    f"TEST_MgrImpC,{sku},Cat,pcs,1,2,0,3,1\n")
        files = {"file": ("import.csv", csv_data, "text/csv")}
        r = requests.post(f"{API}/products/import?dry_run=false", headers=H(manager_token), files=files)
        assert r.status_code == 200, r.text

    def test_manager_can_view_low_stock_alerts(self, manager_token):
        r = requests.get(f"{API}/alerts/low-stock", headers=H(manager_token))
        assert r.status_code == 200


# ---------------- admin regression ----------------
class TestAdminAllowed:
    def test_admin_can_export_products(self, admin_token):
        r = requests.get(f"{API}/products/export", headers=H(admin_token))
        assert r.status_code == 200, r.text
        assert "text/csv" in r.headers.get("content-type", "")

    def test_admin_can_download_products_template(self, admin_token):
        r = requests.get(f"{API}/products/template", headers=H(admin_token))
        assert r.status_code == 200, r.text

    def test_admin_can_export_customers(self, admin_token):
        r = requests.get(f"{API}/customers/export", headers=H(admin_token))
        assert r.status_code == 200, r.text

    def test_admin_can_download_customers_template(self, admin_token):
        r = requests.get(f"{API}/customers/template", headers=H(admin_token))
        assert r.status_code == 200, r.text

    def test_admin_can_export_suppliers(self, admin_token):
        r = requests.get(f"{API}/suppliers/export", headers=H(admin_token))
        assert r.status_code == 200, r.text

    def test_admin_can_download_suppliers_template(self, admin_token):
        r = requests.get(f"{API}/suppliers/template", headers=H(admin_token))
        assert r.status_code == 200, r.text

    def test_admin_can_delete_product(self, admin_token):
        sku = f"TEST_ADMDEL_{uuid.uuid4().hex[:6]}"
        cr = requests.post(f"{API}/products", headers=H(admin_token),
                           json={"name": "AdmDel", "sku": sku, "category": "T", "unit": "pcs",
                                 "purchase_price": 1, "sale_price": 2, "gst_percent": 0,
                                 "stock_qty": 1, "low_stock_threshold": 0})
        assert cr.status_code in (200, 201)
        pid = cr.json()["id"]
        dr = requests.delete(f"{API}/products/{pid}", headers=H(admin_token))
        assert dr.status_code in (200, 204), dr.text

    def test_admin_can_delete_customer(self, admin_token):
        cr = requests.post(f"{API}/customers", headers=H(admin_token),
                           json={"name": f"TEST_AdmDelC_{uuid.uuid4().hex[:5]}", "phone": "1111111111"})
        assert cr.status_code in (200, 201)
        cid = cr.json()["id"]
        dr = requests.delete(f"{API}/customers/{cid}", headers=H(admin_token))
        assert dr.status_code in (200, 204), dr.text

    def test_admin_can_delete_supplier(self, admin_token):
        cr = requests.post(f"{API}/suppliers", headers=H(admin_token),
                           json={"name": f"TEST_AdmDelS_{uuid.uuid4().hex[:5]}", "phone": "2222222222"})
        assert cr.status_code in (200, 201)
        sid = cr.json()["id"]
        dr = requests.delete(f"{API}/suppliers/{sid}", headers=H(admin_token))
        assert dr.status_code in (200, 204), dr.text
