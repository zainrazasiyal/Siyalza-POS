import os
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, List

import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
API_SECRET_KEY = os.environ["API_SECRET_KEY"]

app = FastAPI(title="Siyalza POS Cloud API")

# ---------------------------------------------------------------
# Simple in-memory session store: token -> (shop_id, expiry_time)
# Restart hone par sab log out ho jayenge (login dobara karna hoga)
# ---------------------------------------------------------------
SESSIONS = {}
SESSION_TTL_SECONDS = 60 * 60 * 12  # 12 ghante

def get_conn():
    return psycopg2.connect(DATABASE_URL)

def new_session(shop_id: str) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = (shop_id, time.time() + SESSION_TTL_SECONDS)
    return token

def verify_session(token: str, shop_id: str):
    entry = SESSIONS.get(token)
    if not entry:
        raise HTTPException(401, "Invalid or expired session token")
    sess_shop_id, expiry = entry
    if time.time() > expiry:
        SESSIONS.pop(token, None)
        raise HTTPException(401, "Session expired, please log in again")
    if sess_shop_id != shop_id:
        raise HTTPException(403, "Token does not belong to this shop")

def hash_password(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# =================================================================
# MODELS
# =================================================================
class LicenseCheckRequest(BaseModel):
    hwid: str

class LoginRequest(BaseModel):
    username: str
    password: str

class SaleItem(BaseModel):
    sale_date: str
    items: str
    total_amount: float
    payment_method: str

class SalesUploadRequest(BaseModel):
    token: str
    shop_id: str
    sales: List[SaleItem]

class StaffItem(BaseModel):
    staff_id: int
    staff_name: str
    designation: Optional[str] = ""
    phone: Optional[str] = ""
    monthly_salary: float
    next_due_date: Optional[str] = ""
    last_paid_date: Optional[str] = ""

class StaffUploadRequest(BaseModel):
    token: str
    shop_id: str
    staff: List[StaffItem]

class PaymentItem(BaseModel):
    payment_id: int
    staff_id: int
    staff_name: str
    payment_date: str
    amount: float
    next_due_date: Optional[str] = ""
    note: Optional[str] = ""

class PaymentsUploadRequest(BaseModel):
    token: str
    shop_id: str
    payments: List[PaymentItem]

class CustomerItem(BaseModel):
    phone: str
    name: str
    address: Optional[str] = ""

class CustomersUploadRequest(BaseModel):
    token: str
    shop_id: str
    customers: List[CustomerItem]

class DeleteSaleRequest(BaseModel):
    token: str
    shop_id: str
    sale_id: int

class ShopOnlyRequest(BaseModel):
    token: str
    shop_id: str


# =================================================================
# LICENSE
# =================================================================
@app.post("/license/check")
def license_check(req: LicenseCheckRequest):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT is_approved, is_blocked, expiry_date FROM terminal_license WHERE hwid_hash = %s",
            (req.hwid,),
        )
        row = cur.fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO terminal_license (hwid_hash, is_approved, expiry_date) "
                "VALUES (%s, false, CURRENT_DATE + INTERVAL '30 days')",
                (req.hwid,),
            )
            conn.commit()
            return {"found": False, "approved": False, "blocked": False, "expiry_date": None}
        return {
            "found": True,
            "approved": row["is_approved"],
            "blocked": row["is_blocked"],
            "expiry_date": row["expiry_date"].isoformat() if row["expiry_date"] else None,
        }
    finally:
        conn.close()


# =================================================================
# LOGIN
# =================================================================
@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT shop_id, password_hash, shop_display_name, is_active "
            "FROM shop_accounts WHERE username = %s",
            (req.username,),
        )
        row = cur.fetchone()
        if not row or not row["is_active"]:
            raise HTTPException(401, "Invalid username or password")
        if row["password_hash"] != hash_password(req.password):
            raise HTTPException(401, "Invalid username or password")

        shop_id = str(row["shop_id"])
        token = new_session(shop_id)
        return {
            "shop_id": shop_id,
            "shop_display_name": row["shop_display_name"],
            "token": token,
        }
    finally:
        conn.close()


# =================================================================
# UPLOAD (End of Day batch sync)
# =================================================================
@app.post("/sales/upload")
def upload_sales(req: SalesUploadRequest):
    verify_session(req.token, req.shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        for s in req.sales:
            cur.execute(
                "INSERT INTO shop_sales_ledger (shop_id, sale_date, items, total_amount, payment_method) "
                "VALUES (%s, %s, %s, %s, %s)",
                (req.shop_id, s.sale_date, s.items, s.total_amount, s.payment_method),
            )
        conn.commit()
        return {"uploaded": len(req.sales)}
    finally:
        conn.close()


@app.post("/staff/upload")
def upload_staff(req: StaffUploadRequest):
    verify_session(req.token, req.shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        for s in req.staff:
            cur.execute(
                """
                INSERT INTO shop_staff (staff_id, shop_id, staff_name, designation, phone,
                                         monthly_salary, next_due_date, last_paid_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (shop_id, staff_id) DO UPDATE SET
                    staff_name = EXCLUDED.staff_name,
                    designation = EXCLUDED.designation,
                    phone = EXCLUDED.phone,
                    monthly_salary = EXCLUDED.monthly_salary,
                    next_due_date = EXCLUDED.next_due_date,
                    last_paid_date = EXCLUDED.last_paid_date
                """,
                (s.staff_id, req.shop_id, s.staff_name, s.designation, s.phone,
                 s.monthly_salary, s.next_due_date, s.last_paid_date),
            )
        conn.commit()
        return {"uploaded": len(req.staff)}
    finally:
        conn.close()


@app.post("/staff-payments/upload")
def upload_payments(req: PaymentsUploadRequest):
    verify_session(req.token, req.shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        for p in req.payments:
            cur.execute(
                """
                INSERT INTO shop_staff_salary_payments (payment_id, shop_id, staff_id, staff_name,
                                                         payment_date, amount, next_due_date, note)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (shop_id, payment_id) DO UPDATE SET
                    staff_name = EXCLUDED.staff_name,
                    payment_date = EXCLUDED.payment_date,
                    amount = EXCLUDED.amount,
                    next_due_date = EXCLUDED.next_due_date,
                    note = EXCLUDED.note
                """,
                (p.payment_id, req.shop_id, p.staff_id, p.staff_name,
                 p.payment_date, p.amount, p.next_due_date, p.note),
            )
        conn.commit()
        return {"uploaded": len(req.payments)}
    finally:
        conn.close()


@app.post("/customers/upload")
def upload_customers(req: CustomersUploadRequest):
    verify_session(req.token, req.shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        for c in req.customers:
            cur.execute(
                """
                INSERT INTO shop_customers (shop_id, phone, name, address)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (shop_id, phone) DO UPDATE SET
                    name = EXCLUDED.name, address = EXCLUDED.address
                """,
                (req.shop_id, c.phone, c.name, c.address),
            )
        conn.commit()
        return {"uploaded": len(req.customers)}
    finally:
        conn.close()


# =================================================================
# DELETE
# =================================================================
@app.post("/sales/delete-one")
def delete_one_sale(req: DeleteSaleRequest):
    verify_session(req.token, req.shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM shop_sales_ledger WHERE shop_id = %s AND sale_id = %s",
            (req.shop_id, req.sale_id),
        )
        conn.commit()
        return {"deleted": True}
    finally:
        conn.close()


@app.post("/sales/delete-all")
def delete_all_sales(req: ShopOnlyRequest):
    verify_session(req.token, req.shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM shop_sales_ledger WHERE shop_id = %s", (req.shop_id,))
        conn.commit()
        return {"deleted": True}
    finally:
        conn.close()


# =================================================================
# RESTORE (pull down from cloud)
# =================================================================
@app.get("/restore/sales")
def restore_sales(shop_id: str, token: str):
    verify_session(token, shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT sale_id, sale_date, items, total_amount, payment_method "
            "FROM shop_sales_ledger WHERE shop_id = %s ORDER BY sale_id",
            (shop_id,),
        )
        return {"rows": cur.fetchall()}
    finally:
        conn.close()


@app.get("/restore/staff")
def restore_staff(shop_id: str, token: str):
    verify_session(token, shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT staff_id, staff_name, designation, phone, monthly_salary, "
            "next_due_date, last_paid_date FROM shop_staff WHERE shop_id = %s",
            (shop_id,),
        )
        return {"rows": cur.fetchall()}
    finally:
        conn.close()


@app.get("/restore/staff-payments")
def restore_payments(shop_id: str, token: str):
    verify_session(token, shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT payment_id, staff_id, staff_name, payment_date, amount, "
            "next_due_date, note FROM shop_staff_salary_payments WHERE shop_id = %s",
            (shop_id,),
        )
        return {"rows": cur.fetchall()}
    finally:
        conn.close()


@app.get("/restore/customers")
def restore_customers(shop_id: str, token: str):
    verify_session(token, shop_id)
    conn = get_conn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT phone, name, address FROM shop_customers WHERE shop_id = %s",
            (shop_id,),
        )
        return {"rows": cur.fetchall()}
    finally:
        conn.close()
