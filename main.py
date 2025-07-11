#!/usr/bin/env python3

import os
import random
import string
import asyncio
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential
from pydantic import BaseModel
import json
from cryptography.fernet import Fernet
from prometheus_client import Counter, Gauge, start_http_server
import asyncpg
from celery import Celery
import base64
from typing import Dict, Optional, Tuple, List
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from fake_useragent import UserAgent
import re
import imaplib
import email
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import sqlite3
from telegram import Bot
from telegram.ext import Application, CommandHandler
from datetime import datetime
import hashlib
import hmac
from dotenv import load_dotenv, set_key
from contextlib import asynccontextmanager
from collections import deque
import logging
from asgiref.sync import async_to_sync

# --- Logging Configuration ---
class SensitiveDataFilter(logging.Filter):
    """Filter sensitive data from logs."""
    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = re.sub(r'[\w\.-]+@[\w\.-]+', '[REDACTED_EMAIL]', record.msg)
            record.msg = re.sub(r'password=[^\s]*', 'password=[REDACTED]', record.msg)
            record.msg = re.sub(r'token=[^\s]*', 'token=[REDACTED]', record.msg)
        return True

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)
logger = structlog.get_logger()
logger.addFilter(SensitiveDataFilter())

# --- Metrics Configuration ---
start_http_server(8002)
REQUESTS_TOTAL = Counter("requests_total", "Total requests")
ACCOUNTS_CREATED = Gauge("accounts_created", "Number of accounts created", ["platform"])
PAYMENTS_PROCESSED = Counter("payments_processed", "Total payments processed", ["provider"])
LISTINGS_ACTIVE = Gauge("listings_active", "Active listings", ["platform"])
ORDERS_FULFILLED = Counter("orders_fulfilled", "Orders fulfilled", ["platform"])

# --- Celery Setup ---
app_celery = Celery("dropshipping", broker="redis://redis:6379/0", backend="redis://redis:6379/1")
app_celery.conf.task_reject_on_worker_lost = True
app_celery.conf.task_acks_late = True

# --- FastAPI Setup ---
app = FastAPI()

# --- Telegram Bot Setup ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "7386307537:AAH_4rEoqE_WVyySz5aEoZ36a7iZ6Y3QWPg")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "5993436837")
bot = Bot(TELEGRAM_BOT_TOKEN)
application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
RUNNING = True

# --- Configuration ---
class Config:
    """Configuration class for the application."""
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "your_secure_password")
    DB_NAME = os.getenv("DB_NAME", "dropshipping")
    DB_HOST = os.getenv("DB_HOST", "postgres")
    CAPTCHA_API_KEY = os.getenv("CAPTCHA_API_KEY", "79aecd3e952f7ccc567a0e8643250159")
    TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID", "SK41e5e443ec313bbd3a50a31af3c9898b")
    TWILIO_API_KEY = os.getenv("TWILIO_API_KEY", "2hfkF0qpDcP78Nj2qqPNYbD1mw6Yl4EZ")
    CJ_API_KEY = os.getenv("CJ_API_KEY", "c442a948bad74c118dd2a718a30be41e")
    CJ_SECRET_KEY = os.getenv("CJ_SECRET_KEY", "434e72487e8441a43ca6f05fed60f9a5b9aa002a2e740d2b6a43ac8983e1b9dd")
    PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "AXS10dizgyGuUJ0U06sF7")
    PAYPAL_SECRET = os.getenv("PAYPAL_SECRET", "EImf7uyqqCqsE1-SaVq688NsyRIA6fmrjka5V15A03RrlxoX2Z4fAb5pq5X_TyZg62jVkR1g2OnFX-EL")
    PAYPAL_EMAIL = os.getenv("PAYPAL_EMAIL", "jefftayler@live.ca")
    BTC_WALLET = os.getenv("BTC_WALLET", "bc1q3mwnpa8ndqznyylgtgn8p329qh7g7vhzukdl5t")
    ETH_WALLET = os.getenv("ETH_WALLET", "0x7A51478775722a4faa72b966134a4c47BF6BA60E")
    SUPPLIERS = ["CJ Dropshipping", "Walmart", "Best Buy"]
    RETAIL_SUPPLIERS = ["Walmart", "Best Buy"]
    WHOLESALE_SUPPLIERS = ["CJ Dropshipping"]
    PLATFORMS = ["eBay", "Amazon", "Walmart", "Etsy", "Shopify"]
    BANKING = ["Paypal"]
    NUM_ACCOUNTS_PER_PLATFORM = 2
    PROFIT_MARGIN = 3.0
    PRICE_RANGE = (50, 150)
    MAX_LISTINGS_PER_ACCOUNT = 10
    RETAIL_LISTING_PERCENT = 0.2
    WHOLESALE_LISTING_PERCENT = 0.8
    RATE_LIMIT_DELAY = 2.0
    TEST_ORDERS = 2
    DAILY_ACCOUNT_CREATION_LIMIT = 2
    REINVESTMENT_RATE = 0.3
    PROFIT_THRESHOLD = 2000
    BAN_THRESHOLD = 0.2
    GCP_PROJECT = os.getenv("GCP_PROJECT_ID", "affable-alpha-461019-g8")
    JOB_LOCATION = "us-central1"
    SERVICE_URL = os.getenv("SERVICE_URL")
    WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "supersecretwebhook123")
    ENVIRONMENT = os.getenv("ENVIRONMENT", "production")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "info")

config = Config()

# --- Database Module ---
db_pool = None

async def init_db():
    """Initialize the PostgreSQL database tables."""
    global db_pool
    if db_pool is None:
        db_pool = await asyncpg.create_pool(
            user=config.DB_USER,
            password=config.DB_PASSWORD,
            database=config.DB_NAME,
            host=config.DB_HOST
        )
        async with db_pool.acquire() as conn:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS email_accounts (
                    email TEXT PRIMARY KEY,
                    password TEXT
                )
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS supplier_accounts (
                    supplier TEXT,
                    email TEXT PRIMARY KEY,
                    password TEXT,
                    api_key TEXT,
                    terms TEXT
                )
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS platform_accounts (
                    platform TEXT,
                    email TEXT,
                    username TEXT PRIMARY KEY,
                    password TEXT,
                    token TEXT,
                    status TEXT
                )
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS payment_accounts (
                    email TEXT PRIMARY KEY,
                    type TEXT,
                    password TEXT,
                    api_key TEXT
                )
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS listings (
                    sku TEXT PRIMARY KEY,
                    platform TEXT,
                    title TEXT,
                    price FLOAT,
                    cost FLOAT,
                    status TEXT,
                    type TEXT
                )
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS orders (
                    order_id TEXT PRIMARY KEY,
                    platform TEXT,
                    source_sku TEXT,
                    buyer_name TEXT,
                    buyer_address TEXT,
                    status TEXT,
                    source TEXT,
                    tracking_number TEXT,
                    fulfilled_at TIMESTAMP
                )
            ''')
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS profits (
                    id SERIAL PRIMARY KEY,
                    revenue REAL,
                    cost REAL,
                    profit REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        logger.info("Database initialized")

async def init_dashboard_db():
    """Initialize the SQLite dashboard database."""
    async def _init_dashboard_db():
        conn = sqlite3.connect("dashboard.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            accounts INTEGER,
            listings INTEGER,
            orders INTEGER,
            revenue REAL,
            profit REAL,
            timestamp TEXT
        )''')
        conn.commit()
        conn.close()
    await asyncio.to_thread(_init_dashboard_db)

# --- Utilities Module ---
ua = UserAgent()
executor = ThreadPoolExecutor(max_workers=10)

async def get_random_user_agent() -> str:
    """Return a random user agent string."""
    return await asyncio.to_thread(ua.random)

async def generate_email() -> str:
    """Generate a random Gmail address."""
    return await asyncio.to_thread(lambda: f"{''.join(random.choices(string.ascii_lowercase + string.digits, k=10))}@gmail.com")

async def get_virtual_phone() -> str:
    """Fetch a virtual phone number using Twilio."""
    REQUESTS_TOTAL.inc()
    auth = base64.b64encode(f"{config.TWILIO_SID}:{config.TWILIO_API_KEY}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}"}
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{config.TWILIO_SID}/IncomingPhoneNumbers.json",
            data={"AreaCode": random.choice(["555", "844"])}
        ) as resp:
            if resp.status == 201:
                data = await resp.json()
                return data["phone_number"]
            elif resp.status == 429:
                logger.warning("Twilio rate limit exceeded, retrying")
                raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=429)
            else:
                logger.exception(f"Twilio phone fetch failed, status {resp.status}")
                return f"+1555{random.randint(1000000, 9999999)}"

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
async def solve_captcha(site_key: str, url: str) -> Optional[str]:
    """Solve a CAPTCHA using 2Captcha API with retry on failure."""
    REQUESTS_TOTAL.inc()
    async with aiohttp.ClientSession() as session:
        captcha_url = "http://api.2captcha.com/in.php"
        params = {
            "key": config.CAPTCHA_API_KEY,
            "method": "userrecaptcha",
            "googlekey": site_key,
            "pageurl": url
        }
        async with session.post(captcha_url, data=params) as resp:
            text = await resp.text()
            if "OK" not in text:
                logger.exception(f"CAPTCHA submit failed, status {resp.status}")
                return None
            captcha_id = text.split("|")[1]
            for _ in range(10):
                await asyncio.sleep(5)
                async with session.get(f"http://api.2captcha.com/res.php?key={config.CAPTCHA_API_KEY}&action=get&id={captcha_id}") as check_resp:
                    check_text = await check_resp.text()
                    if "OK" in check_text:
                        return check_text.split("|")[1]
                    elif "ERROR" in check_text:
                        logger.exception("CAPTCHA error")
                        return None
                    await asyncio.sleep(1)
            logger.exception("CAPTCHA timeout after retries")
            return None

async def fetch_otp(email: str, password: str, subject_filter: str = "verification") -> str:
    """Fetch OTP from email."""
    REQUESTS_TOTAL.inc()
    async def _fetch_otp() -> str:
        try:
            mail = imaplib.IMAP4_SSL("imap.gmail.com")
            mail.login(email, password)
            mail.select("inbox")
            for _ in range(15):
                status, messages = mail.search(None, f'(UNSEEN SUBJECT "{subject_filter}")')
                if status == "OK" and messages[0]:
                    latest_email_id = messages[0].split()[-1]
                    _, msg_data = mail.fetch(latest_email_id, "(RFC822)")
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            otp = re.search(r'\b\d{6}\b', body)
                            if otp:
                                mail.store(latest_email_id, '+FLAGS', '\\Seen')
                                mail.logout()
                                return otp.group()
                time.sleep(5)
            mail.logout()
            raise Exception("OTP retrieval failed after 15 attempts")
        except imaplib.IMAP4.error as e:
            logger.exception("IMAP authentication failed")
            return "mock_otp"
        except Exception as e:
            logger.exception("OTP fetch failed")
            return "mock_otp"
    return await asyncio.to_thread(_fetch_otp)

async def create_webdriver(chrome_options: Options) -> webdriver.Chrome:
    """Create a WebDriver instance in a thread pool."""
    return await asyncio.to_thread(lambda: webdriver.Chrome(
        service=Service(ChromeDriverManager().install()),
        options=chrome_options
    ))

async def human_like_typing(element, text: str) -> None:
    """Simulate human-like typing into a Selenium element."""
    async def _human_like_typing_sync(element, text: str) -> None:
        for char in text:
            element.send_keys(char)
            time.sleep(random.uniform(0.05, 0.3))
            if random.random() > 0.8:
                element.send_keys(Keys.BACKSPACE)
                time.sleep(0.5)
                element.send_keys(char)
    await asyncio.to_thread(_human_like_typing_sync, element, text)

# --- Proxy Manager ---
class ProxyManager:
    def __init__(self):
        self.proxies: deque = deque()
        self.failed_proxies: set = set()
        self.session_proxies: Dict[str, str] = {}

    async def init(self) -> None:
        self.proxies = deque(await self.fetch_proxy_list())

    async def fetch_proxy_list(self) -> List[str]:
        REQUESTS_TOTAL.inc()
        async with aiohttp.ClientSession() as session:
            url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
            await asyncio.sleep(config.RATE_LIMIT_DELAY)
            async with session.get(url) as resp:
                if resp.status == 200:
                    proxies = (await resp.text()).splitlines()
                    return proxies[:50]
                logger.exception(f"Proxy fetch failed, status {resp.status}")
                return []

    def rotate(self, session_id: str) -> Dict[str, str]:
        available_proxies = [p for p in self.proxies if p not in self.failed_proxies]
        if not available_proxies:
            logger.warning("All proxies failed, resetting")
            self.failed_proxies.clear()
            available_proxies = list(self.proxies)
        if session_id not in self.session_proxies:
            self.session_proxies[session_id] = available_proxies[0]
            self.proxies.rotate(-1)
        proxy = self.session_proxies[session_id]
        return {'http': f'http://{proxy}', 'https': f'http://{proxy}'}

    def mark_failed(self, proxy: str) -> None:
        self.failed_proxies.add(proxy)
        logger.info(f"Marked proxy as failed: {proxy}")

proxy_manager = ProxyManager()

# --- Secrets Manager ---
class SecretsManager:
    """Manage encrypted secrets storage."""
    def __init__(self, key_file: str = "secret.key"):
        if not os.path.exists(key_file):
            self.key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(self.key)
        else:
            with open(key_file, "rb") as f:
                self.key = f.read()
        self.cipher = Fernet(self.key)

    def save_secrets(self, secrets: Dict, secrets_file: str = "secrets.enc") -> None:
        """Encrypt and save secrets to file and environment."""
        def _save_secrets():
            encrypted = self.cipher.encrypt(json.dumps(secrets).encode())
            with open(secrets_file, "wb") as f:
                f.write(encrypted)
            with open("secrets.json", "w") as f:
                json.dump(secrets, f, indent=2)
            for key, value in secrets.items():
                set_key(".env", key.upper(), str(value))
            logger.info(f"Saved secrets to {secrets_file}, secrets.json, and .env")
        asyncio.get_running_loop().run_in_executor(None, _save_secrets)

secrets_manager = SecretsManager()

# --- Account Creation Tasks ---
@app_celery.task(bind=True)
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
def create_gmail_account(self) -> Tuple[str, str]:
    """Create a new Gmail account."""
    @async_to_sync
    async def _create_gmail() -> Tuple[str, str]:
        email = await generate_email()
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        phone = await get_virtual_phone()
        signup_url = "https://accounts.google.com/signup/v2/webcreateaccount"
        site_key = "6LeTnxkTAAAAAN9QEuDfp67ZNKsw2XHQ"
        session_id = f"gmail_{email}"

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument(f"user-agent={await get_random_user_agent()}")
        proxy = proxy_manager.rotate(session_id).get("http")
        if proxy:
            chrome_options.add_argument(f"--proxy-server={proxy}")
        driver = await create_webdriver(chrome_options)

        try:
            await asyncio.sleep(random.uniform(2, 5))
            driver.get(signup_url)
            await human_like_typing(driver.find_element(By.ID, "username"), email.split("@")[0])
            await human_like_typing(driver.find_element(By.NAME, "Passwd"), password)
            await human_like_typing(driver.find_element(By.NAME, "PasswdAgain"), password)
            await human_like_typing(driver.find_element(By.ID, "phoneNumberId"), phone)

            captcha_response = await solve_captcha(site_key, signup_url)
            if captcha_response:
                driver.execute_script(f"document.getElementById('g-recaptcha-response').innerHTML='{captcha_response}';")
            else:
                logger.warning("CAPTCHA failed, proceeding without verification")
            driver.find_element(By.ID, "accountDetailsNext").click()
            await asyncio.sleep(random.uniform(2, 5))

            otp = await fetch_otp(email, password)
            await human_like_typing(driver.find_element(By.ID, "code"), otp)
            driver.find_element(By.ID, "next").click()
            await asyncio.sleep(random.uniform(2, 5))

            async with db_pool.acquire() as conn:
                result = await conn.execute(
                    "INSERT OR REPLACE INTO email_accounts (email, password) VALUES ($1, $2)",
                    email, password
                )
                if not result:
                    raise Exception("Failed to insert email account")
            ACCOUNTS_CREATED.labels(platform="gmail").inc()
            secrets = {"GMAIL_EMAIL": email, "GMAIL_PASSWORD": password}
            secrets_manager.save_secrets(secrets)
            await bot.send_message(TELEGRAM_CHAT_ID, "Gmail created: [REDACTED_EMAIL]")
            return email, password
        except Exception as e:
            logger.exception("Gmail creation failed")
            raise
        finally:
            driver.quit()
    return _create_gmail()

@app_celery.task(bind=True)
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
def create_supplier_account(self, supplier: str, gmail_email: str, gmail_password: str) -> Tuple[str, str, Optional[str]]:
    """Create a new supplier account."""
    @async_to_sync
    async def _create_supplier() -> Tuple[str, str, Optional[str]]:
        email = gmail_email
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        phone = await get_virtual_phone()
        urls = {
            "CJ Dropshipping": "https://cjdropshipping.com/register",
            "Walmart": "https://developer.walmart.com/register",
            "Best Buy": "https://developer.bestbuy.com/register"
        }
        terms_urls = {
            "CJ Dropshipping": "https://cjdropshipping.com/apply-net-terms",
            "Walmart": "https://marketplace.walmart.com/apply-terms",
            "Best Buy": "https://developer.bestbuy.com/apply-terms"
        }
        site_keys = {
            "CJ Dropshipping": "6LfD3PIbAAAAAJs_eFHQ2mxmgFRxR5sRK9Q-5R2T",
            "Walmart": "6LeGu-GlAAAAAECmS3dPRM07s1p7ZxZ88oW0GTeD",
            "Best Buy": "6LfD3PIbAAAAAJs_eFHQ2mxmgFRxR5sRK9Q-5R2T"
        }
        session_id = f"supplier_{supplier}_{email}"
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument(f"user-agent={await get_random_user_agent()}")
        proxy = proxy_manager.rotate(session_id).get("http")
        if proxy:
            chrome_options.add_argument(f"--proxy-server={proxy}")
        driver = await create_webdriver(chrome_options)

        try:
            await asyncio.sleep(random.uniform(2, 5))
            driver.get(urls[supplier])
            await human_like_typing(driver.find_element(By.NAME, "email"), email)
            await human_like_typing(driver.find_element(By.NAME, "password"), password)
            await human_like_typing(driver.find_element(By.NAME, "phone"), phone)
            captcha_response = await solve_captcha(site_keys[supplier], urls[supplier])
            if captcha_response:
                driver.execute_script(f"document.getElementById('g-recaptcha-response').innerHTML='{captcha_response}';")
            else:
                logger.warning("CAPTCHA failed, proceeding without verification")
            driver.find_element(By.XPATH, "//button[@type='submit']").click()
            await asyncio.sleep(random.uniform(2, 5))

            otp = await fetch_otp(email, gmail_password)
            await human_like_typing(driver.find_element(By.NAME, "otp"), otp)
            driver.find_element(By.XPATH, "//button[@type='submit']").click()
            await asyncio.sleep(random.uniform(2, 5))

            terms = "Net 30" if random.random() < 0.7 else "Net 45"
            if supplier in terms_urls:
                driver.get(terms_urls[supplier])
                await asyncio.sleep(random.uniform(2, 5))
                await human_like_typing(driver.find_element(By.NAME, "email"), email)
                await human_like_typing(driver.find_element(By.NAME, "business_name"), "AutoDrop LLC")
                await human_like_typing(driver.find_element(By.NAME, "terms"), terms)
                driver.find_element(By.XPATH, "//button[@type='submit']").click()
                await asyncio.sleep(random.uniform(2, 5))

            api_key = await fetch_supplier_api_key(supplier, email, password)
            async with db_pool.acquire() as conn:
                result = await conn.execute(
                    "INSERT OR REPLACE INTO supplier_accounts (supplier, email, password, api_key, terms) VALUES ($1, $2, $3, $4, $5)",
                    supplier, email, password, api_key, terms
                )
                if not result:
                    raise Exception("Failed to insert supplier account")
            ACCOUNTS_CREATED.labels(platform=supplier).inc()
            secrets = {f"{supplier.upper()}_API_KEY": api_key, f"{supplier.upper()}_EMAIL": email, f"{supplier.upper()}_PASSWORD": password}
            secrets_manager.save_secrets(secrets)
            await bot.send_message(TELEGRAM_CHAT_ID, f"{supplier} account created with {terms}: [REDACTED_EMAIL]")
            return email, password, api_key
        except Exception as e:
            logger.exception("Supplier account creation failed")
            raise
        finally:
            driver.quit()
    return _create_supplier()

async def fetch_supplier_api_key(supplier: str, email: str, password: str) -> str:
    """Fetch API key for a supplier."""
    if supplier == "CJ Dropshipping":
        async with aiohttp.ClientSession() as session:
            timestamp = str(int(time.time() * 1000))
            sign = hmac.new(config.CJ_SECRET_KEY.encode(), (config.CJ_API_KEY + timestamp).encode(), hashlib.md5).hexdigest()
            headers = {
                "CJ-Access-Token": config.CJ_API_KEY,
                "CJ-Timestamp": timestamp,
                "CJ-Sign": sign,
                "User-Agent": await get_random_user_agent()
            }
            async with session.get("https://developers.cjdropshipping.com/api2.0/v1/auth", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("api_key", config.CJ_API_KEY)
                elif resp.status == 401:
                    logger.exception("CJ authentication failed")
                else:
                    logger.exception(f"CJ API key fetch failed, status {resp.status}")
    return f"mock_key_{supplier.lower()}"

@app_celery.task(bind=True)
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
def create_platform_account(self, platform: str, index: int, gmail_email: str, gmail_password: str) -> Tuple[str, str]:
    """Create a new platform account."""
    @async_to_sync
    async def _create_platform() -> Tuple[str, str]:
        email = gmail_email
        username = f"{platform.lower()}user{index}{random.randint(100, 999)}"
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        phone = await get_virtual_phone()
        signup_urls = {
            "eBay": "https://signup.ebay.com/pa/register",
            "Amazon": "https://sellercentral.amazon.com/register",
            "Walmart": "https://marketplace.walmart.com/register",
            "Etsy": "https://www.etsy.com/sell",
            "Shopify": "https://www.shopify.com/signup"
        }
        site_keys = {
            "eBay": "6LeGu-GlAAAAAECmS3dPRM07s1p7ZxZ88oW0GTeD",
            "Amazon": "6LeTnxkTAAAAAN9QEuDfp67ZNKsw2XHQ",
            "Walmart": "6LfD3PIbAAAAAJs_eFHQ2mxmgFRxR5sRK9Q-5R2T",
            "Etsy": "6LfD3PIbAAAAAJs_eFHQ2mxmgFRxR5sRK9Q-5R2T",
            "Shopify": "6LeTnxkTAAAAAN9QEuDfp67ZNKsw2XHQ"
        }
        session_id = f"{platform}_{username}"
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument(f"user-agent={await get_random_user_agent()}")
        proxy = proxy_manager.rotate(session_id).get("http")
        if proxy:
            chrome_options.add_argument(f"--proxy-server={proxy}")
        driver = await create_webdriver(chrome_options)

        try:
            await asyncio.sleep(random.uniform(2, 5))
            driver.get(signup_urls[platform])
            await human_like_typing(driver.find_element(By.NAME, "email"), email)
            await human_like_typing(driver.find_element(By.NAME, "password"), password)
            await human_like_typing(driver.find_element(By.NAME, "phone"), phone)
            await human_like_typing(driver.find_element(By.NAME, "firstName"), f"User{index}")
            await human_like_typing(driver.find_element(By.NAME, "lastName"), "Auto")

            captcha_response = await solve_captcha(site_keys[platform], signup_urls[platform])
            if captcha_response:
                driver.execute_script(f"document.getElementById('g-recaptcha-response').innerHTML='{captcha_response}';")
            else:
                logger.warning("CAPTCHA failed, proceeding without verification")
            driver.find_element(By.XPATH, "//button[@type='submit']").click()
            await asyncio.sleep(random.uniform(2, 5))

            otp = await fetch_otp(email, gmail_password)
            await human_like_typing(driver.find_element(By.NAME, "otp"), otp)
            driver.find_element(By.XPATH, "//button[@type='submit']").click()
            await asyncio.sleep(random.uniform(2, 5))

            token = await fetch_platform_token(platform, email, password)
            async with db_pool.acquire() as conn:
                result = await conn.execute(
                    "INSERT OR REPLACE INTO platform_accounts (platform, email, username, password, token, status) VALUES ($1, $2, $3, $4, $5, $6)",
                    platform, email, username, password, token, "active"
                )
                if not result:
                    raise Exception("Failed to insert platform account")
            ACCOUNTS_CREATED.labels(platform=platform).inc()
            secrets = {f"{platform.upper()}_TOKEN": token, f"{platform.upper()}_USERNAME": username, f"{platform.upper()}_PASSWORD": password}
            secrets_manager.save_secrets(secrets)
            await bot.send_message(TELEGRAM_CHAT_ID, f"{platform} account created: {username}")
            return username, token
        except Exception as e:
            logger.exception("Platform account creation failed")
            raise
        finally:
            driver.quit()
    return _create_platform()

async def fetch_platform_token(platform: str, email: str, password: str) -> str:
    """Fetch platform authentication token."""
    if platform == "eBay":
        async with aiohttp.ClientSession() as session:
            auth = base64.b64encode(f"{email}:{password}".encode()).decode()
            headers = {"Authorization": f"Basic {auth}"}
            async with session.post("https://api.ebay.com/identity/v1/oauth2/token", headers=headers, data={"grant_type": "client_credentials"}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("access_token", f"mock_token_{platform.lower()}")
                elif resp.status == 401:
                    logger.exception("eBay authentication failed")
                else:
                    logger.exception(f"eBay token fetch failed, status {resp.status}")
    return f"mock_token_{platform.lower()}"

@app_celery.task(bind=True)
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
def create_banking_account(self, provider: str, gmail_email: str, gmail_password: str) -> Tuple[str, str, str]:
    """Create a new banking account."""
    @async_to_sync
    async def _create_banking() -> Tuple[str, str, str]:
        email = config.PAYPAL_EMAIL if provider == "Paypal" else gmail_email
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        phone = await get_virtual_phone()
        signup_urls = {"Paypal": "https://www.paypal.com/us/webapps/mpp/account-selection"}
        site_keys = {"Paypal": "6Lc8r-wZAAAAAK0xN52gL2zRdvzMJA2wLDpL9pAA"}
        session_id = f"banking_{provider}_{email}"
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument(f"user-agent={await get_random_user_agent()}")
        proxy = proxy_manager.rotate(session_id).get("http")
        if proxy:
            chrome_options.add_argument(f"--proxy-server={proxy}")
        driver = await create_webdriver(chrome_options)

        try:
            await asyncio.sleep(random.uniform(2, 5))
            driver.get(signup_urls[provider])
            await human_like_typing(driver.find_element(By.NAME, "email"), email)
            await human_like_typing(driver.find_element(By.NAME, "password"), password)
            await human_like_typing(driver.find_element(By.NAME, "phone"), phone)

            captcha_response = await solve_captcha(site_keys[provider], signup_urls[provider])
            if captcha_response:
                driver.execute_script(f"document.getElementById('g-recaptcha-response').innerHTML='{captcha_response}';")
            else:
                logger.warning("CAPTCHA failed, proceeding without verification")
            driver.find_element(By.XPATH, "//button[@type='submit']").click()
            await asyncio.sleep(random.uniform(2, 5))

            otp = await fetch_otp(email, gmail_password)
            await human_like_typing(driver.find_element(By.NAME, "otp"), otp)
            driver.find_element(By.XPATH, "//button[@type='submit']").click()
            await asyncio.sleep(random.uniform(2, 5))

            api_key = await fetch_banking_api_key(provider, email, password)
            async with db_pool.acquire() as conn:
                result = await conn.execute(
                    "INSERT OR REPLACE INTO payment_accounts (email, type, password, api_key) VALUES ($1, $2, $3, $4)",
                    email, provider, password, api_key
                )
                if not result:
                    raise Exception("Failed to insert banking account")
            ACCOUNTS_CREATED.labels(platform=provider).inc()
            secrets = {f"{provider.upper()}_API_KEY": api_key, f"{provider.upper()}_EMAIL": email, f"{provider.upper()}_PASSWORD": password}
            secrets_manager.save_secrets(secrets)
            await bot.send_message(TELEGRAM_CHAT_ID, f"{provider} account created: [REDACTED_EMAIL]")
            return email, password, api_key
        except Exception as e:
            logger.exception("Banking account creation failed")
            raise
        finally:
            driver.quit()
    return _create_banking()

async def fetch_banking_api_key(provider: str, email: str, password: str) -> str:
    """Fetch banking API key."""
    if provider == "Paypal":
        return config.PAYPAL_CLIENT_ID
    logger.warning(f"No real API key for {provider}, using mock")
    return f"mock_{provider.lower()}_key"

# --- Product Sourcing and Listing ---
class Product(BaseModel):
    """Model for product data."""
    title: str
    sku: str
    cost: float
    price: float
    url: str
    quantity: int
    source: str
    type: str

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
async def fetch_trending_products(source: str, api_key: str, type: str) -> List[Dict]:
    """Fetch trending products from a supplier."""
    REQUESTS_TOTAL.inc()
    if source == "CJ Dropshipping":
        timestamp = str(int(time.time() * 1000))
        sign = hmac.new(config.CJ_SECRET_KEY.encode(), (config.CJ_API_KEY + timestamp).encode(), hashlib.md5).hexdigest()
        headers = {
            "CJ-Access-Token": api_key,
            "CJ-Timestamp": timestamp,
            "CJ-Sign": sign,
            "User-Agent": await get_random_user_agent()
        }
        params = {"page": 1, "pageSize": config.MAX_LISTINGS_PER_ACCOUNT}
        async with aiohttp.ClientSession(headers=headers) as session:
            await asyncio.sleep(config.RATE_LIMIT_DELAY)
            async with session.get("https://developers.cjdropshipping.com/api2.0/v1/product/list", params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    products = []
                    for item in data.get("data", {}).get("list", []):
                        price = float(item.get("sellPrice", 0))
                        if config.PRICE_RANGE[0] <= price <= config.PRICE_RANGE[1]:
                            products.append(Product(
                                title=item.get("productNameEn", "Unknown"),
                                sku=item.get("pid", f"CJ_{random.randint(1000, 9999)}"),
                                cost=price,
                                price=round(price * config.PROFIT_MARGIN, 2),
                                url=item.get("productUrl", "https://cjdropshipping.com"),
                                quantity=1 if type == "retail" else 10,
                                source=source,
                                type=type
                            ).dict())
                    return products
                elif resp.status == 429:
                    logger.warning("CJ API rate limit exceeded")
                    raise aiohttp.ClientResponseError(resp.request_info, resp.history, status=429)
                else:
                    logger.exception(f"CJ Dropshipping fetch failed, status {resp.status}")
                    return []
    return [
        Product(
            title=f"Mock {source} Product",
            sku=f"{source}_{random.randint(1000, 9999)}",
            cost=50.0,
            price=50.0 * config.PROFIT_MARGIN,
            url=f"https://{source.lower()}.com",
            quantity=1 if type == "retail" else 10,
            source=source,
            type=type
        ).dict()
    ]

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
async def list_product(platform: str, product: Dict, token: str) -> bool:
    """List a product on a platform."""
    try:
        LISTINGS_ACTIVE.labels(platform=platform).inc()
        async with db_pool.acquire() as conn:
            result = await conn.execute(
                "INSERT OR REPLACE INTO listings (sku, platform, title, price, cost, status, type) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                product["sku"], platform, product["title"], product["price"], product["cost"], "active", product["type"]
            )
        if not result:
            raise Exception("Failed to insert listing")
        logger.info(f"Listed {product['title']} on {platform}")
        await bot.send_message(TELEGRAM_CHAT_ID, f"Listed {product['title']} on {platform}")
        return True
    except Exception as e:
        logger.exception(f"Failed to list product on {platform}")
        return False

# --- Order and Payment Processing ---
async def fulfill_order(order_id: str, platform: str, sku: str, buyer_name: str, buyer_address: str, source: str, api_key: str) -> bool:
    """Fulfill an order and update the database."""
    try:
        ORDERS_FULFILLED.labels(platform=platform).inc()
        tracking_number = f"mock_tracking_{order_id}"
        async with db_pool.acquire() as conn:
            result = await conn.execute(
                """
                INSERT OR REPLACE INTO orders (
                    order_id, platform, source_sku, buyer_name, buyer_address,
                    status, source, tracking_number, fulfilled_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
                """,
                order_id, platform, sku, buyer_name, buyer_address, "fulfilled", source, tracking_number
            )
        if not result:
            raise Exception("Failed to insert order")
        await bot.send_message(TELEGRAM_CHAT_ID, f"Order {order_id} fulfilled with tracking: {tracking_number}")
        return True
    except Exception as e:
        logger.exception(f"Order fulfillment failed for {order_id}")
        return False

async def get_paypal_access_token() -> str:
    """Fetch PayPal access token."""
    auth = f"{config.PAYPAL_CLIENT_ID}:{config.PAYPAL_SECRET}"
    headers = {
        "Authorization": f"Basic {base64.b64encode(auth.encode()).decode()}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://api-m.sandbox.paypal.com/v1/oauth2/token",
            headers=headers,
            data={"grant_type": "client_credentials"}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get("access_token", "")
            elif resp.status == 401:
                logger.exception("PayPal authentication failed")
            else:
                logger.exception(f"PayPal token fetch failed, status {resp.status}")
            return ""

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30))
async def process_payment(amount: float, provider: str, api_key: str, destination: str = "final") -> bool:
    """Process a payment using the specified provider."""
    try:
        PAYMENTS_PROCESSED.labels(provider=provider).inc()
        if provider == "Paypal" and destination == "final":
            access_token = await get_paypal_access_token()
            if not access_token:
                logger.exception("Failed to get PayPal access token")
                return False
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            payload = {
                "intent": "sale",
                "payer": {"payment_method": "paypal"},
                "transactions": [
                    {
                        "amount": {"total": f"{amount:.2f}", "currency": "USD"},
                        "description": f"Payment to {config.PAYPAL_EMAIL}"
                    }
                ],
                "redirect_urls": {"return_url": "https://example.com/success", "cancel_url": "https://example.com/cancel"}
            }
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.post(
                    "https://api-m.sandbox.paypal.com/v1/payments/payment",
                    headers=headers,
                    json=payload
                ) as resp:
                    if resp.status == 201:
                        logger.info(f"Processed PayPal payment: ${amount:.2f}")
                        await bot.send_message(TELEGRAM_CHAT_ID, f"PayPal payment: ${amount:.2f}")
                        return True
                    elif resp.status == 400:
                        logger.exception("PayPal invalid request")
                    else:
                        logger.exception(f"PayPal payment failed, status {resp.status}")
                    return False
        elif destination == "crypto":
            logger.info(f"Mock crypto payment: ${amount:.2f} to BTC: {config.BTC_WALLET}")
            await bot.send_message(TELEGRAM_CHAT_ID, f"Mock crypto payment: ${amount:.2f}")
            return True
        logger.info(f"Mock payment: ${amount:.2f} via {provider}")
        await bot.send_message(TELEGRAM_CHAT_ID, f"Mock payment: ${amount:.2f}")
        return True
    except Exception as e:
        logger.exception(f"Payment processing failed")
        return False

async def pay_supplier(source: str, amount: float, api_key: str, terms: str) -> None:
    """Record a payment to a supplier."""
    try:
        logger.info(f"Paid {source} ${amount:.2f} under {terms}")
        await bot.send_message(TELEGRAM_CHAT_ID, f"Paid {source} ${amount:.2f}")
    except Exception as e:
        logger.exception(f"Supplier payment failed")

async def track_profit(revenue: float, cost: float) -> None:
    """Track and store profit data."""
    try:
        profit = revenue - cost
        async with db_pool.acquire() as conn:
            await conn.execute("INSERT INTO profits (revenue, cost, profit) VALUES ($1, $2, $3)", revenue, cost, profit)
            accounts = await conn.fetchval("SELECT COUNT(*) FROM platform_accounts WHERE status = 'active'")
            listings = await conn.fetchval("SELECT COUNT(*) FROM listings WHERE status = 'active'")
            orders = await conn.fetchval("SELECT COUNT(*) FROM orders WHERE status = 'fulfilled'")
            total_revenue = await conn.fetchval("SELECT SUM(revenue) FROM profits") or 0
            total_profit = await conn.fetchval("SELECT SUM(profit) FROM profits") or 0
        async def _update_dashboard():
            conn = sqlite3.connect("dashboard.db")
            c = conn.cursor()
            c.execute("INSERT INTO stats (accounts, listings, orders, revenue, profit, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                     (accounts, listings, orders, total_revenue, total_profit, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        await asyncio.to_thread(_update_dashboard)
        await bot.send_message(TELEGRAM_CHAT_ID, f"Profit update: ${profit:.2f} (Total: ${total_profit:.2f})")
    except Exception as e:
        logger.exception(f"Profit tracking failed")

# --- Telegram Commands ---
async def status(update, context):
    """Send current system status via Telegram."""
    try:
        async with db_pool.acquire() as conn:
            accounts = await conn.fetchval("SELECT COUNT(*) FROM platform_accounts WHERE status = 'active'")
            listings = await conn.fetchval("SELECT COUNT(*) FROM listings WHERE status = 'active'")
            orders = await conn.fetchval("SELECT COUNT(*) FROM orders WHERE status = 'fulfilled'")
            profit = await conn.fetchval("SELECT SUM(profit) FROM profits") or 0
        msg = f"Status:\nAccounts: {accounts}\nListings: {listings}\nOrders: {orders}\nProfit: ${profit:.2f}"
        await context.bot.send_message(chat_id=update.effective_chat.id, text=msg)
    except Exception as e:
        logger.exception("Status command failed")
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Error retrieving status")

async def pause(update, context):
    """Pause system operations via Telegram."""
    global RUNNING
    RUNNING = False
    await context.bot.send_message(chat_id=update.effective_chat.id, text="Operations paused.")

async def resume(update, context):
    """Resume system operations via Telegram."""
    global RUNNING
    RUNNING = True
    await context.bot.send_message(chat_id=update.effective_chat.id, text="Operations resumed.")

application.add_handler(CommandHandler("status", status))
application.add_handler(CommandHandler("pause", pause))
application.add_handler(CommandHandler("resume", resume))

# --- FastAPI Endpoints ---
from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Render the dashboard with the latest stats."""
    async def _get_dashboard_stats():
        conn = sqlite3.connect("dashboard.db")
        c = conn.cursor()
        c.execute("SELECT * FROM stats ORDER BY timestamp DESC LIMIT 1")
        stats = c.fetchone()
        conn.close()
        return stats or (0, 0, 0, 0, 0, 0, "No data")
    stats = await asyncio.to_thread(_get_dashboard_stats)
    return templates.TemplateResponse("dashboard.html", {"request": request, "stats": stats})

def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """Verify the webhook signature using SHA-256."""
    secret = os.getenv("WEBHOOK_SECRET", "supersecretwebhook123")
    computed_signature = hmac.new(
        key=secret.encode(),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed_signature, signature)

@app.post("/start_workflow")
async def start_workflow(request: Request):
    """Start the workflow via webhook."""
    if not RUNNING:
        return JSONResponse(content={"status": "Paused"}, status_code=503)

    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature", "")
    if not verify_webhook_signature(payload, signature):
        return JSONResponse(content={"status": "Invalid signature"}, status_code=403)

    await init_dashboard_db()

    async def run_gmail_task():
        try:
            gmail_task = create_gmail_account.delay()
            result = await asyncio.to_thread(gmail_task.get)
            if isinstance(result, Exception):
                logger.exception("Gmail creation failed")
                return None, None
            return result
        except Exception as e:
            logger.exception("Gmail task failed")
            return None, None

    async def run_supplier_task(supplier: str, gmail_email: str, gmail_password: str):
        try:
            task = create_supplier_account.delay(supplier, gmail_email, gmail_password)
            result = await asyncio.to_thread(task.get)
            if isinstance(result, Exception):
                logger.exception(f"Supplier {supplier} creation failed")
                return None
            return result
        except Exception as e:
            logger.exception(f"Supplier {supplier} task failed")
            return None

    async def run_platform_task(platform: str, index: int, gmail_email: str, gmail_password: str):
        try:
            task = create_platform_account.delay(platform, index, gmail_email, gmail_password)
            result = await asyncio.to_thread(task.get)
            if isinstance(result, Exception):
                logger.exception(f"Platform {platform} creation failed")
                return None
            return result
        except Exception as e:
            logger.exception(f"Platform {platform} task failed")
            return None

    async def run_banking_task(provider: str, gmail_email: str, gmail_password: str):
        try:
            task = create_banking_account.delay(provider, gmail_email, gmail_password)
            result = await asyncio.to_thread(task.get)
            if isinstance(result, Exception):
                logger.exception(f"Banking {provider} creation failed")
                return None
            return result
        except Exception as e:
            logger.exception(f"Banking {provider} task failed")
            return None

    async def run_workflow():
        # Gmail account
        gmail_email, gmail_password = await run_gmail_task()
        if not gmail_email:
            return JSONResponse(content={"status": "Error"}, status_code=500)

        # Supplier accounts
        supplier_tasks = [asyncio.create_task(run_supplier_task(supplier, gmail_email, gmail_password)) for supplier in config.SUPPLIERS]
        supplier_accounts = [result for result in await asyncio.gather(*supplier_tasks, return_exceptions=True) if result]

        # Platform accounts
        platform_tasks = [
            asyncio.create_task(run_platform_task(platform, i, gmail_email, gmail_password))
            for platform in config.PLATFORMS
            for i in range(config.NUM_ACCOUNTS_PER_PLATFORM)
        ]
        platform_accounts = [result for result in await asyncio.gather(*platform_tasks, return_exceptions=True) if result]

        # Banking account
        banking_tasks = [asyncio.create_task(run_banking_task(provider, gmail_email, gmail_password)) for provider in config.BANKING]
        banking_accounts = [result for result in await asyncio.gather(*banking_tasks, return_exceptions=True) if result]
        banking_account = banking_accounts[0] if banking_accounts else None

        # Product listing
        retail_listings = int(config.MAX_LISTINGS_PER_ACCOUNT * config.RETAIL_LISTING_PERCENT)
        wholesale_listings = int(config.MAX_LISTINGS_PER_ACCOUNT * config.WHOLESALE_LISTING_PERCENT)
        listing_tasks = []
        for supplier_email, _, supplier_api_key in supplier_accounts:
            supplier = next(s for s in config.SUPPLIERS if supplier_email.lower().startswith(s.lower()))
            product_type = "retail" if supplier in config.RETAIL_SUPPLIERS else "wholesale"
            limit = retail_listings if product_type == "retail" else wholesale_listings
            products = await fetch_trending_products(supplier, supplier_api_key, product_type)
            for platform_username, token in platform_accounts:
                platform = next(p for p in config.PLATFORMS if platform_username.lower().startswith(p.lower()))
                listing_tasks.extend([asyncio.create_task(list_product(platform, product, token)) for product in products[:limit]])
        await asyncio.gather(*listing_tasks, return_exceptions=True)

        # Test orders
        async with db_pool.acquire() as conn:
            listings = await conn.fetch("SELECT sku, platform, source, price, cost FROM listings WHERE status = 'active' LIMIT $1", config.TEST_ORDERS)
            order_tasks = []
            for i, listing in enumerate(listings):
                supplier_api_key = next((api_key for _, _, api_key in supplier_accounts if listing["source"].lower() in api_key.lower()), "mock_key")
                terms = await conn.fetchval("SELECT terms FROM supplier_accounts WHERE supplier = $1", listing["source"]) or "Net 30"
                order_tasks.append(asyncio.create_task(fulfill_order(f"order_{i}", listing["platform"], listing["sku"], "Test Buyer", "123 Test St", listing["source"], supplier_api_key)))
                order_tasks.append(asyncio.create_task(process_payment(listing["price"], "Paypal", banking_account[2] if banking_account else "mock_key")))
                order_tasks.append(asyncio.create_task(track_profit(listing["price"], listing["cost"])))
                order_tasks.append(asyncio.create_task(pay_supplier(listing["source"], listing["cost"], supplier_api_key, terms)))
            await asyncio.gather(*order_tasks, return_exceptions=True)

        return JSONResponse(content={"status": "Workflow completed"}, status_code=200)

    return await run_workflow()

# --- Startup and Shutdown ---
async def run_telegram_bot():
    """Run Telegram bot polling asynchronously."""
    try:
        await application.run_polling()
    except Exception as e:
        logger.exception("Telegram bot polling failed")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown."""
    await proxy_manager.init()
    await init_db()
    telegram_task = asyncio.create_task(run_telegram_bot())
    yield
    telegram_task.cancel()
    try:
        await telegram_task
    except asyncio.CancelledError:
        pass
    await application.stop()

app.router.lifespan_context = lifespan

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
