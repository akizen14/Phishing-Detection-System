import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options


def render_page_source(url: str, wait_seconds: int = 2, headless: bool = True, chrome_path: str = None):
    """
    Renders a webpage and returns its HTML source.
    """
    try:
        chrome_driver_path = os.environ.get("CHROMEDRIVER_PATH", chrome_path)
        if not chrome_driver_path:
            raise ValueError("CHROMEDRIVER_PATH not set or invalid.")

        chrome_options = Options()
        if headless:
            chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        service = Service(chrome_driver_path)
        driver = webdriver.Chrome(service=service, options=chrome_options)
        driver.get(url)
        time.sleep(wait_seconds)
        html = driver.page_source
        driver.quit()
        return html
    except Exception as e:
        print(f"[ERROR] Failed to render {url}: {e}")
        return None
