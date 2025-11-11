"""
Web page rendering using Selenium and Chrome WebDriver.
"""
import time
from typing import Optional

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

from src.config import CHROMEDRIVER_PATH, DEFAULT_WAIT_SECONDS, DEFAULT_HEADLESS


def render_page_source(
    url: str, 
    wait_seconds: int = DEFAULT_WAIT_SECONDS, 
    headless: bool = DEFAULT_HEADLESS, 
    chrome_path: Optional[str] = None
) -> Optional[str]:
    """
    Render a webpage and return its HTML source using Selenium.
    
    Args:
        url: URL to render
        wait_seconds: Seconds to wait for page load
        headless: Run browser in headless mode
        chrome_path: Override path to ChromeDriver executable
        
    Returns:
        HTML source code or None if rendering fails
    """
    try:
        chrome_driver_path = chrome_path or CHROMEDRIVER_PATH
        if not chrome_driver_path:
            raise ValueError("CHROMEDRIVER_PATH not set. Set it in .env or pass chrome_path parameter.")

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
