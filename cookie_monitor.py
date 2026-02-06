#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Monitor and auto-renew DinoRank cookies when they expire."""
import os
import sys
import time
import logging
import subprocess
from threading import Thread, Lock
from dotenv import load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [COOKIE MONITOR] - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CookieMonitor:
    def __init__(self, login_script_path="login_y_extraer_cookies.py"):
        self.login_script_path = login_script_path
        self.lock = Lock()
        self.is_renewing = False
        self.last_renewal = 0
        self.renewal_cooldown = 300  # 5 minutes

    def should_renew(self):
        """Check if cookies should be renewed (prevents too frequent renewals)."""
        with self.lock:
            now = time.time()
            if self.is_renewing:
                logger.info("Renewal already in progress, waiting...")
                return False

            if now - self.last_renewal < self.renewal_cooldown:
                remaining = int(self.renewal_cooldown - (now - self.last_renewal))
                logger.info(f"Cooldown active. Wait {remaining}s before renewing")
                return False

            return True

    def renew_cookies(self, trigger_reason="Unknown"):
        """Execute cookie renewal script."""
        if not self.should_renew():
            return False

        with self.lock:
            self.is_renewing = True
            self.last_renewal = time.time()

        try:
            logger.info("=" * 80)
            logger.warning("COOKIE RENEWAL STARTED")
            logger.info(f"Reason: {trigger_reason}")
            logger.info("=" * 80)

            result = subprocess.run(
                [sys.executable, self.login_script_path],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                logger.info("=" * 80)
                logger.info("RENEWAL SUCCESS")
                logger.info("=" * 80)
                logger.info("Script output:")
                for line in result.stdout.split('\n'):
                    if line.strip():
                        logger.info(f"  {line}")
                return True
            else:
                logger.error("=" * 80)
                logger.error("RENEWAL FAILED")
                logger.error("=" * 80)
                logger.error(f"Exit code: {result.returncode}")
                logger.error("Error output:")
                for line in result.stderr.split('\n'):
                    if line.strip():
                        logger.error(f"  {line}")
                return False

        except subprocess.TimeoutExpired:
            logger.error("Cookie renewal script timed out")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during renewal: {e}")
            return False
        finally:
            with self.lock:
                self.is_renewing = False

    def check_cookie_validity(self, response_status, response_url=""):
        """Check if response indicates invalid cookies."""
        if response_status == 401:
            logger.warning("Detected: 401 Unauthorized - Cookies possibly expired")
            return True

        if response_status == 403:
            logger.warning("Detected: 403 Forbidden - Cookies possibly invalid")
            return True

        if "login" in response_url.lower() and response_status in [301, 302, 303, 307, 308]:
            logger.warning(f"Detected: Redirect to login ({response_status}) - Session expired")
            return True

        return False

cookie_monitor = CookieMonitor()

def auto_renew_if_needed(response_status, response_url="", trigger_reason="Auto-detect"):
    """Auto-renew cookies if needed. Can be called from proxy."""
    if cookie_monitor.check_cookie_validity(response_status, response_url):
        logger.info(f"Starting auto-renewal: {trigger_reason}")
        success = cookie_monitor.renew_cookies(trigger_reason)
        if success:
            logger.info("Auto-renewal completed. New cookies are in .env")
            return True
        else:
            logger.error("Auto-renewal failed")
            return False
    return False

if __name__ == "__main__":
    print("=" * 80)
    print("COOKIE MONITOR TEST")
    print("=" * 80)
    print("\nSimulating expired cookies...")
    auto_renew_if_needed(401, "https://dinorank.com/login/", "Manual test")
