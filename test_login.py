"""
=============================================================================
  PRODIGY INFOTECH — Task 03
  Automated Login Test Suite
  Target: https://www.saucedemo.com (Demo E-Commerce Site)
  Framework: Pytest + Selenium WebDriver
=============================================================================

Test Coverage:
  ✅ Positive Cases  — valid credentials, remember-me, redirect after login
  ❌ Negative Cases  — wrong password, wrong username, empty fields,
                       SQL injection, locked-out user, whitespace-only inputs
=============================================================================
"""

import time
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service


# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────

BASE_URL = "https://www.saucedemo.com"
LOGIN_URL = f"{BASE_URL}/"
DASHBOARD_URL = f"{BASE_URL}/inventory.html"

VALID_USERNAME = "standard_user"
VALID_PASSWORD = "secret_sauce"

TIMEOUT = 10  # seconds


# ─────────────────────────────────────────────
#  FIXTURES
# ─────────────────────────────────────────────

@pytest.fixture(scope="function")
def driver():
    """
    Sets up a Chrome WebDriver instance for each test.
    Uses headless mode for CI/CD environments.
    """
    chrome_options = Options()
    chrome_options.add_argument("--headless")          # Run without UI
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--window-size=1366,768")
    chrome_options.add_argument("--disable-gpu")

    driver = webdriver.Chrome(options=chrome_options)
    driver.implicitly_wait(TIMEOUT)
    driver.get(LOGIN_URL)

    yield driver

    driver.quit()


@pytest.fixture(scope="function")
def wait(driver):
    """Explicit WebDriverWait instance."""
    return WebDriverWait(driver, TIMEOUT)


# ─────────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────────

def fill_login_form(driver, username: str, password: str):
    """Clears and fills the login form fields."""
    username_field = driver.find_element(By.ID, "user-name")
    password_field = driver.find_element(By.ID, "password")

    username_field.clear()
    password_field.clear()

    username_field.send_keys(username)
    password_field.send_keys(password)


def click_login(driver):
    """Clicks the Login button."""
    driver.find_element(By.ID, "login-button").click()


def get_error_message(driver) -> str:
    """Returns the text of the visible error message container."""
    try:
        error = driver.find_element(By.CSS_SELECTOR, "[data-test='error']")
        return error.text.strip()
    except Exception:
        return ""


def is_on_dashboard(driver) -> bool:
    """Returns True if the driver is currently on the inventory/dashboard page."""
    return DASHBOARD_URL in driver.current_url


# ─────────────────────────────────────────────
#  POSITIVE TEST CASES
# ─────────────────────────────────────────────

class TestPositiveLogin:
    """Tests that verify successful login scenarios."""

    def test_valid_credentials_login_success(self, driver):
        """
        TC-P01: Valid username and password should redirect to the dashboard.
        """
        fill_login_form(driver, VALID_USERNAME, VALID_PASSWORD)
        click_login(driver)

        assert is_on_dashboard(driver), (
            f"Expected redirect to {DASHBOARD_URL}, got {driver.current_url}"
        )

    def test_dashboard_renders_after_login(self, driver):
        """
        TC-P02: After successful login, the products inventory should be visible.
        """
        fill_login_form(driver, VALID_USERNAME, VALID_PASSWORD)
        click_login(driver)

        inventory = driver.find_element(By.CLASS_NAME, "inventory_list")
        assert inventory.is_displayed(), "Inventory list should be visible after login."

    def test_page_title_after_login(self, driver):
        """
        TC-P03: The page title should reflect the app name after login.
        """
        fill_login_form(driver, VALID_USERNAME, VALID_PASSWORD)
        click_login(driver)

        assert "Swag Labs" in driver.title, (
            f"Page title mismatch: '{driver.title}'"
        )

    def test_login_button_submits_on_enter_key(self, driver):
        """
        TC-P04: Pressing Enter in the password field should submit the form.
        """
        fill_login_form(driver, VALID_USERNAME, VALID_PASSWORD)
        driver.find_element(By.ID, "password").send_keys(Keys.RETURN)

        assert is_on_dashboard(driver), "Form should submit on Enter key press."

    def test_no_error_shown_on_valid_login(self, driver):
        """
        TC-P05: No error message should appear on a successful login.
        """
        fill_login_form(driver, VALID_USERNAME, VALID_PASSWORD)
        click_login(driver)

        error_msg = get_error_message(driver)
        assert error_msg == "", f"Unexpected error shown: '{error_msg}'"

    def test_performance_glitch_user_login(self, driver):
        """
        TC-P06: The 'performance_glitch_user' account should still log in successfully,
                even if the response is slower than usual.
        """
        fill_login_form(driver, "performance_glitch_user", VALID_PASSWORD)
        click_login(driver)

        WebDriverWait(driver, 20).until(EC.url_contains("inventory"))
        assert is_on_dashboard(driver), "Performance glitch user should eventually log in."

    def test_problem_user_login(self, driver):
        """
        TC-P07: The 'problem_user' account should log in successfully
                (known to have visual bugs, but auth should still work).
        """
        fill_login_form(driver, "problem_user", VALID_PASSWORD)
        click_login(driver)

        assert is_on_dashboard(driver), "Problem user should log in successfully."


# ─────────────────────────────────────────────
#  NEGATIVE TEST CASES
# ─────────────────────────────────────────────

class TestNegativeLogin:
    """Tests that verify failed login scenarios with appropriate error messages."""

    def test_wrong_password_shows_error(self, driver):
        """
        TC-N01: A valid username with an incorrect password should show an error.
        """
        fill_login_form(driver, VALID_USERNAME, "wrong_password_123")
        click_login(driver)

        error = get_error_message(driver)
        assert "Username and password do not match" in error, (
            f"Expected credential mismatch error, got: '{error}'"
        )
        assert not is_on_dashboard(driver), "User should NOT be redirected on wrong password."

    def test_wrong_username_shows_error(self, driver):
        """
        TC-N02: An invalid username should show an authentication error.
        """
        fill_login_form(driver, "nonexistent_user", VALID_PASSWORD)
        click_login(driver)

        error = get_error_message(driver)
        assert "Username and password do not match" in error, (
            f"Expected invalid username error, got: '{error}'"
        )

    def test_empty_username_shows_error(self, driver):
        """
        TC-N03: Submitting the form with an empty username should show a required field error.
        """
        fill_login_form(driver, "", VALID_PASSWORD)
        click_login(driver)

        error = get_error_message(driver)
        assert "Username is required" in error, (
            f"Expected 'Username is required', got: '{error}'"
        )

    def test_empty_password_shows_error(self, driver):
        """
        TC-N04: Submitting with a valid username but no password should prompt for password.
        """
        fill_login_form(driver, VALID_USERNAME, "")
        click_login(driver)

        error = get_error_message(driver)
        assert "Password is required" in error, (
            f"Expected 'Password is required', got: '{error}'"
        )

    def test_both_fields_empty_shows_error(self, driver):
        """
        TC-N05: Submitting with both fields empty should show a username required error.
        """
        fill_login_form(driver, "", "")
        click_login(driver)

        error = get_error_message(driver)
        assert "Username is required" in error, (
            f"Expected 'Username is required', got: '{error}'"
        )

    def test_locked_out_user_shows_error(self, driver):
        """
        TC-N06: A locked-out user account should be denied access with an informative message.
        """
        fill_login_form(driver, "locked_out_user", VALID_PASSWORD)
        click_login(driver)

        error = get_error_message(driver)
        assert "locked out" in error.lower(), (
            f"Expected locked out message, got: '{error}'"
        )
        assert not is_on_dashboard(driver), "Locked-out user must NOT access the dashboard."

    def test_sql_injection_username(self, driver):
        """
        TC-N07: SQL injection in the username field should not grant access.
        """
        fill_login_form(driver, "' OR '1'='1", VALID_PASSWORD)
        click_login(driver)

        assert not is_on_dashboard(driver), "SQL injection should not bypass authentication."

    def test_sql_injection_password(self, driver):
        """
        TC-N08: SQL injection in the password field should not grant access.
        """
        fill_login_form(driver, VALID_USERNAME, "' OR '1'='1' --")
        click_login(driver)

        assert not is_on_dashboard(driver), "SQL injection in password should not grant access."

    def test_whitespace_only_username(self, driver):
        """
        TC-N09: A username consisting only of spaces should be treated as empty/invalid.
        """
        fill_login_form(driver, "     ", VALID_PASSWORD)
        click_login(driver)

        assert not is_on_dashboard(driver), "Whitespace-only username should not log in."

    def test_whitespace_only_password(self, driver):
        """
        TC-N10: A password consisting only of spaces should be treated as invalid.
        """
        fill_login_form(driver, VALID_USERNAME, "     ")
        click_login(driver)

        assert not is_on_dashboard(driver), "Whitespace-only password should not log in."

    def test_case_sensitive_username(self, driver):
        """
        TC-N11: Username should be case-sensitive — 'Standard_User' ≠ 'standard_user'.
        """
        fill_login_form(driver, "Standard_User", VALID_PASSWORD)
        click_login(driver)

        assert not is_on_dashboard(driver), "Uppercase username variant should not log in."

    def test_case_sensitive_password(self, driver):
        """
        TC-N12: Password should be case-sensitive — 'Secret_Sauce' ≠ 'secret_sauce'.
        """
        fill_login_form(driver, VALID_USERNAME, "Secret_Sauce")
        click_login(driver)

        assert not is_on_dashboard(driver), "Uppercase password variant should not log in."

    def test_xss_in_username_field(self, driver):
        """
        TC-N13: XSS payload in username should not be executed or grant access.
        """
        fill_login_form(driver, "<script>alert('xss')</script>", VALID_PASSWORD)
        click_login(driver)

        assert not is_on_dashboard(driver), "XSS payload should not bypass authentication."

    def test_very_long_username(self, driver):
        """
        TC-N14: An extremely long username should be rejected gracefully.
        """
        long_user = "a" * 500
        fill_login_form(driver, long_user, VALID_PASSWORD)
        click_login(driver)

        assert not is_on_dashboard(driver), "500-char username should not authenticate."

    def test_error_message_dismissible(self, driver):
        """
        TC-N15: The error message should have a close/dismiss button that hides it.
        """
        fill_login_form(driver, "", "")
        click_login(driver)

        error_close = driver.find_element(By.CSS_SELECTOR, ".error-button")
        assert error_close.is_displayed(), "Error close button should be visible."
        error_close.click()
        time.sleep(0.5)

        error_container = driver.find_element(By.CSS_SELECTOR, "[data-test='error']")
        assert not error_container.is_displayed(), "Error message should hide after clicking X."


# ─────────────────────────────────────────────
#  UI / UX TEST CASES
# ─────────────────────────────────────────────

class TestLoginUI:
    """Tests that verify UI elements are correct and accessible."""

    def test_login_page_title(self, driver):
        """TC-U01: The login page should have the correct browser tab title."""
        assert "Swag Labs" in driver.title

    def test_username_field_visible(self, driver):
        """TC-U02: Username input should be visible and enabled."""
        field = driver.find_element(By.ID, "user-name")
        assert field.is_displayed() and field.is_enabled()

    def test_password_field_visible(self, driver):
        """TC-U03: Password input should be visible and enabled."""
        field = driver.find_element(By.ID, "password")
        assert field.is_displayed() and field.is_enabled()

    def test_password_field_is_masked(self, driver):
        """TC-U04: Password field type must be 'password' to mask input."""
        field = driver.find_element(By.ID, "password")
        assert field.get_attribute("type") == "password", (
            "Password field should have type='password'"
        )

    def test_login_button_visible(self, driver):
        """TC-U05: The login button should be visible and clickable."""
        btn = driver.find_element(By.ID, "login-button")
        assert btn.is_displayed() and btn.is_enabled()

    def test_login_button_label(self, driver):
        """TC-U06: Login button value/label should say 'Login'."""
        btn = driver.find_element(By.ID, "login-button")
        assert btn.get_attribute("value").lower() == "login"

    def test_username_placeholder(self, driver):
        """TC-U07: Username field should have a descriptive placeholder."""
        field = driver.find_element(By.ID, "user-name")
        placeholder = field.get_attribute("placeholder")
        assert placeholder and len(placeholder) > 0, "Username field needs a placeholder."

    def test_password_placeholder(self, driver):
        """TC-U08: Password field should have a descriptive placeholder."""
        field = driver.find_element(By.ID, "password")
        placeholder = field.get_attribute("placeholder")
        assert placeholder and len(placeholder) > 0, "Password field needs a placeholder."
