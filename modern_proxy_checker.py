import logging
import re
import sys
import threading
import time
import json
import os
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple, Set

import requests
import urllib3
from requests.exceptions import (
    ProxyError,
    ConnectTimeout,
    ConnectionError,
    TooManyRedirects,
    Timeout,
    ReadTimeout,
)

# PyQt5 imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QProgressBar,
    QFileDialog, QSlider, QComboBox, QListWidget, QTabWidget,
    QGroupBox, QMessageBox, QSpinBox, QFrame, QSplitter
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QFont, QPixmap

# Matplotlib for charts
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Disable TLS warnings
urllib3.disable_warnings()

# Constants
DEFAULT_TIMEOUT = (5, 8)
DEFAULT_THREADS = 16
DEFAULT_TEST_URLS = [
    "https://captive.apple.com/",
    "https://www.google.com/",
    "https://www.cloudflare.com/"
]
SUCCESS_PATTERNS = {
    "https://captive.apple.com/": r"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>$",
    "https://www.google.com/": r"(<title>Google</title>|google)",
    "https://www.cloudflare.com/": r"(cloudflare|Cloudflare)"
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
)


class ProxyStats:
    """Class to track proxy checking statistics"""

    def __init__(self):
        self.total = 0
        self.tested = 0
        self.working = 0
        self.working_types = {"http": 0, "https": 0, "socks4": 0, "socks5": 0}
        self.speeds = []  # List of response times in seconds
        self.locations = {}  # Country -> count
        self.anonymity = {"transparent": 0, "anonymous": 0, "elite": 0}
        self.start_time = time.time()

    def add_working(self, proxy_type: str, speed: float, location: str = None, anonymity_level: str = None):
        """Track a working proxy"""
        self.working += 1
        if proxy_type in self.working_types:
            self.working_types[proxy_type] += 1
        self.speeds.append(speed)

        if location:
            self.locations[location] = self.locations.get(location, 0) + 1

        if anonymity_level:
            if anonymity_level in self.anonymity:
                self.anonymity[anonymity_level] += 1

    def avg_speed(self) -> float:
        """Get average speed of working proxies"""
        if not self.speeds:
            return 0
        return sum(self.speeds) / len(self.speeds)

    def get_elapsed_time(self) -> float:
        """Get elapsed time since start"""
        return time.time() - self.start_time

    def to_dict(self) -> Dict:
        """Convert stats to dictionary for serialization"""
        return {
            "total": self.total,
            "tested": self.tested,
            "working": self.working,
            "working_types": self.working_types,
            "avg_speed": self.avg_speed(),
            "locations": self.locations,
            "anonymity": self.anonymity,
            "elapsed_time": self.get_elapsed_time()
        }

    def reset(self):
        """Reset all stats"""
        self.__init__()


class ProxyChecker:
    """Enhanced proxy checker with support for multiple proxy types and test URLs"""

    def __init__(
        self,
        input_file: str = None,
        output_file: str = None,
        threads: int = DEFAULT_THREADS,
        timeout: Tuple[int, int] = DEFAULT_TIMEOUT,
        test_urls: List[str] = DEFAULT_TEST_URLS,
        log_file: str = "proxy-checker.log",
        verbose: bool = False,
        proxy_list: List[str] = None,
    ):
        # Setup logging
        self.logger = self._setup_logging(log_file, verbose)

        # Settings
        self.input_file = input_file
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.test_urls = test_urls
        self.success_patterns = {url: re.compile(SUCCESS_PATTERNS.get(url, r".*")) for url in test_urls}

        # Status tracking
        self.stats = ProxyStats()
        self.proxies = proxy_list or []
        self.queue = Queue()
        self.stop_event = threading.Event()
        self.progress_callback = None
        self.working_proxies = []
        self.blacklist = set()  # Blacklist for permanently failed proxies

        # Load proxy list from file if provided
        if input_file and not proxy_list:
            self.load_proxies()

    def _setup_logging(self, log_file: str, verbose: bool) -> logging.Logger:
        """Set up logging for the application"""
        log_level = logging.DEBUG if verbose else logging.INFO

        logger = logging.getLogger("ProxyChecker")
        logger.setLevel(log_level)

        # Create formatter
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        # File handler
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)

        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

        return logger

    def load_proxies(self) -> List[str]:
        """Load and validate proxy list from file"""
        if not self.input_file or not os.path.exists(self.input_file):
            self.logger.error(f"Input file not found: {self.input_file}")
            return []

        try:
            with open(self.input_file, "r", encoding="utf-8") as file:
                # Process and clean the proxy list
                lines = [
                    line.strip()
                    for line in file
                    if not line.startswith("#") and line.strip()
                ]

                # Validate proxies with regex patterns
                ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$"
                ipv6_pattern = r"^\[[\da-fA-F:]+\]:\d+$"
                domain_pattern = r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}:\d+$"

                valid_proxies = []
                for line in lines:
                    if (re.match(ipv4_pattern, line) or
                        re.match(ipv6_pattern, line) or
                        re.match(domain_pattern, line)):
                        valid_proxies.append(line)

                # Remove duplicates while preserving order
                self.proxies = list(dict.fromkeys(valid_proxies))
                self.stats.total = len(self.proxies)

                self.logger.info(f"Loaded {len(self.proxies)} valid proxies from {self.input_file}")
                return self.proxies

        except Exception as e:
            self.logger.error(f"Error loading proxy list: {e}")
            return []

    def save_working_proxies(self):
        """Save working proxies to output file"""
        if not self.output_file:
            self.logger.warning("No output file specified, working proxies won't be saved")
            return

        try:
            # Create directory if it doesn't exist
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            # Basic text output
            with open(self.output_file, "w", encoding="utf-8") as file:
                for proxy in self.working_proxies:
                    file.write(f"{proxy}\n")

            # JSON output with detailed information
            json_output = f"{os.path.splitext(self.output_file)[0]}_detailed.json"
            with open(json_output, "w", encoding="utf-8") as file:
                json.dump({
                    "stats": self.stats.to_dict(),
                    "proxies": self.working_proxies,
                    "timestamp": datetime.now().isoformat()
                }, file, indent=2)

            self.logger.info(f"Saved {len(self.working_proxies)} working proxies to {self.output_file}")
            self.logger.info(f"Detailed report saved to {json_output}")

        except Exception as e:
            self.logger.error(f"Error saving working proxies: {e}")

    def add_proxy(self, proxy: str) -> bool:
        """Add a single proxy to the list if valid"""
        ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$"
        ipv6_pattern = r"^\[[\da-fA-F:]+\]:\d+$"
        domain_pattern = r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}:\d+$"

        if (re.match(ipv4_pattern, proxy) or
            re.match(ipv6_pattern, proxy) or
            re.match(domain_pattern, proxy)):
            if proxy not in self.proxies and proxy not in self.blacklist:
                self.proxies.append(proxy)
                self.stats.total += 1
                return True
        return False

    def add_proxies(self, proxy_list: List[str]) -> int:
        """Add multiple proxies to the list"""
        added = 0
        for proxy in proxy_list:
            if self.add_proxy(proxy.strip()):
                added += 1
        return added

    def check_proxy(self, proxy: str) -> dict:
        """Check if a proxy is working by testing it against all test URLs"""
        result = {
            "proxy": proxy,
            "working": False,
            "type": None,
            "speed": 0,
            "anonymity": None,
            "location": None,
            "error": None
        }

        self.stats.tested += 1

        # Test with different proxy protocols
        for proxy_type in ["http", "https", "socks4", "socks5"]:
            try:
                proxy_url = f"{proxy_type}://{proxy}"

                session = requests.Session()
                session.headers["User-Agent"] = USER_AGENT
                session.verify = False
                session.max_redirects = 5

                # First test with primary URL
                start_time = time.time()
                response = session.get(
                    self.test_urls[0],
                    proxies={
                        "http": proxy_url,
                        "https": proxy_url
                    },
                    timeout=self.timeout,
                    allow_redirects=True
                )
                response_time = time.time() - start_time

                # Check if proxy is working using regex pattern
                pattern = self.success_patterns[self.test_urls[0]]
                if pattern.search(response.text):
                    # Try to determine anonymity level
                    anonymity_level = self._check_anonymity(proxy_url)

                    # Try to determine location
                    location = self._get_proxy_location(proxy_url)

                    # Update results
                    result["working"] = True
                    result["type"] = proxy_type
                    result["speed"] = response_time
                    result["anonymity"] = anonymity_level
                    result["location"] = location

                    # Update stats
                    self.stats.add_working(proxy_type, response_time, location, anonymity_level)

                    if proxy not in self.working_proxies:
                        self.working_proxies.append(proxy)

                    # Log success
                    self.logger.info(
                        f"[{self.stats.tested}/{self.stats.total}] {proxy} is working "
                        f"({proxy_type}, {response_time:.2f}s)"
                    )

                    # Once we find a working protocol, we can stop testing
                    break

            except (ProxyError, ConnectTimeout, ConnectionError, TooManyRedirects,
                    Timeout, ReadTimeout, Exception) as e:
                # Just continue to the next protocol type
                continue

        # Log error if none of the protocols worked
        if not result["working"]:
            error_msg = f"[{self.stats.tested}/{self.stats.total}] {proxy} is not working"
            self.logger.debug(error_msg)
            result["error"] = "Failed with all protocols"

            # Add to blacklist to prevent retesting
            self.blacklist.add(proxy)

        # Update UI if callback is set
        if self.progress_callback and callable(self.progress_callback):
            self.progress_callback(self.stats)

        return result

    def _check_anonymity(self, proxy_url: str) -> str:
        """Determine the anonymity level of a proxy"""
        try:
            session = requests.Session()
            session.headers["User-Agent"] = USER_AGENT

            response = session.get(
                "https://httpbin.org/headers",
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                headers = data.get("headers", {})

                # Check for revealing headers
                if "X-Forwarded-For" in headers or "Via" in headers:
                    return "transparent"

                # Check if original IP is exposed
                ip_response = session.get(
                    "https://httpbin.org/ip",
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=self.timeout
                )

                if ip_response.status_code == 200:
                    # Elite proxies completely hide the fact you're using a proxy
                    return "elite"

                return "anonymous"

        except Exception:
            pass

        # Default if we couldn't determine
        return "unknown"

    def _get_proxy_location(self, proxy_url: str) -> str:
        """Try to determine the geographical location of a proxy"""
        try:
            session = requests.Session()
            response = session.get(
                "https://ipinfo.io/json",
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                country = data.get("country", "Unknown")
                return country

        except Exception:
            pass

        return "Unknown"

    def start_checking(self):
        """Start checking proxies using thread pool"""
        self.logger.info(f"Starting proxy checking with {self.threads} threads")
        self.logger.info(f"Testing against URLs: {', '.join(self.test_urls)}")
        self.stats.start_time = time.time()

        # Fill the queue
        for proxy in self.proxies:
            self.queue.put(proxy)

        # Create thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            # Submit tasks to the pool
            while not self.queue.empty() and not self.stop_event.is_set():
                proxy = self.queue.get()
                futures.append(executor.submit(self.check_proxy, proxy))

            # Wait for all tasks to complete
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Error in thread: {e}")

        # Save results
        if self.output_file:
            self.save_working_proxies()

        # Log summary
        elapsed = self.stats.get_elapsed_time()
        self.logger.info(f"Finished checking {self.stats.tested} proxies in {elapsed:.2f} seconds")
        self.logger.info(f"Found {len(self.working_proxies)} working proxies")

        return self.working_proxies, self.stats

    def stop_checking(self):
        """Stop the proxy checking process"""
        self.stop_event.set()
        self.logger.info("Stopping proxy checking")


class CheckerThread(QThread):
    """Thread for running the proxy checker"""
    update_signal = pyqtSignal(object)
    finished_signal = pyqtSignal(object, object)

    def __init__(self, checker):
        super().__init__()
        self.checker = checker

    def run(self):
        working_proxies, stats = self.checker.start_checking()
        self.finished_signal.emit(working_proxies, stats)


class ModernProxyCheckerGUI(QMainWindow):
    """Modern GUI for the proxy checker using PyQt5"""

    def __init__(self):
        super().__init__()

         # Set application icon
        icon_path = os.path.join(os.path.dirname(__file__), 'images', 'app_icon.png')
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.logger.warning(f"Icon file not found: {icon_path}")

        self.checker = None
        self.checker_thread = None
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)

        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Modern Proxy Checker")
        self.setMinimumSize(1000, 700)

        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                background-color: white;
                border-radius: 4px;
            }
            QTabBar::tab {
                background-color: #e1e1e1;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border: 1px solid #ddd;
                border-bottom: 1px solid white;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #ddd;
                border-radius: 4px;
                margin-top: 12px;
                padding-top: 24px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #0275d8;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #025aa5;
            }
            QPushButton:disabled {
                background-color: #6c757d;
            }
            QPushButton#stop-btn {
                background-color: #d9534f;
            }
            QPushButton#stop-btn:hover {
                background-color: #c9302c;
            }
            QPushButton#info-btn {
                background-color: #5bc0de;
            }
            QPushButton#info-btn:hover {
                background-color: #31b0d5;
            }
            QLineEdit, QTextEdit, QComboBox, QListWidget {
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 6px;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #5cb85c;
                width: 10px;
                margin: 0.5px;
            }
            QLabel {
                color: #333;
            }
            QLabel#header-label {
                font-size: 18px;
                font-weight: bold;
                color: #0275d8;
            }
            QLabel#status-label {
                font-weight: bold;
            }
            QSlider::groove:horizontal {
                border: 1px solid #999999;
                height: 8px;
                background: #f0f0f0;
                margin: 2px 0;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #0275d8;
                border: 1px solid #0275d8;
                width: 18px;
                margin: -2px 0;
                border-radius: 9px;
            }
        """)

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)
        # Header with icon and text
        header_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_path = os.path.join(os.path.dirname(__file__), 'images', 'app_icon.png')
        if os.path.exists(icon_path):
            icon_pixmap = QPixmap(icon_path).scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            icon_label.setPixmap(icon_pixmap)
        header_label = QLabel("Modern Proxy Checker")
        header_label.setObjectName("header-label")
        header_layout.addWidget(icon_label)
        header_layout.addWidget(header_label)
        header_layout.setAlignment(Qt.AlignCenter)
        main_layout.addLayout(header_layout)



        # Create tab widget
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # Create tabs
        settings_tab = QWidget()
        results_tab = QWidget()

        tab_widget.addTab(settings_tab, "Settings")
        tab_widget.addTab(results_tab, "Results")

        # Settings tab layout
        settings_layout = QVBoxLayout(settings_tab)

        # File settings group
        file_group = QGroupBox("File Settings")
        file_layout = QVBoxLayout(file_group)

        input_layout = QHBoxLayout()
        input_label = QLabel("Input File:")
        self.input_file_edit = QLineEdit()
        browse_input_btn = QPushButton("Browse")
        browse_input_btn.clicked.connect(self.browse_input_file)

        input_layout.addWidget(input_label)
        input_layout.addWidget(self.input_file_edit)
        input_layout.addWidget(browse_input_btn)

        output_layout = QHBoxLayout()
        output_label = QLabel("Output File:")
        self.output_file_edit = QLineEdit()
        browse_output_btn = QPushButton("Browse")
        browse_output_btn.clicked.connect(self.browse_output_file)

        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_file_edit)
        output_layout.addWidget(browse_output_btn)

        file_layout.addLayout(input_layout)
        file_layout.addLayout(output_layout)

        settings_layout.addWidget(file_group)

        # Checker settings group
        checker_group = QGroupBox("Checker Settings")
        checker_layout = QVBoxLayout(checker_group)

        threads_layout = QHBoxLayout()
        threads_label = QLabel("Threads:")
        self.threads_slider = QSlider(Qt.Horizontal)
        self.threads_slider.setMinimum(1)
        self.threads_slider.setMaximum(100)
        self.threads_slider.setValue(DEFAULT_THREADS)
        self.threads_value_label = QLabel(str(DEFAULT_THREADS))
        self.threads_slider.valueChanged.connect(self.update_threads_label)

        threads_layout.addWidget(threads_label)
        threads_layout.addWidget(self.threads_slider)
        threads_layout.addWidget(self.threads_value_label)

        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("Timeout (s):")
        self.timeout_slider = QSlider(Qt.Horizontal)
        self.timeout_slider.setMinimum(1)
        self.timeout_slider.setMaximum(30)
        self.timeout_slider.setValue(DEFAULT_TIMEOUT[1])
        self.timeout_value_label = QLabel(str(DEFAULT_TIMEOUT[1]))
        self.timeout_slider.valueChanged.connect(self.update_timeout_label)

        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_slider)
        timeout_layout.addWidget(self.timeout_value_label)

        url_layout = QHBoxLayout()
        url_label = QLabel("Test URLs:")
        self.url_combo = QComboBox()
        self.url_combo.addItems(DEFAULT_TEST_URLS)
        add_url_btn = QPushButton("Add")
        add_url_btn.clicked.connect(self.add_test_url)
        clear_urls_btn = QPushButton("Clear")
        clear_urls_btn.clicked.connect(self.clear_test_urls)

        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_combo)
        url_layout.addWidget(add_url_btn)
        url_layout.addWidget(clear_urls_btn)

        self.url_list = QListWidget()
        self.url_list.addItems(DEFAULT_TEST_URLS)

        checker_layout.addLayout(threads_layout)
        checker_layout.addLayout(timeout_layout)
        checker_layout.addLayout(url_layout)
        checker_layout.addWidget(self.url_list)

        settings_layout.addWidget(checker_group)

        # Manual proxy input group
        proxy_group = QGroupBox("Manual Proxy Input")
        proxy_layout = QVBoxLayout(proxy_group)

        proxy_label = QLabel("Enter proxies (one per line, format: ip:port)")
        self.proxy_text = QTextEdit()
        self.proxy_text.setPlaceholderText("Example:\n192.168.1.1:8080\n10.0.0.1:3128")

        proxy_buttons_layout = QHBoxLayout()
        add_proxies_btn = QPushButton("Add Proxies")
        add_proxies_btn.clicked.connect(self.add_manual_proxies)
        clear_proxies_btn = QPushButton("Clear")
        clear_proxies_btn.clicked.connect(self.clear_manual_proxies)

        proxy_buttons_layout.addWidget(add_proxies_btn)
        proxy_buttons_layout.addWidget(clear_proxies_btn)

        proxy_layout.addWidget(proxy_label)
        proxy_layout.addWidget(self.proxy_text)
        proxy_layout.addLayout(proxy_buttons_layout)

        settings_layout.addWidget(proxy_group)

        # Action buttons
        action_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.start_checking)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stop-btn")
        self.stop_btn.clicked.connect(self.stop_checking)
        self.stop_btn.setEnabled(False)

        self.reset_btn = QPushButton("Reset")
        self.reset_btn.clicked.connect(self.reset_checker)

        self.info_btn = QPushButton("Info")
        self.info_btn.setObjectName("info-btn")
        self.info_btn.clicked.connect(self.show_info)

        action_layout.addWidget(self.start_btn)
        action_layout.addWidget(self.stop_btn)
        action_layout.addWidget(self.reset_btn)
        action_layout.addWidget(self.info_btn)

        settings_layout.addLayout(action_layout)

        # Results tab layout
        results_layout = QVBoxLayout(results_tab)

        # Status group
        status_group = QGroupBox("Status")
        status_layout = QVBoxLayout(status_group)

        self.status_label = QLabel("Status: Not started")
        self.status_label.setObjectName("status-label")

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% (%v/%m)")

        stats_layout = QHBoxLayout()

        total_layout = QVBoxLayout()
        total_label = QLabel("Total:")
        self.total_value = QLabel("0")
        total_layout.addWidget(total_label)
        total_layout.addWidget(self.total_value)

        tested_layout = QVBoxLayout()
        tested_label = QLabel("Tested:")
        self.tested_value = QLabel("0")
        tested_layout.addWidget(tested_label)
        tested_layout.addWidget(self.tested_value)

        working_layout = QVBoxLayout()
        working_label = QLabel("Working:")
        self.working_value = QLabel("0")
        working_layout.addWidget(working_label)
        working_layout.addWidget(self.working_value)

        stats_layout.addLayout(total_layout)
        stats_layout.addLayout(tested_layout)
        stats_layout.addLayout(working_layout)

        # Chart frame
        chart_frame = QFrame()
        chart_layout = QVBoxLayout(chart_frame)

        # Create matplotlib figure
        self.figure = plt.figure(figsize=(5, 4))
        self.canvas = FigureCanvas(self.figure)
                # Create matplotlib figure
        self.figure = plt.figure(figsize=(5, 4))
        self.canvas = FigureCanvas(self.figure)
        chart_layout.addWidget(self.canvas)

        # Initialize the chart
        self.init_chart()

        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)
        status_layout.addLayout(stats_layout)
        status_layout.addWidget(chart_frame)

        # Working proxies group
        working_group = QGroupBox("Working Proxies")
        working_layout = QVBoxLayout(working_group)

        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)

        results_buttons_layout = QHBoxLayout()
        copy_btn = QPushButton("Copy All")
        copy_btn.clicked.connect(self.copy_results)
        export_btn = QPushButton("Export")
        export_btn.clicked.connect(self.export_results)

        results_buttons_layout.addWidget(copy_btn)
        results_buttons_layout.addWidget(export_btn)

        working_layout.addWidget(self.results_text)
        working_layout.addLayout(results_buttons_layout)

        # Add groups to results tab
        results_splitter = QSplitter(Qt.Vertical)

        # Düzeltme: Gereksiz widget oluşturma kaldırıldı
        results_splitter.addWidget(status_group)
        results_splitter.addWidget(working_group)

        results_layout.addWidget(results_splitter)

        # Show the window
        self.show()

    def init_chart(self):
        """Initialize the pie chart"""
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.set_title("Proxy Types")
        ax.pie([1], labels=["No Data"], autopct='%1.1f%%', startangle=90)
        ax.axis('equal')
        self.canvas.draw()

    def update_chart(self, stats):
        """Update the chart with current statistics"""
        self.figure.clear()
        ax = self.figure.add_subplot(111)

        if stats.working > 0:
            # Proxy types pie chart
            types = []
            values = []
            for proxy_type, count in stats.working_types.items():
                if count > 0:
                    types.append(proxy_type)
                    values.append(count)

            if values:
                ax.set_title("Proxy Types")
                ax.pie(values, labels=types, autopct='%1.1f%%', startangle=90)
                ax.axis('equal')
        else:
            ax.set_title("Proxy Types")
            ax.pie([1], labels=["No Data"], autopct='%1.1f%%', startangle=90)
            ax.axis('equal')

        self.canvas.draw()

    def update_threads_label(self):
        """Update the threads value label"""
        value = self.threads_slider.value()
        self.threads_value_label.setText(str(value))

    def update_timeout_label(self):
        """Update the timeout value label"""
        value = self.timeout_slider.value()
        self.timeout_value_label.setText(str(value))

    def browse_input_file(self):
        """Browse for input file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Input File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.input_file_edit.setText(file_path)

    def browse_output_file(self):
        """Browse for output file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Output File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.output_file_edit.setText(file_path)

    def add_test_url(self):
        """Add a test URL to the list"""
        url = self.url_combo.currentText()
        if url and url not in [self.url_list.item(i).text() for i in range(self.url_list.count())]:
            self.url_list.addItem(url)

    def clear_test_urls(self):
        """Clear the test URL list"""
        self.url_list.clear()

    def add_manual_proxies(self):
        """Add manually entered proxies"""
        if not self.checker:
            self.init_checker()

        proxies = self.proxy_text.toPlainText().strip().split("\n")
        added = self.checker.add_proxies(proxies)

        QMessageBox.information(self, "Proxies Added", f"Added {added} proxies")
        self.total_value.setText(str(self.checker.stats.total))

    def clear_manual_proxies(self):
        """Clear the manual proxy input"""
        self.proxy_text.clear()

    def init_checker(self):
        """Initialize the proxy checker"""
        # Get test URLs
        test_urls = []
        for i in range(self.url_list.count()):
            test_urls.append(self.url_list.item(i).text())

        if not test_urls:
            test_urls = DEFAULT_TEST_URLS

        # Create checker instance
        self.checker = ProxyChecker(
            input_file=self.input_file_edit.text() if self.input_file_edit.text() else None,
            output_file=self.output_file_edit.text() if self.output_file_edit.text() else None,
            threads=self.threads_slider.value(),
            timeout=(self.timeout_slider.value() // 2, self.timeout_slider.value()),
            test_urls=test_urls,
            verbose=False
        )

        # Set progress callback
        self.checker.progress_callback = self.update_stats

    def update_stats(self, stats):
        """Callback for updating stats from the checker"""
        # This will be called from a different thread, so we don't update UI directly
        pass

    def update_stats_display(self):
        """Update the stats display from the main thread"""
        if self.checker:
            stats = self.checker.stats

            # Update status
            self.status_label.setText(f"Status: Running ({stats.get_elapsed_time():.1f}s)")

            # Update progress
            if stats.total > 0:
                self.progress_bar.setMaximum(stats.total)
                self.progress_bar.setValue(stats.tested)

            # Update stats
            self.total_value.setText(str(stats.total))
            self.tested_value.setText(str(stats.tested))
            self.working_value.setText(str(stats.working))

            # Update chart
            self.update_chart(stats)

            # Update results
            if self.checker.working_proxies:
                self.results_text.setText("\n".join(self.checker.working_proxies))

    def start_checking(self):
        """Start the proxy checking process"""
        # Initialize checker if not already done
        if not self.checker:
            self.init_checker()

        # Add manual proxies if any
        manual_proxies = self.proxy_text.toPlainText().strip().split("\n")
        if manual_proxies[0]:  # Check if there's at least one non-empty proxy
            self.checker.add_proxies(manual_proxies)

        # Check if we have proxies to check
        if not self.checker.proxies:
            QMessageBox.warning(
                self, "No Proxies",
                "No proxies to check. Please load a file or enter proxies manually."
            )
            return

        # Update UI
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Status: Starting...")
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(self.checker.stats.total)

        # Create and start the checker thread
        self.checker_thread = CheckerThread(self.checker)
        self.checker_thread.finished_signal.connect(self.checking_finished)
        self.checker_thread.start()

        # Start the stats update timer
        self.stats_timer.start(500)  # Update every 500ms

    def stop_checking(self):
        """Stop the proxy checking process"""
        if self.checker:
            self.checker.stop_checking()
            self.status_label.setText("Status: Stopping...")

    def checking_finished(self, working_proxies, stats):
        """Handle the completion of the checking process"""
        # Stop the timer
        self.stats_timer.stop()

        # Update UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"Status: Completed ({stats.get_elapsed_time():.1f}s)")

        # Final stats update
        self.total_value.setText(str(stats.total))
        self.tested_value.setText(str(stats.tested))
        self.working_value.setText(str(stats.working))

        # Update chart
        self.update_chart(stats)

        # Update results
        if working_proxies:
            self.results_text.setText("\n".join(working_proxies))
        else:
            self.results_text.setText("No working proxies found.")

        # Show completion message
        QMessageBox.information(
            self, "Checking Completed",
            f"Checked {stats.tested} proxies\nFound {stats.working} working proxies"
        )

    def reset_checker(self):
        """Reset the checker and UI"""
        # Stop checking if running
        if self.checker:
            self.checker.stop_checking()
            self.checker = None

        # Stop the timer
        self.stats_timer.stop()

        # Reset UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Status: Not started")
        self.progress_bar.setValue(0)
        self.total_value.setText("0")
        self.tested_value.setText("0")
        self.working_value.setText("0")
        self.results_text.clear()

        # Reset chart
        self.init_chart()

    def copy_results(self):
        """Copy results to clipboard"""
        text = self.results_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", "Results copied to clipboard")
        else:
            QMessageBox.warning(self, "No Results", "No results to copy")

    def export_results(self):
        """Export results to a file"""
        if not self.checker or not self.checker.working_proxies:
            QMessageBox.warning(self, "No Results", "No working proxies to export")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "", "Text Files (*.txt);;All Files (*)"
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write("\n".join(self.checker.working_proxies))

                # Also save detailed JSON
                json_path = f"{os.path.splitext(file_path)[0]}_detailed.json"
                with open(json_path, "w", encoding="utf-8") as file:
                    json.dump({
                        "stats": self.checker.stats.to_dict(),
                        "proxies": self.checker.working_proxies,
                        "timestamp": datetime.now().isoformat()
                    }, file, indent=2)

                QMessageBox.information(
                    self, "Export Successful",
                    f"Results exported to:\n{file_path}\n\nDetailed report saved to:\n{json_path}"
                )

            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Error: {str(e)}")

    def show_info(self):
        """Show information about the application"""
        info_text = """
        <h2>Modern Proxy Checker</h2>
        <p>This application is used to test whether proxy servers are working or not.</p>

        <h3>How to Use:</h3>
        <ol>
            <li><b>File Settings:</b> You can select a file containing a proxy list or add proxies manually.</li>
            <li><b>Checker Settings:</b> You can adjust the number of threads, timeout duration, and test URLs.</li>
            <li><b>Manual Proxy Input:</b> You can enter proxies one per line (format: ip:port).</li>
            <li><b>Start:</b> Click to start proxy checking.</li>
            <li><b>Stop:</b>  Click to stop an ongoing check.</li>
            <li><b>Reset:</b> Click to reset all settings and results.</li>
        </ol>

        <h3>Results Tab:</h3>
        <p>n this tab, you can see the checking progress, statistics, and working proxies.
        You can copy working proxies to clipboard or export them to a file.</p>

        <h3>Supported Proxy Types:</h3>
        <ul>
            <li>HTTP</li>
            <li>HTTPS</li>
            <li>SOCKS4</li>
            <li>SOCKS5</li>
        </ul>

        <h3>Proxy Format:</h3>
        <p>All proxies must be in this format: <code>ip:port</code> or <code>hostname:port</code></p>
        <p><code>192.168.1.1:8080</code> or <code>proxy.example.com:3128</code></p>

        <h3>Developer:</h3>
        <p>This application is developed by <a href='https://github.com/captainmgc'>CaptainMGC</a>.</p>
        """

        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Proxy Checker About")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(info_text)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.exec_()


# Düzeltme: main() fonksiyonu sınıf dışına alındı
def main():
    app = QApplication(sys.argv)
    gui = ModernProxyCheckerGUI()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

