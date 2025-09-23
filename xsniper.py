import sys
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QSplitter, QFrame, QListWidget, QButtonGroup
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class XSSScanWorker(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)
    info_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, url, method, wordlist, delay, depth):
        super().__init__()
        self.url = url
        self.method = method
        self.wordlist = wordlist
        self.delay = delay
        self.depth = depth

    def run(self):
        vuln_types = set()
        scanned = 0
        sections = []
        if self.depth >= 1: sections.append(('Query Parameter', self.inject_query_param))
        if self.depth >= 2: sections.append(('Header: Referer', lambda p: self.inject_header(p, 'Referer')))
        if self.depth >= 3: sections.append(('Path Segment', self.inject_path_segment))
        if self.depth >= 4: sections.append(('Header: User-Agent', lambda p: self.inject_header(p, 'User-Agent')))
        if self.depth >= 5: sections.append(('Header: X-Forwarded-For', lambda p: self.inject_header(p, 'X-Forwarded-For')))
        if self.depth >= 6: sections.append(('Cookie', self.inject_cookie))
        if self.depth >= 7 and self.method == "POST": sections.append(('POST Body', self.inject_post_body))
        total = len(self.wordlist) * len(sections)
        for payload in self.wordlist:
            for name, func in sections:
                self.log_signal.emit(f"Scanning {name} with payload: {payload}")
                result = func(payload)
                self.result_signal.emit(result)
                scanned += 1
                if result['vulnerable']: vuln_types.add(result['type'])
                time.sleep(self.delay)
                self.info_signal.emit(f"Progress: {scanned}/{total} tests")
        summary = (
            f"Site is {'XSS vulnerable' if vuln_types else 'not XSS vulnerable'}.\n"
            f"Found types: {', '.join(vuln_types) if vuln_types else 'None'}"
        )
        self.info_signal.emit(summary)
        self.finished_signal.emit()

    def inject_query_param(self, payload):
        try:
            u = urlparse(self.url)
            query = parse_qs(u.query)
            if not query: query = {"xss": [payload]}
            else:
                for k in query: query[k] = [payload]
            new_query = urlencode(query, doseq=True)
            new_url = urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, u.fragment))
            r = requests.get(new_url, timeout=7)
            vulnerable = payload in r.text
            vuln_type = "Reflected" if vulnerable else "Unknown"
            return {
                "place": "Query Parameter",
                "payload": payload,
                "vulnerable": vulnerable,
                "type": vuln_type,
                "details": f"Injected into query parameters.",
                "response": r.text[:100]
            }
        except Exception as e:
            return {
                "place": "Query Parameter",
                "payload": payload,
                "vulnerable": False,
                "type": "Error",
                "details": str(e),
                "response": ""
            }

    def inject_path_segment(self, payload):
        try:
            u = urlparse(self.url)
            path = u.path.rstrip('/') + f"/{payload}"
            new_url = urlunparse((u.scheme, u.netloc, path, u.params, u.query, u.fragment))
            r = requests.get(new_url, timeout=7)
            vulnerable = payload in r.text
            vuln_type = "Reflected" if vulnerable else "Unknown"
            return {
                "place": "Path Segment",
                "payload": payload,
                "vulnerable": vulnerable,
                "type": vuln_type,
                "details": f"Appended payload to path segment.",
                "response": r.text[:100]
            }
        except Exception as e:
            return {
                "place": "Path Segment",
                "payload": payload,
                "vulnerable": False,
                "type": "Error",
                "details": str(e),
                "response": ""
            }

    def inject_post_body(self, payload):
        try:
            r = requests.post(self.url, data={"xss": payload}, timeout=7)
            vulnerable = payload in r.text
            vuln_type = "Reflected" if vulnerable else "Unknown"
            return {
                "place": "POST Body",
                "payload": payload,
                "vulnerable": vulnerable,
                "type": vuln_type,
                "details": f"Injected payload as POST body field 'xss'.",
                "response": r.text[:100]
            }
        except Exception as e:
            return {
                "place": "POST Body",
                "payload": payload,
                "vulnerable": False,
                "type": "Error",
                "details": str(e),
                "response": ""
            }

    def inject_header(self, payload, header):
        try:
            headers = {header: payload}
            r = requests.get(self.url, headers=headers, timeout=7)
            vulnerable = payload in r.text
            vuln_type = "Reflected" if vulnerable else "Unknown"
            return {
                "place": f"HTTP Header: {header}",
                "payload": payload,
                "vulnerable": vulnerable,
                "type": vuln_type,
                "details": f"Injected payload as HTTP header '{header}'.",
                "response": r.text[:100]
            }
        except Exception as e:
            return {
                "place": f"HTTP Header: {header}",
                "payload": payload,
                "vulnerable": False,
                "type": "Error",
                "details": str(e),
                "response": ""
            }

    def inject_cookie(self, payload):
        try:
            cookies = {"xss_cookie": payload}
            r = requests.get(self.url, cookies=cookies, timeout=7)
            vulnerable = payload in r.text
            vuln_type = "Reflected" if vulnerable else "Unknown"
            return {
                "place": "Cookie",
                "payload": payload,
                "vulnerable": vulnerable,
                "type": vuln_type,
                "details": f"Injected payload as cookie 'xss_cookie'.",
                "response": r.text[:100]
            }
        except Exception as e:
            return {
                "place": "Cookie",
                "payload": payload,
                "vulnerable": False,
                "type": "Error",
                "details": str(e),
                "response": ""
            }

class XSSLiveDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HiTec XSS Live Dashboard")
        self.setGeometry(100, 100, 1450, 900)
        self.setStyleSheet("""
            QMainWindow { background: #070a13; border: none; }
            QLabel, QLineEdit, QPushButton, QComboBox, QTextEdit, QTableWidget { color: #b3f7ff; font-family: 'Orbitron', 'Consolas'; }
            QLineEdit, QComboBox, QTextEdit { background: #10151c; border: 2px solid #07c6ff; border-radius: 7px; padding: 4px; }
            QPushButton { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0fd9ff, stop:1 #07c6ff); border-radius: 7px; font-weight: bold; }
            QPushButton:checked, QPushButton[active="true"] { border: 2px solid #e7ff20; background: #0fd9ff; color: #070a13; }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #07c6ff, stop:1 #0fd9ff); }
            QTableWidget { background: #10151c; border: 2px solid #07c6ff; border-radius: 7px; }
            QHeaderView::section { background-color: #070a13; color: #0fd9ff; border: none; font-weight: bold; }
            QTextEdit { font-size: 14px; }
            #logPanel { background: #0d1e28; color: #aafff7; font-family: 'Share Tech Mono', 'Consolas'; border: 2px solid #07c6ff; border-radius: 7px; }
        """)

        mainWidget = QWidget()
        mainLayout = QHBoxLayout()
        mainWidget.setLayout(mainLayout)
        self.setCentralWidget(mainWidget)

        # --- Control Panel ---
        controlPanel = QFrame()
        controlPanel.setFrameShape(QFrame.StyledPanel)
        controlLayout = QVBoxLayout()
        controlPanel.setLayout(controlLayout)
        controlPanel.setMaximumWidth(400)
        controlPanel.setStyleSheet("background: #0d1e28; border-radius: 15px;")

        self.urlInput = QLineEdit()
        self.urlInput.setPlaceholderText("Target URL (e.g., https://target.com)")
        controlLayout.addWidget(QLabel("Target URL:"))
        controlLayout.addWidget(self.urlInput)

        self.methodCombo = QComboBox()
        self.methodCombo.addItems(["GET", "POST"])
        controlLayout.addWidget(QLabel("HTTP Method:"))
        controlLayout.addWidget(self.methodCombo)

        self.wordlistText = QTextEdit()
        self.wordlistText.setPlaceholderText("Paste payloads here or load a wordlist file")
        controlLayout.addWidget(QLabel("Wordlist Payloads:"))
        controlLayout.addWidget(self.wordlistText)

        wordlistBtn = QPushButton("Load Wordlist File")
        wordlistBtn.clicked.connect(self.loadWordlist)
        controlLayout.addWidget(wordlistBtn)

        # Speed Control
        self.speedCombo = QComboBox()
        self.speedCombo.addItems(["Fast", "Medium", "Slow"])
        self.speedCombo.setCurrentIndex(0)
        controlLayout.addWidget(QLabel("Scan Speed:"))
        controlLayout.addWidget(self.speedCombo)

        # --- Depth Buttons ---
        depthLabel = QLabel("Scan Depth:")
        controlLayout.addWidget(depthLabel)
        depthBtnsLayout = QHBoxLayout()
        self.depthButtons = []
        self.depthBtnGroup = QButtonGroup()
        for i in range(1, 8):
            btn = QPushButton(str(i))
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, depth=i: self.setDepth(depth))
            if i == 1:
                btn.setChecked(True)
                btn.setProperty("active", True)
            else:
                btn.setProperty("active", False)
            self.depthBtnGroup.addButton(btn, i)
            self.depthButtons.append(btn)
            depthBtnsLayout.addWidget(btn)
        controlLayout.addLayout(depthBtnsLayout)
        self.scanDepth = 1

        self.scanBtn = QPushButton("Start Live XSS Scan")
        self.scanBtn.clicked.connect(self.startScan)
        controlLayout.addWidget(self.scanBtn)

        self.statusLabel = QLabel("")
        self.statusLabel.setStyleSheet("color: #0fd9ff; font-size: 16px;")
        controlLayout.addWidget(self.statusLabel)
        controlLayout.addStretch(1)

        # --- Results & Panels ---
        rightPanel = QSplitter(Qt.Vertical)
        rightPanel.setStyleSheet("border: none;")

        self.resultsTable = QTableWidget()
        self.resultsTable.setColumnCount(6)
        self.resultsTable.setHorizontalHeaderLabels([
            "Place", "Payload", "Vulnerable", "Type", "Details", "Response"
        ])
        self.resultsTable.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.resultsTable.setFont(QFont("Consolas", 11))

        resultsFrame = QFrame()
        resultsLayout = QVBoxLayout()
        resultsFrame.setLayout(resultsLayout)
        resultsLayout.addWidget(QLabel("Scan Results:"))
        resultsLayout.addWidget(self.resultsTable)
        resultsFrame.setStyleSheet("background: #10151c; border-radius: 10px;")

        infoFrame = QFrame()
        infoLayout = QVBoxLayout()
        infoFrame.setLayout(infoLayout)
        self.infoText = QTextEdit()
        self.infoText.setReadOnly(True)
        infoLayout.addWidget(QLabel("Vulnerability Info:"))
        infoLayout.addWidget(self.infoText)
        infoFrame.setStyleSheet("background: #10151c; border-radius: 10px;")

        logFrame = QFrame()
        logLayout = QVBoxLayout()
        logFrame.setLayout(logLayout)
        self.logPanel = QTextEdit()
        self.logPanel.setObjectName("logPanel")
        self.logPanel.setReadOnly(True)
        logLayout.addWidget(QLabel("Live Scan Log:"))
        logLayout.addWidget(self.logPanel)
        logFrame.setMaximumHeight(160)
        logFrame.setStyleSheet("background: #0d1e28; border-radius: 10px;")

        vulnFrame = QFrame()
        vulnLayout = QVBoxLayout()
        vulnFrame.setLayout(vulnLayout)
        vulnLabel = QLabel("Vulnerable Payloads:")
        vulnLabel.setStyleSheet("color: #0fd9ff; font-weight: bold;")
        self.vulnList = QListWidget()
        self.vulnList.setStyleSheet("color: red;")
        vulnLayout.addWidget(vulnLabel)
        vulnLayout.addWidget(self.vulnList)
        vulnFrame.setStyleSheet("background: #10151c; border-radius: 10px;")
        self.vulnerable_payloads = set()

        rightPanel.addWidget(resultsFrame)
        rightPanel.addWidget(vulnFrame)
        rightPanel.addWidget(infoFrame)
        rightPanel.addWidget(logFrame)
        rightPanel.setSizes([400, 200, 200, 150])

        mainLayout.addWidget(controlPanel)
        mainLayout.addWidget(rightPanel)

        self.worker = None

    def setDepth(self, depth):
        self.scanDepth = depth
        for i, btn in enumerate(self.depthButtons, 1):
            btn.setChecked(i == depth)
            btn.setProperty("active", i == depth)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def loadWordlist(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Choose Wordlist", "", "Text Files (*.txt)")
        if fname:
            with open(fname) as f:
                self.wordlistText.setText(f.read())
            self.logPanel.append(f"Loaded wordlist from {fname}")

    def startScan(self):
        url = self.urlInput.text().strip()
        method = self.methodCombo.currentText()
        wordlist = [w for w in self.wordlistText.toPlainText().splitlines() if w.strip()]
        speed = self.speedCombo.currentText()
        delay_map = {"Fast": 0.1, "Medium": 0.5, "Slow": 1.2}
        delay = delay_map.get(speed, 0.1)
        depth = self.scanDepth
        if not url or not wordlist:
            self.statusLabel.setText("Please enter a URL and at least one payload.")
            return

        self.statusLabel.setText("Scanning...")
        self.resultsTable.setRowCount(0)
        self.infoText.clear()
        self.logPanel.clear()
        self.vulnList.clear()
        self.vulnerable_payloads.clear()

        self.worker = XSSScanWorker(url, method, wordlist, delay, depth)
        self.worker.log_signal.connect(self.logPanel.append)
        self.worker.result_signal.connect(self.addResult)
        self.worker.info_signal.connect(self.infoText.setText)
        self.worker.finished_signal.connect(lambda: self.statusLabel.setText("Scan complete."))

        self.worker.start()

    def addResult(self, res):
        i = self.resultsTable.rowCount()
        self.resultsTable.insertRow(i)
        self.resultsTable.setItem(i, 0, QTableWidgetItem(res['place']))
        self.resultsTable.setItem(i, 1, QTableWidgetItem(res['payload']))
        self.resultsTable.setItem(i, 2, QTableWidgetItem("Yes" if res['vulnerable'] else "No"))
        self.resultsTable.setItem(i, 3, QTableWidgetItem(res.get('type', 'Unknown')))
        self.resultsTable.setItem(i, 4, QTableWidgetItem(res.get('details', '')))
        self.resultsTable.setItem(i, 5, QTableWidgetItem(res['response']))
        # If this result is vulnerable, add to the separate list (deduplicated)
        if res.get('vulnerable'):
            payload = res.get('payload')
            label = f"{res['place']}: {payload}"
            if label not in self.vulnerable_payloads:
                self.vulnerable_payloads.add(label)
                self.vulnList.addItem(label)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = XSSLiveDashboard()
    window.show()
    sys.exit(app.exec_())
