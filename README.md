# XSniper

**XSniper** is an ultra-advanced, stylish XSS vulnerability scanner built in python.  
It supports multiple HTTP injection points, live scan logging, scan speed and depth control, and a hi-tech dashboard UI.

## Features

- **Injection Points:**  
  - Query parameters  
  - Path segments  
  - POST body (if POST selected)  
  - HTTP headers (User-Agent, Referer, X-Forwarded-For)  
  - Cookies

- **Scan Control:**  
  - Choose HTTP method (GET/POST)  
  - Scan speed (Fast/Medium/Slow)  
  - Scan depth (1–7) via buttons (depth = number of injection types checked)

- **Live Dashboard:**  
  - Live scan log  
  - Full results table  
  - Vulnerable payloads list  
  - Vulnerability info panel  
  - Neon hi-tech UI

- **Wordlist:**  
  - Load or paste your own payloads

## Usage

1. **Install dependencies:**
    ```bash
    pip install PyQt5 requests
    ```
2. **Run the tool:**
    ```bash
    python xsniper.py
    ```
3. **How to scan:**
    - Enter target URL.
    - Select HTTP method.
    - Paste or load your payload wordlist.
    - Pick scan speed and scan depth using the buttons.
    - Click "Start Live XSS Scan".
    - Review vulnerable payloads, log, and results in the dashboard.

## Scan Depth Reference

| Depth | Injection Types                                       |
|-------|------------------------------------------------------|
| 1     | Query Parameter                                      |
| 2     | + Header: Referer                                    |
| 3     | + Path Segment                                       |
| 4     | + Header: User-Agent                                 |
| 5     | + Header: X-Forwarded-For                            |
| 6     | + Cookie                                             |
| 7     | + POST Body (if POST selected)                       |

## Screenshot
<img width="1464" height="933" alt="Screenshot at 2025-09-25 00-44-48" src="https://github.com/user-attachments/assets/33ed01f4-c827-4267-af5a-e15348526b2f" />


## Disclaimer

For educational and authorized security testing only.  
Use responsibly and **never scan sites without permission**.
---
## If you want to donate for our project, then you can :) 💰
##### Bitcoin(BTC) address: `bc1qrgakys3xn64g74422m3v6avhd7as3hgejsqs7d`
##### Ethereum(ETH) address: `0x8CC47B3d6B820D7c72b2778d3D684b430ec6BF38`
##### Polygon(POL) address: `0x8CC47B3d6B820D7c72b2778d3D684b430ec6BF38`
##### BNB smart chain(BNB): `0x8CC47B3d6B820D7c72b2778d3D684b430ec6BF38`
## Created by
**INDIAN CYBER ARMY** >>[WebDragon63](https://github.com/webdragon63)\
**YouTube Channel** [INDIAN CYBER ARMY](https://youtube.com/@webdragon63)
---
