# SniffX v2 - iOS API Traffic Interceptor

![Frida](https://img.shields.io/badge/Frida-16.5.6-blue) 
![iOS](https://img.shields.io/badge/iOS-Jailbreak%20Bypass-green)
![Security](https://img.shields.io/badge/Security-Bypass-red)

## Overview
SniffX v2 is a Frida-based tool for intercepting iOS API traffic, bypassing SSL Pinning, and extracting API endpoints used by an application.

## Features
- **Intercept API Requests**: Capture outgoing requests from iOS applications.
- **Bypass SSL Pinning**: Disable SSL Pinning to inspect encrypted traffic.
- **Filter API Calls**: Target specific API endpoints.
- **List All Endpoints**: Extract and display all API endpoints used by an application.

## Installation
```sh
pip install frida
```

## Usage
### Attach to an App and Bypass SSL Pinning
```sh
python3 sniffx.py <App>
```

### Intercept Only Specific API Requests
```sh
python3 sniffx.py <App> --api /login
```

### Enable SSL Pinning Bypass Only
```sh
python3 sniffx.py <App> --ssl-bypass-only
```

### Extract and List All API Endpoints
```sh
python3 sniffx.py <App> --list-endpoints
```

## Author
**Abdulrahman Al-Hakami**

