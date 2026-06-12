# CyberShield Security Suite

## Overview

CyberShield Security Suite is a web-based cybersecurity toolkit developed using Python Flask. The application provides multiple security-focused utilities, including phishing detection, password strength analysis, and file integrity verification through cryptographic hashing.

The project aims to help users identify common security threats and improve cybersecurity awareness through an interactive and user-friendly interface.

## Features

### Phishing Detection

* Analyze suspicious URLs and email content.
* Detect common phishing indicators.
* Display risk assessment results.

### Password Strength Analyzer

* Evaluate password complexity.
* Calculate password strength metrics.
* Provide recommendations for stronger passwords.

### File Integrity Checker

* Generate SHA-256 hashes for files.
* Verify file integrity.
* Detect unauthorized modifications.

### Security Reports

* Generate analysis reports.
* Store scan results for review.
* Track security assessments.

## Technologies Used

### Backend

* Python
* Flask

### Frontend

* HTML5
* CSS3
* JavaScript

### Security Concepts

* SHA-256 Hashing
* Password Entropy Analysis
* Phishing Detection Techniques
* File Integrity Monitoring

## Project Structure

```text
CyberShield/
│
├── app.py
├── config.py
├── requirements.txt
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── templates/
│   ├── index.html
│   ├── phishing.html
│   ├── password.html
│   └── integrity.html
│
└── utils/
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/CyberShield-Security-Suite.git
```

2. Navigate to the project folder:

```bash
cd CyberShield-Security-Suite
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the application:

```bash
python app.py
```

5. Open in browser:

```text
http://127.0.0.1:5000
```

## Future Enhancements

* User Authentication System
* Database Integration
* Malware File Analysis
* Security Dashboard Analytics
* Real-Time Threat Intelligence Integration

## Author

Dharani L

Cybersecurity Student | SA Engineering College

## License

This project is developed for educational and learning purposes.
