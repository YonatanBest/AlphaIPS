# Network Intrusion Detection System

This project is a Network Intrusion Detection System (NIDS) that monitors network traffic in real-time and classifies it as either "normal" or "abnormal" based on machine learning predictions. It uses Scapy for packet sniffing and Flask for creating a web interface to display predictions.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Simulating Abnormal Traffic](#simulating-abnormal-traffic)
- [Web Interface](#web-interface)
- [License](#license)

## Features

- Real-time network traffic monitoring
- Machine learning model for classifying traffic
- Web interface to display recent predictions and historical data
- Support for handling unknown categorical feature values

## Installation

### Prerequisites

- Python 3.6 or higher
- `pip` for package management

### Clone the Repository

```bash
git clone https://github.com/yonatanbest/AlphaIPS.git
cd AlphaIPS
