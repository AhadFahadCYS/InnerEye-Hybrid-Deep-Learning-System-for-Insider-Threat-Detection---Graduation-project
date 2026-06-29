InnerEye – Hybrid Deep Learning System for Insider Threat Detection

📖 Overview

InnerEye is a hybrid deep learning system developed to detect insider threats by analyzing employee behavioral patterns within enterprise environments.

The system combines Autoencoder and LSTM Autoencoder models with contextual risk analysis to identify anomalous user activities, calculate dynamic risk scores, and generate explainable security alerts through an interactive dashboard.

The project was developed as a Graduation Project in Cybersecurity at Princess Nourah bint Abdulrahman University.

---

🚀 Key Features

* Hybrid Deep Learning Detection
* User Behavior Profiling
* Context-Aware Risk Scoring
* Explainable Security Alerts
* Interactive Dashboard
* PDF & CSV Report Generation
* Behavioral Trend Visualization
* Insider Threat Detection using the CERT Insider Threat Dataset

---

🧠 Detection Workflow

**1. Data Collection**

The system analyzes user activity collected from multiple enterprise log sources:

* Logon / Logoff
* File Access
* HTTP Browsing
* USB Device Activity
* Employee Information (LDAP)

**2. Data Preprocessing**

* Data Cleaning
* Feature Engineering
* User Behavior Profiling
* Feature Scaling
* Sequence Generation

**3. Hybrid Detection Model**

The detection engine combines:

* Autoencoder
* LSTM Autoencoder

The models learn normal user behavior and identify abnormal activities using reconstruction error and sequential behavior analysis.

**4. Risk Assessment**

Detected anomalies are enriched with contextual information such as:

* Login Time
* Device Usage
* File Access
* User Role

A dynamic Risk Score is calculated for every detected event.

**5. Alert Generation**

When suspicious behavior exceeds the predefined threshold, the system generates:

* Explainable Alerts
* Risk Score
* User Information
* Detection Reason

---

🛠️ Technologies

* Python
* TensorFlow / Keras
* Flask
* Pandas
* NumPy
* Scikit-learn
* HTML
* CSS
* JavaScript

---

📊 Dataset

This project uses the CERT Insider Threat Dataset (r5.2) to simulate realistic enterprise user behavior for insider threat detection.

---

👥 Team Members

* Ahad Fahad Alotaibi
* Reema Mohaimeed Alosaimi
* Njoud Ahmed Almusallam
* Layan Khalid Alharthi
* Hadeel Abduallah Alrashidi

---

🎓 Graduation Project

Cybersecurity Department

Princess Nourah bint Abdulrahman University

2026


