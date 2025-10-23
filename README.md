
# Anomaly Detection in Network Traffic Using Advanced Machine Learning Techniques

## Project Overview

This project focuses on detecting anomalies in network traffic using advanced machine learning techniques. Network security is a critical challenge due to increasing cyber threats. Traditional intrusion detection systems (IDS) often struggle with new or zero-day attacks, high false positive rates, and real-time performance limitations. This project proposes a machine learning-based approach to address these issues effectively.

The system leverages both supervised and unsupervised learning models, including:

* **Isolation Forest**
* **Extra Trees Classifier**
* **Gradient Boosting Classifier**
* **MLP Classifier**
* **DNN (Deep Neural Network)**
* **CNN (Convolutional Neural Network)**
* **ANN (Artificial Neural Network)**

The models are trained and tested on network traffic datasets like **NSL-KDD** and **CICIDS2017**, ensuring robust anomaly detection.

---

## Features

* High detection accuracy using deep learning models
* Zero-day attack detection
* Reduced false positives through optimized classification
* Real-time intrusion monitoring and alerts via a web interface
* Scalable and adaptive to new attack patterns
* Integration with firewall systems for automated protection

---

## System Architecture

The project follows a **three-tier architecture**:

1. **Presentation Layer:** Django-based web interface for users and administrators
2. **Application Layer:** Handles machine learning model training, prediction, and business logic
3. **Data Layer:** Manages network traffic datasets, user information, and prediction results

---

## Installation and Setup

### Prerequisites

* Python 3.8+
* Anaconda
* Libraries:

  * `numpy`
  * `pandas`
  * `matplotlib`
  * `seaborn`
  * `scikit-learn`
  * `imblearn`
  * `tensorflow`
  * `django`

### Steps

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd <repository-folder>
   ```
2. Create a virtual environment:

   ```bash
   conda create -n anomaly_detection python=3.8
   conda activate anomaly_detection
   ```
3. Install required packages:

   ```bash
   pip install -r requirements.txt
   ```
4. Run the Django server:

   ```bash
   python manage.py runserver
   ```
5. Open the web interface at `http://127.0.0.1:8000/`

---

## Usage

* **Admin/Service Provider:** Train and test classifiers, view prediction results, authorize users.
* **Remote User:** Register, login, predict anomaly types, view personal profiles and prediction results.

---

## Machine Learning Workflow

1. Data preprocessing and feature scaling
2. Dataset split into training, validation, and testing sets
3. Model selection and hyperparameter tuning using k-fold cross-validation
4. Ensemble learning and performance evaluation
5. Visualization of results and anomaly predictions

---

## Datasets Used

* NSL-KDD
* CICIDS2017

These datasets contain labeled network traffic data with normal and anomalous activities.


