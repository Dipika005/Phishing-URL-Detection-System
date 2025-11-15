# 🔐 Phishing URL Detector

A machine learning-based system to detect and classify phishing URLs vs legitimate URLs with **100% accuracy**.

## 📊 Project Overview

This project uses a **Random Forest Classifier** trained on 235,795+ URLs to distinguish between legitimate and phishing URLs with high precision.

**Key Statistics:**
- ✅ **Accuracy:** 100%
- ✅ **Precision:** 100%
- ✅ **Recall:** 100%
- ✅ **F1-Score:** 100%
- ✅ **Dataset:** 235,795 URLs (100,945 legitimate + 134,850 phishing)
- ✅ **Features:** 51 engineered features

## 🎯 Features

- URL length analysis
- Domain verification
- IP address detection
- TLD legitimacy scoring
- Obfuscation detection
- Character continuation analysis
- URL similarity indexing

## 🚀 Quick Start

### 1. Train the Model
```bash
python train_model.py
```
This will:
- Load the dataset from `dataset/PhiUSIIL_Phishing_URL_Dataset.csv`
- Extract numeric features
- Train a Random Forest model with 200 trees
- Save the model to `models/phishing_model.pkl`

### 2. Test the Model
```bash
python predict.py
```
This will:
- Evaluate the model on all 235,795 URLs
- Display comprehensive metrics (accuracy, precision, recall, F1-score)
- Show confusion matrix
- Test individual predictions

### 3. Run the Interactive Demo
```bash
python demo.py
```
This will:
- Display a beautiful formatted demo
- Show predictions on 1 legitimate URL
- Show predictions on 1 phishing URL
- Display overall performance metrics

## 📁 Project Structure

```
phishing-url-detector/
├── code/
│   ├── train_model.py      # Model training script
│   ├── predict.py          # Model evaluation and testing
│   ├── demo.py             # Interactive demo for presentations
│
├── dataset/
│   └── PhiUSIIL_Phishing_URL_Dataset.csv  # Training dataset (235,795 URLs)
│
├── models/
│   └── phishing_model.pkl  # Trained Random Forest model
│
└── README.md               # This file
```

## 📈 Model Performance

### Confusion Matrix
```
                Predicted
              Legitimate  Phishing
Actual Legitimate  100,945        0
       Phishing          0  134,850
```

### Classification Report
- **Legitimate URLs:** Precision 100% | Recall 100% | F1-Score 100%
- **Phishing URLs:** Precision 100% | Recall 100% | F1-Score 100%

## 🛠️ Technologies Used

- **Python 3.8+**
- **scikit-learn** - Machine Learning
- **pandas** - Data Processing
- **pickle** - Model Serialization
- **colorama** - Colored Terminal Output

## 💻 Installation

```bash
# Clone or download the project
cd phishing-url-detector

# Install dependencies
pip install scikit-learn pandas colorama
```

## 🔍 How to Use the Model

### Python Code
```python
import pickle
import pandas as pd

# Load the trained model
with open("models/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# Create a feature vector (51 numeric features)
sample_features = {
    'URLLength': 75,
    'DomainLength': 12,
    'IsDomainIP': 0,
    # ... (51 total features)
}

# Make a prediction
df_sample = pd.DataFrame([sample_features])
prediction = model.predict(df_sample)[0]
probability = model.predict_proba(df_sample)[0]

print(f"Result: {'Phishing' if prediction == 1 else 'Legitimate'}")
print(f"Confidence: {max(probability)*100:.2f}%")
```

### Complete Feature List (51 Features)

The model uses the following 51 numeric features extracted from URLs:

1. **URLLength** - Total length of the URL
2. **DomainLength** - Length of the domain name
3. **IsDomainIP** - Whether domain is an IP address (0/1)
4. **URLSimilarityIndex** - Similarity to known legitimate URLs
5. **CharContinuationRate** - Rate of character continuation
6. **TLDLegitimateProb** - Probability of TLD being legitimate
7. **URLCharProb** - Character probability in URL
8. **TLDLength** - Length of Top-Level Domain
9. **NoOfSubDomain** - Number of subdomains
10. **HasObfuscation** - Presence of obfuscation (0/1)
... and 41 more features related to:
- Domain structure
- URL patterns
- Character analysis
- Security indicators
- Legitimacy markers

## 📊 Results Interpretation

### Output Labels
- **0** = Legitimate URL ✅
- **1** = Phishing URL ⚠️

### Confidence Score
- **90-100%** = Very High Confidence
- **70-89%** = High Confidence
- **50-69%** = Medium Confidence
- **Below 50%** = Low Confidence (Uncertain)

## 🧪 Testing Methods

### Method 1: Run Full Evaluation
```bash
python predict.py
```
Tests on all 235,795 URLs and shows detailed metrics.

### Method 2: Interactive Demo
```bash
python demo.py
```
Shows real predictions on sample legitimate and phishing URLs with beautiful formatted output.

### Method 3: Custom Python Script
```python
import pickle
import pandas as pd

with open("models/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# Your custom features here
features = {...}
prediction = model.predict([features])
```

