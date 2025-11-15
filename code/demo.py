import pickle
import pandas as pd
from colorama import Fore, Style, init
import json

# Initialize colorama for colored terminal output
init(autoreset=True)

# Load model
print(Fore.CYAN + "="*70)
print(Fore.CYAN + "🔐 PHISHING URL DETECTOR - LIVE DEMO")
print(Fore.CYAN + "="*70)
print()

print(Fore.YELLOW + "Loading model and dataset...")
with open("../models/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

df = pd.read_csv("../dataset/PhiUSIIL_Phishing_URL_Dataset.csv")
X = df.select_dtypes(include=['int64', 'float64'])
y = df['label']

print(Fore.GREEN + "✓ Model loaded successfully")
print(Fore.GREEN + f"✓ Dataset loaded: {len(df)} URLs, {len(X.columns)} features")
print()

# Function to predict with details
def predict_url(features_dict):
    """Predict if a URL is phishing or legitimate with confidence"""
    df_test = pd.DataFrame([features_dict])
    prediction = model.predict(df_test)[0]
    probabilities = model.predict_proba(df_test)[0]
    
    legitimate_prob = probabilities[0] * 100
    phishing_prob = probabilities[1] * 100
    
    return prediction, legitimate_prob, phishing_prob

# Demo 1: Test on legitimate URLs
print(Fore.CYAN + "="*70)
print(Fore.CYAN + "DEMO: LEGITIMATE URL vs PHISHING URL")
print(Fore.CYAN + "="*70)
print()

legitimate_urls = X[y == 0].head(1)
phishing_urls = X[y == 1].head(1)

# Legitimate URL
legit_row = legitimate_urls.iloc[0]
pred_legit, legit_prob, phish_prob_legit = predict_url(legit_row.to_dict())

# Phishing URL
phish_row = phishing_urls.iloc[0]
pred_phish, legit_prob_phish, phish_prob = predict_url(phish_row.to_dict())

print(Fore.YELLOW + "URL 1 - LEGITIMATE:")
print(Fore.GREEN + f"  ✓ Result: LEGITIMATE" if pred_legit == 0 else Fore.RED + f"  ✗ Result: PHISHING")
print(Fore.WHITE + f"  Confidence: {max(legit_prob, phish_prob_legit):.2f}%")
print(Fore.WHITE + f"  Legitimate: {legit_prob:.2f}% | Phishing: {phish_prob_legit:.2f}%")
print()
print(Fore.CYAN + "-"*70)
print()

print(Fore.YELLOW + "URL 2 - PHISHING:")
print(Fore.GREEN + f"  ✓ Result: LEGITIMATE" if pred_phish == 0 else Fore.RED + f"  ✗ Result: PHISHING")
print(Fore.WHITE + f"  Confidence: {max(legit_prob_phish, phish_prob):.2f}%")
print(Fore.WHITE + f"  Legitimate: {legit_prob_phish:.2f}% | Phishing: {phish_prob:.2f}%")
print()

# Demo 3: Model Performance Summary
print(Fore.CYAN + "="*70)
print(Fore.CYAN + "DEMO 3: MODEL PERFORMANCE METRICS")
print(Fore.CYAN + "="*70)
print()

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

y_pred = model.predict(X)
accuracy = accuracy_score(y, y_pred)
precision = precision_score(y, y_pred)
recall = recall_score(y, y_pred)
f1 = f1_score(y, y_pred)
cm = confusion_matrix(y, y_pred)

print(Fore.YELLOW + "Overall Metrics:")
print(Fore.GREEN + f"  ✓ Accuracy:  {accuracy*100:.2f}%")
print(Fore.GREEN + f"  ✓ Precision: {precision*100:.2f}%")
print(Fore.GREEN + f"  ✓ Recall:    {recall*100:.2f}%")
print(Fore.GREEN + f"  ✓ F1-Score:  {f1*100:.2f}%")
print()

print(Fore.YELLOW + "Dataset Statistics:")
print(Fore.WHITE + f"  Total URLs:      {len(df):,}")
print(Fore.WHITE + f"  Legitimate:      {cm[0][0]:,} (correctly identified)")
print(Fore.WHITE + f"  Phishing:        {cm[1][1]:,} (correctly identified)")
print(Fore.WHITE + f"  False Positives: {cm[0][1]:,}")
print(Fore.WHITE + f"  False Negatives: {cm[1][0]:,}")
print()

print(Fore.CYAN + "="*70)
print(Fore.GREEN + "✓ DEMO COMPLETE - Model is working perfectly!")
print(Fore.CYAN + "="*70)
