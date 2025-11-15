import pickle
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

# Load model
print("Loading model...")
with open("../models/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

# Load dataset
print("Loading dataset...")
df = pd.read_csv("../dataset/PhiUSIIL_Phishing_URL_Dataset.csv")

# Prepare data (same as training)
X = df.select_dtypes(include=['int64', 'float64'])
y = df['label']

# Get feature names
feature_names = X.columns.tolist()

print(f"\nFeatures used by model: {len(feature_names)} features")
print(f"Feature names: {feature_names[:5]}... (showing first 5)")

# Function to predict using numeric features
def predict_url(features_dict):
    """Predict if a URL is phishing (1) or legitimate (0)"""
    df_test = pd.DataFrame([features_dict])
    prediction = model.predict(df_test)[0]
    probability = model.predict_proba(df_test)[0]
    return prediction, probability

# Test 1: Make predictions on entire dataset
print("\n" + "="*60)
print("TEST 1: FULL DATASET EVALUATION")
print("="*60)
y_pred = model.predict(X)

accuracy = accuracy_score(y, y_pred)
precision = precision_score(y, y_pred)
recall = recall_score(y, y_pred)
f1 = f1_score(y, y_pred)

print(f"\nAccuracy:  {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall:    {recall:.4f}")
print(f"F1-Score:  {f1:.4f}")

print("\nConfusion Matrix:")
cm = confusion_matrix(y, y_pred)
print(cm)
print(f"True Negatives: {cm[0][0]}")
print(f"False Positives: {cm[0][1]}")
print(f"False Negatives: {cm[1][0]}")
print(f"True Positives: {cm[1][1]}")

print("\nClassification Report:")
print(classification_report(y, y_pred, target_names=['Legitimate', 'Phishing']))

# Test 2: Test on individual samples
print("\n" + "="*60)
print("TEST 2: INDIVIDUAL SAMPLE PREDICTIONS")
print("="*60)

# Get a few sample rows from each class
legitimate_samples = X[y == 0].head(2)
phishing_samples = X[y == 1].head(2)

print("\nLegitimate URL predictions:")
for idx, (i, row) in enumerate(legitimate_samples.iterrows(), 1):
    pred, prob = predict_url(row.to_dict())
    print(f"  Sample {idx}: Predicted={'Phishing' if pred==1 else 'Legitimate'} (confidence: {max(prob)*100:.2f}%)")

print("\nPhishing URL predictions:")
for idx, (i, row) in enumerate(phishing_samples.iterrows(), 1):
    pred, prob = predict_url(row.to_dict())
    print(f"  Sample {idx}: Predicted={'Phishing' if pred==1 else 'Legitimate'} (confidence: {max(prob)*100:.2f}%)")

print("\n" + "="*60)
print("Testing complete!")
print("="*60)
