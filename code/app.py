from flask import Flask, render_template, request, jsonify
import pickle
import pandas as pd
import json
from url_extractor import URLFeatureExtractor

app = Flask(__name__)

# Load model and dataset
print("Loading model...")
with open("../models/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

print("Loading dataset...")
df = pd.read_csv("../dataset/PhiUSIIL_Phishing_URL_Dataset.csv")
X = df.select_dtypes(include=['int64', 'float64'])
y = df['label']

# Get feature names
feature_names = X.columns.tolist()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/demo', methods=['GET'])
def get_demo():
    """Get sample legitimate and phishing URLs for demo"""
    legit_sample = X[y == 0].iloc[0].to_dict()
    phish_sample = X[y == 1].iloc[0].to_dict()
    
    legit_pred, legit_prob = model.predict([list(legit_sample.values())])[0], model.predict_proba([list(legit_sample.values())])[0]
    phish_pred, phish_prob = model.predict([list(phish_sample.values())])[0], model.predict_proba([list(phish_sample.values())])[0]
    
    return jsonify({
        'legitimate': {
            'prediction': int(legit_pred),
            'legitimate_prob': float(legit_prob[0]) * 100,
            'phishing_prob': float(legit_prob[1]) * 100
        },
        'phishing': {
            'prediction': int(phish_pred),
            'legitimate_prob': float(phish_prob[0]) * 100,
            'phishing_prob': float(phish_prob[1]) * 100
        }
    })

@app.route('/api/predict', methods=['POST'])
def predict():
    """Predict if URL features are phishing or legitimate"""
    try:
        data = request.json
        features = data.get('features', {})
        
        # Ensure all 51 features are present
        feature_vector = [features.get(name, 0) for name in feature_names]
        
        prediction = model.predict([feature_vector])[0]
        probabilities = model.predict_proba([feature_vector])[0]
        
        return jsonify({
            'success': True,
            'prediction': int(prediction),
            'legitimate_prob': float(probabilities[0]) * 100,
            'phishing_prob': float(probabilities[1]) * 100,
            'result': 'Legitimate' if prediction == 0 else 'Phishing'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get model statistics"""
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    
    y_pred = model.predict(X)
    
    return jsonify({
        'total_urls': len(df),
        'legitimate_urls': int((y == 0).sum()),
        'phishing_urls': int((y == 1).sum()),
        'accuracy': float(accuracy_score(y, y_pred)) * 100,
        'precision': float(precision_score(y, y_pred)) * 100,
        'recall': float(recall_score(y, y_pred)) * 100,
        'f1_score': float(f1_score(y, y_pred)) * 100,
        'num_features': len(feature_names)
    })

@app.route('/api/check-url', methods=['POST'])
def check_url():
    """Check if a URL is phishing or legitimate using heuristics"""
    try:
        data = request.json
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = 'https://' + url
        
        # Use URL heuristics for quick phishing detection
        from url_heuristics import detect_phishing_heuristics
        
        result, confidence, features_dict = detect_phishing_heuristics(url)
        
        # Simplify features for JSON serialization
        simplified_features = {
            'Domain': features_dict.get('Domain', ''),
            'TLD': features_dict.get('TLD', ''),
            'IsKnownLegitimate': features_dict.get('IsKnownLegitimate', False),
            'KnownPhishingPattern': features_dict.get('KnownPhishingPattern'),
            'ImpersonationAttempt': features_dict.get('ImpersonationAttempt'),
            'IsIPAddress': features_dict.get('IsIPAddress', False),
            'HasHTTPS': features_dict.get('HasHTTPS', False),
            'SuspiciousTLD': features_dict.get('SuspiciousTLD', False),
            'SuspiciousKeywords': features_dict.get('SuspiciousKeywords', []),
            'HasAtSymbol': features_dict.get('HasAtSymbol', False),
            'URLLength': features_dict.get('URLLength', 0),
            'DomainLength': features_dict.get('DomainLength', 0),
            'DigitsInDomain': features_dict.get('DigitsInDomain', 0),
            'HasHyphenInDomain': features_dict.get('HasHyphenInDomain', False),
            'TooManySubdomains': features_dict.get('TooManySubdomains', False),
        }
        
        # Get risk and trust factors as strings
        risk_factors = []
        trust_factors = []
        
        if 'RiskFactors' in features_dict:
            risk_factors = [f[0] for f in features_dict['RiskFactors']]
        
        if 'TrustFactors' in features_dict:
            trust_factors = [f[0] for f in features_dict['TrustFactors']]
        
        return jsonify({
            'success': True,
            'url': url,
            'prediction': 1 if result == 'Phishing' else 0,
            'result': result,
            'confidence': confidence,
            'features': simplified_features,
            'risk_factors': risk_factors,
            'trust_factors': trust_factors
        })
    except Exception as e:
        import traceback
        print("Error:", traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
