# 🌐 How to Run the Web Interface

## Installation

```bash
# Install Flask
pip install flask

# Navigate to code directory
cd code
```

## Running the Web App

```bash
# Run the Flask app
python app.py
```

The web interface will be available at:
```
http://localhost:5000
```

## Features

✅ **Live Statistics** - See model metrics in real-time
✅ **Demo Section** - View predictions on sample URLs
✅ **Manual Prediction** - Enter custom features and get predictions
✅ **Beautiful UI** - Modern, responsive design
✅ **Interactive Charts** - Visual probability representation

## Navigation

1. **📊 Model Statistics** - View accuracy, precision, recall, F1-score
2. **🧪 Live Demo** - See real predictions on legitimate and phishing URLs
3. **🔍 Manual Prediction** - Enter URL features to get a prediction
4. **ℹ️ About** - Project details and use cases

## Browser Compatibility

Works on:
- Chrome ✓
- Firefox ✓
- Safari ✓
- Edge ✓

## API Endpoints

### Get Statistics
```
GET /api/stats
```

### Get Demo Predictions
```
GET /api/demo
```

### Make Prediction
```
POST /api/predict
Body: {"features": {...}}
```

## Troubleshooting

If port 5000 is already in use:
```python
# In app.py, change:
app.run(debug=True, port=5000)
# To:
app.run(debug=True, port=5001)
```

---

**Status:** Ready to use ✅
