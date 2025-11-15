# %%
import pandas as pd

# Load dataset
df = pd.read_csv("../dataset/PhiUSIIL_Phishing_URL_Dataset.csv")

df.head()


# %%
df.columns


# %%
# Keep only numeric columns
X = df.select_dtypes(include=['int64', 'float64'])

y = df['label']


# %%
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))



# %%
import pickle

with open("../models/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)


