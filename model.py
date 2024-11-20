import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
import joblib

# Load the dataset
df = pd.read_csv("GetResultDataset.csv")
df['Result'] = df['Result'].replace(-1, 0)

# Check for missing values and handle them
df.dropna(inplace=True)

# Prepare the features and target variable
X = df.drop(columns=['index', 'Result'])
Y = df['Result']

# Split the data into training and testing sets
train_X, test_X, train_Y, test_Y = train_test_split(X, Y, test_size=0.3, random_state=2)

# Feature scaling
scaler = StandardScaler()
train_X = scaler.fit_transform(train_X)
test_X = scaler.transform(test_X)

# Train and save ANN model
ann_model = MLPClassifier(random_state=2, max_iter=500)
ann_model.fit(train_X, train_Y)
joblib.dump(ann_model, 'ann_model.pkl')

ann_pred = ann_model.predict(test_X)

print("ANN Accuracy:", accuracy_score(test_Y, ann_pred))

print("ANN Classification Report:\n", classification_report(test_Y, ann_pred))
