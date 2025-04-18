import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import os

def main():
    # Adjust path to your CSV dataset (make sure the file is in the dataset folder)
    dataset_path = os.path.expanduser("~/Desktop/phishing/dataset/phishing_data.csv")
    df = pd.read_csv(dataset_path)
    
    print("Columns:", df.columns.tolist())
    
    # Map the status column: assuming values are "legitimate" and "phishing"
    df["status"] = df["status"].map({"legitimate": 0, "phishing": 1})
    # Drop rows where status is NaN
    df.dropna(subset=["status"], inplace=True)
    print("Unique status after mapping:", df["status"].unique())
    
    # Use 4 features: length_url, nb_dots, nb_hyphens, and ip.
    # We assume these columns exist in the CSV.
    # Alternatively, you can compute them from the URL string.
    X = df[['length_url', 'nb_dots', 'nb_hyphens', 'ip']]
    y = df["status"]
    
    # Split dataset for training and testing (80/20 split)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train a RandomForestClassifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    accuracy = clf.score(X_test, y_test)
    print("Test Accuracy:", accuracy)
    
    # Save the trained model to the specified path
    model_path = os.path.expanduser("~/Desktop/phishing/model_training/phishing_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    print("Model saved at:", model_path)

if __name__ == "__main__":
    main()

