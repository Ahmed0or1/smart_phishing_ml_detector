import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Paths
base_path = os.path.expanduser("~/Desktop/phishing/model_training")
csv_path = os.path.expanduser("~/Desktop/phishing/dataset/phishing_data.csv")
figures_dir = os.path.join(base_path, "figures")
os.makedirs(figures_dir, exist_ok=True)

# Load and clean dataset
df = pd.read_csv(csv_path)
df["status"] = df["status"].map({"legitimate": 0, "phishing": 1})
df.dropna(subset=["status"], inplace=True)

features = ['length_url', 'nb_dots', 'nb_hyphens', 'ip']
X = df[features]
y = df["status"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# 1. Workflow chart
fig, ax = plt.subplots(figsize=(8, 4))
ax.axis('off')
ax.text(0.1, 0.8, 'Data Collection', fontsize=12, bbox=dict(facecolor='lightblue'))
ax.text(0.4, 0.8, 'Preprocessing', fontsize=12, bbox=dict(facecolor='lightgreen'))
ax.text(0.7, 0.8, 'Train/Test Split', fontsize=12, bbox=dict(facecolor='lightyellow'))
ax.text(0.25, 0.4, 'Model Training\n(RandomForest)', fontsize=12, bbox=dict(facecolor='orange'))
ax.text(0.55, 0.4, 'Evaluation', fontsize=12, bbox=dict(facecolor='salmon'))
ax.annotate('', xy=(0.3, 0.85), xytext=(0.2, 0.85), arrowprops=dict(arrowstyle='->'))
ax.annotate('', xy=(0.6, 0.85), xytext=(0.5, 0.85), arrowprops=dict(arrowstyle='->'))
ax.annotate('', xy=(0.45, 0.5), xytext=(0.35, 0.8), arrowprops=dict(arrowstyle='->'))
ax.annotate('', xy=(0.65, 0.5), xytext=(0.55, 0.8), arrowprops=dict(arrowstyle='->'))
ax.annotate('', xy=(0.5, 0.45), xytext=(0.4, 0.45), arrowprops=dict(arrowstyle='->'))
fig.savefig(f"{figures_dir}/1_workflow_chart.png", dpi=300, bbox_inches="tight")

# 2. Class distribution
fig, ax = plt.subplots()
sns.countplot(x='status', data=df, ax=ax)
ax.set_xticklabels(['Legitimate', 'Phishing'])
ax.set_title('Class Distribution')
fig.savefig(f"{figures_dir}/2_class_distribution.png", dpi=300, bbox_inches="tight")

# 3. Feature importance
importances = clf.feature_importances_
indices = importances.argsort()[::-1]
fig, ax = plt.subplots()
sns.barplot(x=importances[indices], y=[features[i] for i in indices], ax=ax)
ax.set_title('Top Feature Importances')
fig.savefig(f"{figures_dir}/3_feature_importance.png", dpi=300, bbox_inches="tight")

# 4. KDE plot of URL length
df["length_url"] = pd.to_numeric(df["length_url"], errors="coerce")
df_kde = df.dropna(subset=["length_url", "status"])
legit = np.array(df_kde[df_kde["status"] == 0]["length_url"], dtype=np.float64)
phish = np.array(df_kde[df_kde["status"] == 1]["length_url"], dtype=np.float64)

fig, ax = plt.subplots()
sns.kdeplot(legit, label="Legitimate")
sns.kdeplot(phish, label="Phishing")
ax.set_title("KDE Plot of URL Length by Class")
ax.set_xlabel("URL Length")
ax.set_ylabel("Density")
ax.legend()
fig.savefig(f"{figures_dir}/4_kde_plot.png", dpi=300, bbox_inches="tight")

# 5. Results table
y_pred = clf.predict(X_test)
results_df = pd.DataFrame({
    "Metric": ["Accuracy", "Precision", "Recall", "F1 Score"],
    "Score": [
        accuracy_score(y_test, y_pred),
        precision_score(y_test, y_pred),
        recall_score(y_test, y_pred),
        f1_score(y_test, y_pred)
    ]
})
fig, ax = plt.subplots()
ax.axis('off')
tbl = ax.table(cellText=results_df.values, colLabels=results_df.columns, cellLoc='center', loc='center')
tbl.auto_set_font_size(False)
tbl.set_fontsize(10)
tbl.scale(1, 2)
ax.set_title("Evaluation Results", fontweight="bold")
fig.savefig(f"{figures_dir}/5_results_table.png", dpi=300, bbox_inches="tight")
