import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import os

# Set base paths
base_path = os.path.expanduser("~/Desktop/phishing/model_training")
csv_path = os.path.expanduser("~/Desktop/phishing/dataset/phishing_data.csv")
os.makedirs(base_path, exist_ok=True)

# Load dataset
df = pd.read_csv(csv_path)

# Drop non-numeric and target columns
X = df.drop(columns=["url", "status"])
y = df["status"].map({"legitimate": 0, "phishing": 1})  # Encode labels

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluation
y_pred = clf.predict(X_test)
report = classification_report(y_test, y_pred, output_dict=False)

# Figure 1: Workflow chart
plt.figure(figsize=(10, 6))
plt.title("Figure 1: Workflow Chart", fontsize=14)
workflow_steps = [
    "1. Load Dataset", "2. Preprocess Data", "3. Train/Test Split",
    "4. Train Random Forest", "5. Evaluate Model", "6. Generate Visuals"
]
for i, step in enumerate(workflow_steps):
    plt.text(0.5, 1 - i * 0.15, step, ha='center', va='center', fontsize=12,
             bbox=dict(facecolor='lightblue', edgecolor='black', boxstyle='round,pad=0.4'))
plt.axis('off')
plt.tight_layout()
plt.savefig(os.path.join(base_path, "figure1_workflow.png"))
plt.close()

# Figure 2: Class Distribution
plt.figure(figsize=(6, 4))
sns.countplot(x=y, palette="Set2")
plt.title("Figure 2: Mixtures of Two Males (Phishing vs Legitimate)")
plt.xlabel("Class (0 = Legitimate, 1 = Phishing)")
plt.ylabel("Count")
plt.savefig(os.path.join(base_path, "figure2_class_distribution.png"))
plt.close()

# Figure 3: Feature Importances
importances = clf.feature_importances_
indices = importances.argsort()[::-1][:10]
top_features = X.columns[indices]
plt.figure(figsize=(10, 6))
sns.barplot(x=importances[indices], y=top_features, palette="viridis")
plt.title("Figure 3: Top 10 Important Features")
plt.xlabel("Importance Score")
plt.ylabel("Features")
plt.tight_layout()
plt.savefig(os.path.join(base_path, "figure3_feature_importance.png"))
plt.close()

# Figure 4: KDE Distribution of nb_dots
plt.figure(figsize=(8, 4))
sns.kdeplot(df[df["status"] == "legitimate"]["nb_dots"], label="Legitimate", fill=True)
sns.kdeplot(df[df["status"] == "phishing"]["nb_dots"], label="Phishing", fill=True)
plt.title("Figure 4: Distribution of 'nb_dots' in URLs")
plt.xlabel("Number of Dots")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(base_path, "figure4_nb_dots_distribution.png"))
plt.close()

# Figure 5: Table of results
columns_to_display = ["url", "length_url", "nb_dots", "nb_hyphens", "ip", "status"]
subset_df = df[columns_to_display].head(10)
fig, ax = plt.subplots(figsize=(15, 5))
ax.axis('tight')
ax.axis('off')
table = ax.table(
    cellText=subset_df.values,
    colLabels=subset_df.columns,
    cellLoc='center',
    loc='center'
)
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1.2, 1.2)
plt.title("Figure 5: Sample Results Table from Phishing Dataset", fontsize=14, pad=20)
plt.tight_layout()
table_path = os.path.join(base_path, "figure5_results_table.png")
plt.savefig(table_path)
plt.close()

(table_path, report)
