from sklearn.ensemble import IsolationForest
import joblib
from app import parse_zscaler_log

log_file = 'uploads/latest.txt'
parsed = parse_zscaler_log(log_file)
print(parsed)
# model = IsolationForest(contamination=0.05, random_state=42)
# model.fit(features)
# joblib.dump(model, 'anomaly_model.pkl')
# print("Anomaly model trained and saved.")


