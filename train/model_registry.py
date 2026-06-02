# train/model_registry.py
"""
MLflow model registry with promotion gates.
New model only goes to production if it beats current model on held-out test set.
"""

import mlflow
from mlflow.tracking import MlflowClient
import pandas as pd

class ModelRegistry:
    
    PRODUCTION_THRESHOLDS = {
        "macro_f1":    0.95,   # Must beat this to promote
        "c2_recall":   0.97,   # Never miss a beacon (recall > precision)
        "dns_recall":  0.98,
        "exfil_recall": 0.96,
        "fp_rate_max": 0.003,  # Max 0.3% false positives (SOC fatigue)
    }
    
    def __init__(self):
        self.client = MlflowClient()
    
    def evaluate_and_promote(self, run_id: str, model_name: str):
        """
        Promotion gates — model CANNOT go to production if:
        - Macro F1 < 0.95
        - Any class recall < threshold
        - False positive rate > 0.3%
        - Performance degraded vs current production model
        """
        run = self.client.get_run(run_id)
        metrics = run.data.metrics
        
        for metric, threshold in self.PRODUCTION_THRESHOLDS.items():
            val = metrics.get(metric, 0)
            if metric == "fp_rate_max":
                if val > threshold:
                    raise ValueError(f"BLOCKED: {metric}={val:.4f} exceeds max {threshold}")
            else:
                if val < threshold:
                    raise ValueError(f"BLOCKED: {metric}={val:.4f} below threshold {threshold}")
        
        # Compare against current production
        current = self._get_production_metrics(model_name)
        if current and metrics.get("macro_f1", 0) <= current.get("macro_f1", 0):
            raise ValueError(
                f"BLOCKED: New model F1={metrics.get('macro_f1', 0):.4f} "
                f"does not beat production F1={current.get('macro_f1', 0):.4f}"
            )
        
        # Promote
        latest_version = self._get_latest_version(model_name)
        if latest_version:
            self.client.transition_model_version_stage(
                name=model_name,
                version=latest_version,
                stage="Production",
            )
            print(f"✓ {model_name} promoted to production")
    
    def _get_latest_version(self, model_name: str) -> str:
        versions = self.client.get_latest_versions(model_name)
        if not versions:
            return None
        return max(versions, key=lambda v: int(v.version)).version
    
    def _get_production_metrics(self, model_name: str) -> dict:
        versions = self.client.get_latest_versions(model_name, stages=["Production"])
        if not versions:
            return None
        run = self.client.get_run(versions[0].run_id)
        return run.data.metrics


# Scheduled retraining job (run weekly via cron or Airflow)
# crontab: 0 2 * * 0 python3 train/scheduled_retrain.py
class ScheduledRetrain:
    """
    Weekly retraining incorporating analyst feedback from last 7 days.
    This is how models stay current as C2 frameworks evolve TTPs.
    """
    
    def run(self):
        # 1. Pull analyst-labeled false positives from PostgreSQL
        fp_data = self._get_analyst_feedback(days=7)
        
        # 2. Pull new confirmed threats from SIEM
        new_threats = self._get_confirmed_threats(days=7)
        
        # 3. Merge with training set (without overwriting old data)
        updated_df = self._incremental_merge(fp_data, new_threats)
        
        # 4. Retrain
        # 5. Evaluate against fixed test set (never changes)
        # 6. Promote only if gates pass
        pass
        
    def _get_analyst_feedback(self, days: int) -> pd.DataFrame:
        """
        Analysts mark false positives in the dashboard.
        These flow back here to improve the model.
        This closes the feedback loop — the most important
        feature for production ML systems.
        """
        # from pipeline.db_layer import Database
        # db = Database()
        # return db.query(...)
        return pd.DataFrame()

    def _get_confirmed_threats(self, days: int) -> pd.DataFrame:
        return pd.DataFrame()
        
    def _incremental_merge(self, df1: pd.DataFrame, df2: pd.DataFrame) -> pd.DataFrame:
        return pd.concat([df1, df2])
