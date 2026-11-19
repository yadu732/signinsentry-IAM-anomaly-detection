"""Explainable IAM signals with an optional unsupervised model."""
from collections import deque
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

PROFILE_COLUMNS = {"user_id","home_country","trusted_device","work_hour_start","work_hour_end","privileged"}
EVENT_COLUMNS = {"event_id","user_id","timestamp_utc","country","device_id","result","mfa_used"}
FEATURES = ["unfamiliar_country", "new_device", "outside_work_hours", "failed_signin", "privileged_no_mfa", "rapid_failures_15m"]
RULES = {"unfamiliar_country": 25, "new_device":20, "outside_work_hours":10, "failed_signin":10,
         "privileged_no_mfa":35, "rapid_failures_15m":25}


def _as_bool(column: pd.Series) -> pd.Series:
    # CSV import gives bool for well-formed fields, but accommodate textual values.
    return column.map(lambda x: x if isinstance(x,(bool,np.bool_)) else str(x).strip().lower() in {"true","1","yes"}).astype(bool)


def calculate_features(profiles: pd.DataFrame, events: pd.DataFrame) -> pd.DataFrame:
    if PROFILE_COLUMNS - set(profiles): raise ValueError("Missing user profile fields")
    if EVENT_COLUMNS - set(events): raise ValueError("Missing sign-in fields")
    if profiles.user_id.isna().any() or profiles.user_id.duplicated().any(): raise ValueError("User IDs must be unique")
    if events.event_id.isna().any() or events.event_id.duplicated().any(): raise ValueError("Event IDs must be unique")
    if not events.user_id.isin(profiles.user_id).all(): raise ValueError("Sign-in event references unknown identity")
    if not events.result.isin(["success","failure"]).all(): raise ValueError("Unknown authentication result")
    table = events.merge(profiles,on="user_id",how="left",validate="many_to_one")
    table["timestamp_utc"] = pd.to_datetime(table.timestamp_utc,utc=True,errors="raise")
    table = table.sort_values(["user_id","timestamp_utc","event_id"]).reset_index(drop=True)
    hours = table.timestamp_utc.dt.hour
    table["unfamiliar_country"] = (table.country != table.home_country).astype(int)
    table["new_device"] = (table.device_id != table.trusted_device).astype(int)
    table["outside_work_hours"] = ((hours < table.work_hour_start) | (hours >= table.work_hour_end)).astype(int)
    table["failed_signin"] = (table.result == "failure").astype(int)
    table["mfa_used"] = _as_bool(table.mfa_used)
    table["privileged"] = _as_bool(table.privileged)
    table["privileged_no_mfa"] = (table.privileged & (table.result == "success") & ~table.mfa_used).astype(int)
    # Count 15-minute failed sign-in burst per identity, up to and including this event.
    counts = np.zeros(len(table),dtype=int)
    for uid, loc in table.groupby("user_id",sort=False).indices.items():
        failures = deque()
        for pos in loc:
            t = table.at[pos,"timestamp_utc"]
            while failures and (t - failures[0]).total_seconds() > 900:
                failures.popleft()
            if table.at[pos,"failed_signin"]:
                failures.append(t)
            counts[pos] = len(failures)
    table["failure_count_15m"] = counts
    table["rapid_failures_15m"] = (counts >= 3).astype(int)
    return table


def score_events(profiles: pd.DataFrame, events: pd.DataFrame, *, contamination: float=.05, seed: int=42) -> pd.DataFrame:
    """Unsupervised model intentionally uses neither attack label nor event ID."""
    if not (0 < contamination < .5): raise ValueError("contamination must be between 0 and 0.5")
    table = calculate_features(profiles,events)
    x = table[FEATURES].astype(float)
    # Fit only on observable authentication features, without synthetic attack labels.
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=seed, n_jobs=1)
    table["model_anomaly"] = (model.fit_predict(x) == -1).astype(int)
    table["model_anomaly_margin"] = (-model.decision_function(x)).round(4)
    contributions = table[list(RULES)].mul(pd.Series(RULES))
    table["rule_score"] = contributions.sum(axis=1).clip(upper=100).astype(int)
    table["risk_score"] = (table.rule_score + 12 * table.model_anomaly).clip(upper=100).astype(int)
    table["risk_level"] = pd.cut(table.risk_score, bins=[-1,29,54,100],labels=["Low","Medium","High"]).astype(str)
    table["alert"] = (table.risk_score >= 55).astype(int)
    table["triggered_rules"] = table.apply(lambda row: ", ".join(name.replace("_"," ") for name in RULES if row[name]) or "No rules",axis=1)
    return table.sort_values(["timestamp_utc","event_id"]).reset_index(drop=True)


def evaluate_simulation(scored: pd.DataFrame) -> dict:
    """Evaluation is valid ONLY against synthetic labels injected by our generator."""
    if "simulated_attack" not in scored:
        return {"note":"No synthetic ground-truth labels available"}
    y = scored.simulated_attack.astype(int)
    pred = scored.alert.astype(int)
    tn,fp,fn,tp = confusion_matrix(y,pred,labels=[0,1]).ravel()
    return {"simulated_events":int(y.sum()),"alerts":int(pred.sum()),
            "precision":round(float(precision_score(y,pred,zero_division=0)),3),
            "recall":round(float(recall_score(y,pred,zero_division=0)),3),
            "f1":round(float(f1_score(y,pred,zero_division=0)),3),
            "tp":int(tp),"fp":int(fp),"fn":int(fn),"tn":int(tn),
            "caution":"Metrics on deliberately injected patterns in synthetic logs, not real-world detection performance."}
