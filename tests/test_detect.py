import pandas as pd
import pytest
from signinsentry.generate import simulate
from signinsentry.detect import calculate_features,score_events,evaluate_simulation


def one_user():
    profiles = pd.DataFrame([{"user_id":"U1","home_country":"DE","trusted_device":"D1","work_hour_start":8,"work_hour_end":19,"privileged":True}])
    events = pd.DataFrame([
        {"event_id":f"E{i}","user_id":"U1","timestamp_utc":f"2026-10-10T02:0{i}:00+00:00","country":"US","device_id":"UNKNOWN","result":"failure" if i<3 else "success","mfa_used":False,"simulated_attack":1} for i in range(4)
    ])
    return profiles,events


def test_features_rapid_burst_and_privileged_mfa():
    p,e = one_user()
    f = calculate_features(p,e)
    assert f.rapid_failures_15m.tolist() == [0,0,1,1]
    assert f.privileged_no_mfa.tolist() == [0,0,0,1]
    assert f.unfamiliar_country.sum() == 4 and f.new_device.sum() == 4


def test_reject_unknown_user():
    p,e = one_user()
    e.loc[0,"user_id"] = "UNKNOWN"
    with pytest.raises(ValueError,match="unknown identity"):
        calculate_features(p,e)


def test_reject_duplicate_event_id():
    p,e = one_user()
    e.loc[0,"event_id"] = e.loc[1,"event_id"]
    with pytest.raises(ValueError,match="unique"):
        calculate_features(p,e)


def test_reproducible_data():
    p1,e1 = simulate(seed=44,users=8,events_per_user=5,attack_users=3)
    p2,e2 = simulate(seed=44,users=8,events_per_user=5,attack_users=3)
    pd.testing.assert_frame_equal(p1,p2)
    pd.testing.assert_frame_equal(e1,e2)
    assert e1.simulated_attack.sum() == 12


def test_attack_label_not_used_in_detection():
    p,e = simulate(seed=12,users=10,events_per_user=6,attack_users=3)
    scored1 = score_events(p,e)
    e["simulated_attack"] = 1 - e["simulated_attack"]
    scored2 = score_events(p,e)
    assert scored1.risk_score.tolist() == scored2.risk_score.tolist()
    assert scored1.model_anomaly.tolist() == scored2.model_anomaly.tolist()
    assert scored1.alert.tolist() == scored2.alert.tolist()


def test_simulated_attacks_are_partially_detected():
    p,e = simulate(seed=42,users=15,events_per_user=8,attack_users=5)
    scored = score_events(p,e)
    attacks = scored[scored.simulated_attack == 1]
    assert len(attacks) == 20
    assert (attacks.risk_score >= 55).any()
    stats = evaluate_simulation(scored)
    assert 0.0 < stats["recall"] <= 1.0
    assert stats["tp"] > 0


def test_contamination_validation():
    p,e = one_user()
    with pytest.raises(ValueError,match="contamination"):
        score_events(p,e,contamination=.5)
