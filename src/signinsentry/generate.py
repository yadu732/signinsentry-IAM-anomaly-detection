"""Generate reproducible, fictional sign-in telemetry and attack simulations."""
from pathlib import Path
import argparse
from datetime import datetime, timedelta, timezone
import numpy as np
import pandas as pd

COUNTRIES = ["DE","NL","FR","GB","SE"]


def simulate(seed: int = 42, users: int = 120, events_per_user: int = 36, attack_users: int = 45) -> tuple[pd.DataFrame, pd.DataFrame]:
    if users < 5 or events_per_user < 5 or not (0 <= attack_users <= users):
        raise ValueError("Invalid generator size")
    rng = np.random.default_rng(seed)
    profiles, events = [], []
    home = datetime(2026, 10, 1, tzinfo=timezone.utc)
    selected_attacks = set(int(i) for i in rng.choice(users, attack_users, replace=False))
    for i in range(users):
        uid = f"U{i+1:04d}"
        country = str(rng.choice(COUNTRIES))
        privileged = bool(rng.random() < .16)
        device = f"D{i+1:04d}-TRUSTED"
        profiles.append({"user_id":uid, "department":str(rng.choice(["Engineering","Finance","Operations","Sales","HR"])),
                         "home_country":country,"trusted_device":device, "work_hour_start":8, "work_hour_end":19,
                         "privileged":privileged})
        for j in range(events_per_user):
            day = int(rng.integers(0,27))
            hr = int(rng.integers(8,19))
            moment = home + timedelta(days=day, hours=hr, minutes=int(rng.integers(0,60)))
            success = rng.random() < .965
            # Some legitimate travel and replacement-device logins intentionally look risky.
            benign_travel = (i % 11 == 0 and j == 0)
            if benign_travel:
                moment = home + timedelta(days=day, hours=2, minutes=int(rng.integers(0,60)))
            events.append({"event_id":f"S-{i:04d}-{j:04d}","user_id":uid,
                           "timestamp_utc":moment.isoformat(),
                           "country":"US" if benign_travel else country,
                           "device_id":f"D{i+1:04d}-NEW" if benign_travel else device,
                           "result":"success" if benign_travel else ("success" if success else "failure"),
                           "mfa_used":True if benign_travel else bool(success),
                           "ip_address":f"192.0.2.{int(rng.integers(1,255))}", "simulated_attack":0})
        if i in selected_attacks:
            # Three difficulty levels. Some simulated attacks are intentionally subtle
            # (trusted-device / MFA-backed sessions), demonstrating false negatives.
            scenario = i % 3
            hr = 2 if scenario != 2 else 10
            ts = home + timedelta(days=int(rng.integers(28,30)), hours=hr, minutes=int(rng.integers(0,30)))
            other_country = str(rng.choice(["US","BR","IN","RU"]))
            for j in range(4):
                if scenario == 0:  # obvious off-hours, foreign device, no MFA
                    event_country, event_device, mfa = other_country, f"D{i+1:04d}-UNKNOWN", False
                elif scenario == 1:  # attacker operating from a trusted identity context
                    event_country, event_device, mfa = country, device, True
                else:  # unfamiliar country but familiar device / valid MFA
                    event_country, event_device, mfa = other_country, device, True
                events.append({"event_id":f"A-{i:04d}-{j:04d}","user_id":uid,
                               "timestamp_utc":(ts+timedelta(minutes=2*j)).isoformat(),
                               "country":event_country,"device_id":event_device,
                               "result":"failure" if j < 3 else "success", "mfa_used":mfa,
                               "ip_address":f"203.0.113.{int(rng.integers(1,255))}", "simulated_attack":1})
    profiles_df = pd.DataFrame(profiles).sort_values("user_id").reset_index(drop=True)
    events_df = pd.DataFrame(events).sort_values(["timestamp_utc","event_id"]).reset_index(drop=True)
    return profiles_df, events_df


def write_data(folder: str | Path="data", seed: int=42):
    p = Path(folder)
    p.mkdir(parents=True, exist_ok=True)
    profiles, events = simulate(seed=seed)
    profiles.to_csv(p / "user_profiles.csv", index=False)
    events.to_csv(p / "signins.csv", index=False)
    print(f"Generated {len(profiles)} user profiles and {len(events)} fictional sign-ins in {p}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="data")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    write_data(args.out, args.seed)


if __name__ == "__main__":
    main()
