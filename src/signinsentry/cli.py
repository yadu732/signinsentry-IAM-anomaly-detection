"""Generate synthetic telemetry and score user sign-in behavior."""
import argparse
import json
from pathlib import Path
import pandas as pd
from .generate import write_data
from .detect import score_events,evaluate_simulation


def main():
    parser = argparse.ArgumentParser(prog="signinsentry")
    sub = parser.add_subparsers(dest="command",required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--out",default="data")
    gen.add_argument("--seed",type=int,default=42)
    score = sub.add_parser("score")
    score.add_argument("--data",default="data")
    score.add_argument("--out",default="reports")
    score.add_argument("--contamination",type=float,default=.05)
    args = parser.parse_args()
    if args.command == "generate":
        write_data(args.out,args.seed)
    else:
        base, dest = Path(args.data), Path(args.out)
        profiles = pd.read_csv(base / "user_profiles.csv")
        events = pd.read_csv(base / "signins.csv")
        result = score_events(profiles,events,contamination=args.contamination)
        metrics = evaluate_simulation(result)
        dest.mkdir(parents=True,exist_ok=True)
        result.to_csv(dest / "scored_signins.csv",index=False)
        (dest / "synthetic_evaluation.json").write_text(json.dumps(metrics,indent=2),encoding="utf-8")
        print(json.dumps(metrics,indent=2))


if __name__ == "__main__":
    main()
