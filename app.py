"""Streamlit security analytics dashboard, no real accounts or APIs required."""
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from signinsentry.detect import score_events,evaluate_simulation

st.set_page_config(page_title="SignInSentry | Identity Threat Analytics",page_icon="🔐",layout="wide")
st.title("🔐 SignInSentry")
st.caption("Identity Security Analytics | Explainable access-risk flags + unsupervised anomaly detection")
st.warning("Synthetic security lab. Alerts indicate review priority, not confirmed attacks. No real identities or login systems are connected.")

@st.cache_data

def get_data():
    root = Path(__file__).resolve().parent / "data"
    return pd.read_csv(root / "user_profiles.csv"),pd.read_csv(root / "signins.csv")

try:
    profiles,events = get_data()
except FileNotFoundError:
    st.error("Missing data. Run: python -m signinsentry.cli generate")
    st.stop()
contamination = st.sidebar.slider("Expected anomaly fraction", min_value=.01,max_value=.15,value=.05,step=.01,help="Model contamination, not ground-truth attack rate")

@st.cache_data(show_spinner="Scoring synthetic sign-in data...")
def get_scores(profiles_df, events_df, contamination):
    return score_events(profiles_df,events_df,contamination=contamination)

scored = get_scores(profiles,events,contamination)
metrics = evaluate_simulation(scored)
top = st.columns(4)
top[0].metric("Sign-in events",f"{len(scored):,}")
top[1].metric("Flagged alerts",f"{scored.alert.sum():,}")
top[2].metric("High-risk identities",f"{scored.loc[scored.alert==1,'user_id'].nunique():,}")
top[3].metric("Simulated attack recall",f"{metrics['recall']:.1%}")

t1,t2,t3,t4 = st.tabs(["Overview","Investigation queue","User timeline","Synthetic evaluation"])
with t1:
    a,b = st.columns(2)
    with a:
        cnt = scored.risk_level.value_counts().reindex(["Low","Medium","High"],fill_value=0).reset_index()
        cnt.columns=["risk_level","count"]
        st.plotly_chart(px.bar(cnt,x="risk_level",y="count",title="Risk bands"),use_container_width=True)
    with b:
        names = ["unfamiliar_country","new_device","outside_work_hours","failed_signin","privileged_no_mfa","rapid_failures_15m"]
        triggers = pd.DataFrame({"rule":names,"events":[int(scored[x].sum()) for x in names]})
        st.plotly_chart(px.bar(triggers,x="events",y="rule",orientation="h",title="Explainable rule triggers"),use_container_width=True)
    scored["day"] = scored.timestamp_utc.dt.strftime("%Y-%m-%d")
    series = scored.groupby("day",as_index=False).alert.sum()
    st.plotly_chart(px.line(series,x="day",y="alert",title="Alert frequency by UTC day",markers=True),use_container_width=True)
with t2:
    level = st.selectbox("Risk level",["All","High","Medium","Low"],index=1)
    selected = scored if level=="All" else scored[scored.risk_level==level]
    view = selected.sort_values("risk_score",ascending=False)[["timestamp_utc","event_id","user_id","country","result","risk_score","risk_level","model_anomaly","triggered_rules"]]
    st.dataframe(view,use_container_width=True,hide_index=True)
    st.download_button("Export investigation queue",view.to_csv(index=False),file_name="signinsentry_queue.csv",mime="text/csv")
with t3:
    identities = sorted(scored.user_id.unique())
    risky = scored.groupby("user_id").risk_score.max().sort_values(ascending=False).index.tolist()
    user = st.selectbox("Identity to inspect",risky,index=0)
    subset = scored[scored.user_id==user].sort_values("timestamp_utc")
    st.plotly_chart(px.scatter(subset,x="timestamp_utc",y="risk_score",color="result",hover_data=["country","device_id","triggered_rules"],title="User risk timeline"),use_container_width=True)
    st.dataframe(subset[["timestamp_utc","country","device_id","result","risk_score","triggered_rules"]],hide_index=True,use_container_width=True)
with t4:
    st.json(metrics)
    st.caption("Injected attack labels are used ONLY here for evaluation. The anomaly model is fit on observable sign-in features; the attack label is not a model input. Results do not generalize to real attacks.")
st.caption("All IP addresses use documentation-only ranges (RFC 5737). No production identity API, credential, or real person data is included.")
