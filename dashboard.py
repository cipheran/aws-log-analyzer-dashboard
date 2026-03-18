import streamlit as st
import boto3
import json
import pandas as pd

st.set_page_config(page_title="SOC Dashboard", layout="wide")

st.title("🔐 Cloud Intrusion Detection Dashboard")

# 🔐 Secure AWS connection (NO hardcoded keys)
s3 = boto3.client(
    's3',
    aws_access_key_id=st.secrets["AWS_ACCESS_KEY"],
    aws_secret_access_key=st.secrets["AWS_SECRET_KEY"],
    region_name='ap-south-1'
)

bucket = "abhinav-cloud-log-analyzer-001"
key = "output/results.json"

try:
    obj = s3.get_object(Bucket=bucket, Key=key)
    data = json.loads(obj['Body'].read())

    st.subheader("🚨 Suspicious IP Activity")

    for alert in data:
        color = "red" if alert['threat_level'] == "Malicious" else "green"

        st.markdown(f"""
        <div style="border:2px solid {color}; padding:10px; border-radius:10px; margin-bottom:10px;">
        🔴 <b>IP:</b> {alert['ip']}<br>
        🌍 <b>Country:</b> {alert['country']}<br>
        ⚠ <b>Attempts:</b> {alert['attempts']}<br>
        🔥 <b>Threat Level:</b> {alert['threat_level']}
        </div>
        """, unsafe_allow_html=True)

    # 📊 Summary
    st.subheader("📊 Summary")
    st.write(f"Total suspicious IPs: {len(data)}")

    # 📊 Graph
    st.subheader("📊 Attacks by Country")
    df = pd.DataFrame(data)
    country_counts = df['country'].value_counts()
    st.bar_chart(country_counts)

    # 🔄 Refresh button
    if st.button("🔄 Refresh"):
        st.rerun()

except Exception as e:
    st.warning("⚠ No data available yet or access issue.")
    st.text(str(e))