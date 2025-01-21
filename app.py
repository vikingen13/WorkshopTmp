import streamlit as st
import json
import boto3
import pandas as pd


with st.sidebar:
    st.title(f"Welcome,")

    st.title("About")
    st.text(f"Project created by the \nFlex Security Team during \nthe Hackathon\n")

# Add title on the page
st.title("AWS ClaudeTrail")
st.text(f"What do you want to know about your AWS Account?\n")

