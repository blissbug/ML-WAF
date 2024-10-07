import streamlit as st
import numpy as np
import pandas as pd
import string
import pickle

# Load the model
model = pickle.load(open('mms_maf_final', 'rb'))

# Function to check if input is suspicious
def is_suspicious(payload):
    # Feature extraction
    sql_keywords = pd.read_csv('SQLKeywords.txt', index_col=False)
    js_keywords = pd.read_csv("JavascriptKeywords.txt",index_col=False)
    features = {} 
    features['length'] = len(payload)
    features['non-printable'] = len([1 for letter in payload if letter not in string.printable])
    features['punctuation'] = len([1 for letter in payload if letter in string.punctuation])
    features['min-byte'] = None if not payload else min(bytearray(payload,'utf-8'))
    features['max-byte'] = None if not payload else max(bytearray(payload,'utf-8'))
    features['mean-byte'] = np.mean(bytearray(payload,'utf-8'))
    features['std-byte'] = np.std(bytearray(payload,'utf-8'))
    features['distinct-byte'] = len(set(bytearray(payload,'utf-8')))
    features['sql-keywords'] = len([1 for keyword in sql_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
    features['js-keywords'] = len([1 for keyword in js_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
 
    # Predict
    payload_df = pd.DataFrame(features,index=[0])
    result = model.predict(payload_df)
    
    return result[0] > 0

# Function for Main Page
def main_page():
    st.title("Main Page")

    if "my_input" not in st.session_state:
        st.session_state["my_input"] = ""

    my_input = st.text_input("Input a text here", st.session_state["my_input"])
    predict = st.button("Predict")

    if predict:
        if is_suspicious(my_input):
            st.error("Your input is detected as malicious. Cannot proceed.")
        else:
            st.session_state["my_input"] = my_input
            st.session_state["page"] = "projects_page"

# Function for Projects Page
def projects_page():
    st.title("Result")
    st.write("Hello ", st.session_state["my_input"])

# Main function
def main():
    st.set_page_config(
        page_title="Firewall implementation",
        page_icon="👋",
    )

    if "page" not in st.session_state:
        st.session_state["page"] = "main_page"

    if st.session_state["page"] == "main_page":
        main_page()
    elif st.session_state["page"] == "projects_page":
        projects_page()

if __name__ == "__main__":
    main()
