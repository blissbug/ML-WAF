import streamlit as st

def main():
    input_param = st.query_params.get("input", "")
    st.markdown(f"Hello {input_param}, the input you provided is safe.")

if __name__ == "__main__":
    main()

