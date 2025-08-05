import streamlit as st
import google.generativeai as genai
import pandas as pd
import time

# ============ Gemini Setup ============
API_KEY = st.secrets["API_KEY"]
genai.configure(api_key=API_KEY)
model = genai.GenerativeModel("gemini-2.5-flash")

# ============ Streamlit UI ============
st.set_page_config(page_title="AI ProductFinder", page_icon="🛒", layout="wide")

# --- Custom CSS for Sidebar Tabs ---
st.markdown("""
    <style>
    .sidebar .stButton button {
        width: 100%;
        text-align: left;
        background-color: transparent;
        color: white;
        border: none;
        font-size: 16px;
        padding: 6px 12px;
        border-radius: 6px;
    }
    .sidebar .stButton button:hover {
        background-color: #333;
    }
    .active-tab {
        background-color: #444 !important;
        font-weight: bold !important;
    }
    </style>
""", unsafe_allow_html=True)

# Sidebar Navigation (Clickable)
st.sidebar.title("📌 Navigation")
tabs = ["Product Finder", "Project Info", "About Us"]

if "active_tab" not in st.session_state:
    st.session_state.active_tab = "Product Finder"

for tab in tabs:
    button_style = "active-tab" if tab == st.session_state.active_tab else ""
    if st.sidebar.button(tab, key=tab):
        st.session_state.active_tab = tab

page = st.session_state.active_tab

# --- Utility Functions ---
def update_slider():
    st.session_state.slider = (st.session_state.numeric1, st.session_state.numeric2)

def update_numin():
    st.session_state.numeric1 = st.session_state.slider[0]
    st.session_state.numeric2 = st.session_state.slider[1]

# --- Project Info Page ---
if page == "Project Info":
    st.title("ℹ️ Project Information")
    st.markdown("""
    **AI ProductFinder** is an AI-powered tool to get product recommendations based on:
    - ✅ Price range
    - ⭐ Minimum rating
    - 📝 Context
    - ⚠ Constraints

    ### Features:
    - Upload products via CSV
    - Add products manually
    - Optimized AI prompt (no web search)
    """)
    sample_csv = "product_name,price_min,price_max,rating,context,constraints\nDog food bowl,5,15,4.5,For small dogs,Must be stainless steel\nLaptop,500,1200,4.0,For gaming,Under 2kg"
    st.download_button("📥 Download Sample CSV", sample_csv, "products_template.csv", "text/csv")
    st.info("Use the sample CSV above to quickly test our project.")
    st.stop()

# --- About Us Page ---
elif page == "About Us":
    st.title("About Us")
    st.write("Meet the team behind AI ProductFinder:")
    team = [
        {
            "name": "Devansh Malhotra",
            "image": "https://raw.githubusercontent.com/DevanshMalhotra17/AI_ProductFinder/main/assets/DevanshMalhotra.jpg",
            "contributions": """Led UI design and core feature implementation: CSV upload, context input, constraint fields, 
            and AI prompt optimization. Ensured intuitive and user-friendly workflow.""",
            "summary": """Aspiring AI engineer with strong experience in software development, algorithms, and robotics 
            (FRC 1923). Skilled in Java and Python, with a focus on building intelligent systems. Intern at BetterMind Labs, 
            working on real-world AI applications and prompt engineering. Passionate about advancing practical AI-driven solutions.""",
            "linkedin": "https://www.linkedin.com/in/devansh-malhotra-825789314/",
            "github": "https://github.com/DevanshMalhotra17"
        },
        {
            "name": "Haoxuan Liu",
            "image": "https://via.placeholder.com/150",
            "contributions": """Developed AI integration: dual API request system for recommendations and product links.
            Optimized backend logic for accurate outputs.""",
            "summary": "",
            "linkedin": "https://www.linkedin.com/",
            "github": "https://github.com/"
        },
        {
            "name": "Matthew Yu",
            "image": "https://via.placeholder.com/150",
            "contributions": """Enhanced input functionality: price range sliders and synchronization mechanisms.
            Improved overall UX for seamless integration.""",
            "summary": "",
            "linkedin": "https://www.linkedin.com/",
            "github": "https://github.com/"
        }
    ]
    for member in team:
        st.markdown("---")
        col1, col2 = st.columns([1, 3])
        with col1:
            st.image(member["image"], width=250)
        with col2:
            st.subheader(member["name"])
            st.write(f"**Contributions:** {member['contributions']}")
            if member["summary"]:
                st.write(f"**Professional Summary:** {member['summary']}")
            st.markdown(f"[LinkedIn]({member['linkedin']}) | [GitHub]({member['github']})")
    st.stop()

# --- Product Finder Page ---
st.title("AI ProductFinder")
st.write("Get AI-powered product recommendations based on your budget, context, and constraints.")

# Initialize product list
if "products" not in st.session_state:
    st.session_state.products = {}

# --- CSV Upload ---
st.subheader("📂 Upload Products via CSV (optional)")
uploaded_file = st.file_uploader("Upload CSV (columns: product_name, price_min, price_max, rating, context, constraints)", type=["csv"])
if uploaded_file:
    df = pd.read_csv(uploaded_file)
    for _, row in df.iterrows():
        st.session_state.products[row["product_name"]] = {
            "price_range": (row["price_min"], row["price_max"]),
            "rating": row["rating"],
            "context": row.get("context", ""),
            "constraints": row.get("constraints", "")
        }
    st.success("✅ Products added from CSV!")

# --- Manual Product Input (Step-by-step) ---
with st.expander("➕ Add a Product Manually", expanded=False):
    if "product_form" not in st.session_state:
        st.session_state.product_form = {
            "step": 1,
            "name": "",
            "price_mode": "Set Price Range",
            "min_price": 0.0,
            "max_price": 500.0,
            "rating_mode": "Stars",
            "rating": 4,
            "context": "",
            "constraints": ""
        }

    form = st.session_state.product_form

    form["name"] = st.text_input("📝 Product Name", value=form["name"], placeholder="e.g. Dog food bowl")
    if form["name"] and form["step"] == 1:
        time.sleep(1)
        form["step"] = 2

    if form["step"] >= 2:
        form["price_mode"] = st.radio("💰 Price Input", ["Set Price Range", "No Price Limit"], horizontal=True)
        if form["price_mode"] == "Set Price Range":
            col1, col2 = st.columns(2)
            with col1:
                form["min_price"] = st.number_input("Min Price", value=form["min_price"])
            with col2:
                form["max_price"] = st.number_input("Max Price", value=form["max_price"])
        if form["step"] == 2:
            time.sleep(3)
            form["step"] = 3

    if form["step"] >= 3:
        form["rating_mode"] = st.radio("⭐ Rating Input", ["Stars (whole numbers)", "Numeric (decimals allowed)"], horizontal=True)
        if form["rating_mode"] == "Stars (whole numbers)":
            form["rating"] = st.feedback("stars") or form["rating"]
        else:
            form["rating"] = st.number_input("Numeric Rating", min_value=1.0, max_value=5.0, step=0.1, value=float(form["rating"]))
        if form["step"] == 3:
            time.sleep(2)
            form["step"] = 4

    if form["step"] >= 4:
        form["context"] = st.text_input("📄 Context (optional)", value=form["context"], placeholder="e.g. For a small dog, dishwasher-safe")
        form["step"] = max(form["step"], 5)

    if form["step"] >= 5:
        form["constraints"] = st.text_input("⚠ Constraints (optional)", value=form["constraints"], placeholder="e.g. Must be eco-friendly")
        form["step"] = max(form["step"], 6)

    if form["step"] >= 6:
        if st.button("➕ Add Product"):
            st.session_state.products[form["name"]] = {
                "price_range": (form["min_price"], form["max_price"]) if form["price_mode"] == "Set Price Range" else None,
                "rating": form["rating"],
                "context": form["context"],
                "constraints": form["constraints"]
            }
            st.success(f"Added {form['name']} to the list!")
            st.session_state.product_form = {
                "step": 1,
                "name": "",
                "price_mode": "Set Price Range",
                "min_price": 0.0,
                "max_price": 500.0,
                "rating_mode": "Stars",
                "rating": 4,
                "context": "",
                "constraints": ""
            }

if st.session_state.products:
    st.subheader("🛍 Your Product List")
    for name, details in st.session_state.products.items():
        price_text = f"${details['price_range'][0]} - ${details['price_range'][1]}" if details['price_range'] else "No price limit"
        st.markdown(f"""
        **{name}**
        - Price: {price_text}
        - Rating ≥ {details['rating']}
        - Context: {details['context']}
        - Constraints: {details['constraints']}
        """)

if st.button("🔍 Generate Recommendations"):
    if st.session_state.products:
        with st.spinner("Finding the best products for you..."):
            prompt = "Recommend 5 products for each of the following items:\n"
            for name, details in st.session_state.products.items():
                price_text = f"Price {details['price_range']}" if details['price_range'] else "No price limit"
                prompt += f"- {name}: {price_text}, Rating ≥ {details['rating']}, Context: {details['context']}, Constraints: {details['constraints']}\n"
            prompt += """
            Format the response in markdown with clear product cards:
            - Product Name
            - Estimated Price
            - Rating
            - Why It Fits
            """
            response = model.generate_content([prompt])
            st.subheader("✅ Recommendations")
            st.markdown(response.text)
    else:
        st.warning("Please add at least one product.")
