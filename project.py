import streamlit as st
import google.generativeai as genai
import pandas as pd
import time
import re

# ============ Gemini Setup ============
API_KEY = st.secrets["API_KEY"]  # Securely load from Streamlit secrets
genai.configure(api_key=API_KEY)
model = genai.GenerativeModel("gemini-2.5-flash")

# ============ Streamlit UI ============
st.set_page_config(page_title="AI ProductFinder", page_icon="https://raw.githubusercontent.com/DevanshMalhotra17/AI_ProductFinder/main/Logo_ProductFinder.png", layout="wide")

# --- Define Pages for Navigation ---
pages = [
    st.Page("project.py", title="Product Finder", icon="🛒", url_path="product"),
    st.Page("project.py", title="Project Info", icon="ℹ️", url_path="info"),
    st.Page("project.py", title="About Us", icon="👥", url_path="about"),
]

# --- Sidebar Navigation ---
with st.sidebar:
    st.markdown(
        """
        <style>
        div[data-testid="stSidebarNav"]::before {
            content: "";
            display: block;
            background-image: url('https://raw.githubusercontent.com/DevanshMalhotra17/AI_ProductFinder/main/Logo_ProductFinder.png');
            background-size: contain;
            background-repeat: no-repeat;
            background-position: left;
            height: 70px;
            margin-bottom: 20px;
            margin-left: 52px;
        }

        div[data-testid="stSidebarNav"] > div:first-child {
            display: none !important;
        }

        div[data-testid="stSidebarNav"] button {
            font-size: 18px !important;
            text-align: center !important;
            color: white !important;
        }

        div[data-testid="stSidebarNav"] button[title="Product Finder"][aria-selected="true"] {
            color: #1E90FF !important;
            font-weight: bold !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    pg = st.navigation(pages)

# ============ Constants ============
MAX_SAFE_INT = float(9007199254740991)

# --- Utility Functions ---
def update_slider():
    st.session_state.slider = (st.session_state.numeric1, st.session_state.numeric2)

def update_numin():
    st.session_state.numeric1 = st.session_state.slider[0]
    st.session_state.numeric2 = st.session_state.slider[1]

def genai_response(prompt):
    response = model.generate_content([prompt])
    return re.findall(r"<(.*?)>\s*(https[^\~]+)~", response.text, re.DOTALL)

# --- Output recommended products ---
def get_out(products):
    prompt = "Recommend 5 products for each of the following items:\n"
    for name, details in products.items():
        price_text = f"{details['price_range']}" if details['price_range'] else "No price limit"
        prompt += f"{name}: {price_text}, Rating >= {float(details['rating']):.1f}\n"
    prompt += """
    Format each product block as:
    <Product Name
    Estimated Price: X
    Rating: X
    Why It Fits: X>
    Then add the Google search link for the product followed by '~'
    """

    LLM_response = model.generate_content([prompt])
    text = LLM_response.text

    # Extract all product blocks using regex
    product_blocks = re.findall(r"<(.*?)>\s*(https[^\~]+)~", text, re.DOTALL)

    attempts = 0
    recommendations = []
    while not recommendations and attempts < 5:
        recommendations = genai_response(prompt)
        attempts += 1

    if not recommendations:
        st.warning("⚠ No recommendations found after multiple tries.")
        return

    # Display each product
    for block, link in product_blocks:
        lines = [line.strip() for line in block.split("\n") if line.strip()]
        if lines:
            st.markdown(f"### {lines[0]}")  # Product Name
            for line in lines[1:]:
                st.write(line)  # Price, Rating, Why It Fits
            st.link_button("Shop", link)
            st.markdown("---")

# --- Helper to extract products from uploaded CSV ---
def extract_products(df):
    products = {}
    for _, row in df.iterrows():
        name = str(row.get("product_name", "")).strip()
        if not name:
            continue
        price_min = float(row.get("price_min", 0))
        price_max = float(row.get("price_max", 0))
        rating = float(row.get("rating", 0))
        context = str(row.get("context", ""))
        constraints = str(row.get("constraints", ""))

        price_range = (price_min, price_max) if price_min and price_max else None

        products[name] = {
            "price_range": price_range,
            "rating": rating,
            "context": context,
            "constraints": constraints
        }
    return products

# --- Page Logic ---
if pg.title == "Project Info":
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

elif pg.title == "About Us":
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
            "image": "https://raw.githubusercontent.com/DevanshMalhotra17/AI_ProductFinder/main/assets/Haoxuan_Liu.jpg",
            "contributions": """Developed AI integration: dual API request system for recommendations and product links.
            Optimized backend logic for accurate outputs.""",
            "summary": """Inspired by coding since middle school and have a decent understanding of both Java, Python, and HTML&CSS. 
            Holds certifications in Python and HTML&CSS and completed an internship at BetterMind Labs focusing on creating AI.""",
            "linkedin": "https://www.linkedin.com/in/haoxuan-liu",
            "github": "https://github.com/hxliufl"
        },
        {
            "name": "Matthew Yu",
            "image": "https://raw.githubusercontent.com/DevanshMalhotra17/AI_ProductFinder/main/assets/Matthew_Yu.jpg",
            "contributions": """Enhanced input functionality: price range sliders and synchronization mechanisms.
            Improved overall UX for seamless integration.""",
            "summary": """Experienced in Java, Python, and Wolfram Language, novice in HTML and CSS. 
            Intern at BetterMind Labs with a focus on applying AI systems to real life.""",
            "linkedin": "https://www.linkedin.com/in/matthew-yu-6902a3302/",
            "github": "https://github.com/mattY-08"
        }
    ]
    for member in team:
        st.markdown("---")
        col1, col2 = st.columns([1, 3])
        with col1:
            st.image(member["image"], width=250)
        with col2:
            st.subheader(member["name"])
            if member["summary"]:
                st.write(member["summary"])
            st.write(f"**Contributions:** {member['contributions']}")
            st.markdown(f"[LinkedIn]({member['linkedin']}) | [GitHub]({member['github']})")
    st.stop()

else:
    st.title("AI ProductFinder")
    st.write("Get AI-powered product recommendations based on your budget, context, and constraints.")

    if "products" not in st.session_state:
        st.session_state.products = {}

    st.subheader("📂 Upload Products via CSV (optional)")
    uploaded_file = st.file_uploader("Upload CSV (columns: product_name, price_min, price_max, rating, context, constraints)", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.session_state["uploaded_file"] = uploaded_file  # store for refresh
        st.session_state.products = extract_products(df)
        st.success("✅ Products added from CSV!")


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

                form["min_price"] = max(0.0, min(form["min_price"], MAX_SAFE_INT))
                form["max_price"] = max(1.0, min(form["max_price"], MAX_SAFE_INT))

                with col1:
                    form["min_price"] = st.number_input(
                        "Min Price",
                        min_value=0.0,
                        max_value=MAX_SAFE_INT,
                        value=float(form["min_price"]),
                        step=0.01,
                        format="%.2f",
                        key="min_price_input",
                    )

                with col2:
                    form["max_price"] = st.number_input(
                        "Max Price",
                        min_value=1.0,
                        max_value=MAX_SAFE_INT,
                        value=float(form["max_price"]),
                        step=0.01,
                        format="%.2f",
                        key="max_price_input",
                    )

                if form["min_price"] > form["max_price"]:
                    form["max_price"] = form["min_price"]

                if form["step"] == 2:
                    form["step"] = 3

        if form["step"] >= 3:
            form["rating_mode"] = st.radio("⭐ Rating Input", ["Stars (whole numbers)", "Numeric (decimals allowed)"], horizontal=True)
            if form["rating_mode"] == "Stars (whole numbers)":
                star_rating = st.feedback("stars")
                if star_rating is not None:
                    form["rating"] = float(star_rating + 1)

            else:
                form["rating"] = st.number_input("Numeric Rating", min_value=1.0, max_value=5.0, step=0.1, value=float(form["rating"]))
            if form["step"] == 3:
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
        st.subheader("Your Product List")
        for name, details in st.session_state.products.items():
            price_text = f"${details['price_range'][0]:.2f} - ${details['price_range'][1]:.2f}" if details['price_range'] else "No price limit"
            st.markdown(f"""
            **{name}**
            - Price: {price_text}
            - Rating ≥ {details['rating']}
            - Context: {details['context']}
            - Constraints: {details['constraints']}
            """)

    colA, colC = st.columns([6, 1])
    with colA:
        if st.button("🔍 Generate Recommendations"):
            if st.session_state.products:
                with st.spinner("Finding the best products for you..."):
                    get_out(st.session_state.products)
            else:
                st.warning("Please add at least one product.")

    with colC:
        if st.button("🔄 Refresh Searches"):
            st.session_state.products = {}

            if "uploaded_file" in st.session_state and st.session_state["uploaded_file"] is not None:
                uploaded_file = st.session_state["uploaded_file"]

                try:
                    df = pd.read_csv(uploaded_file)
                    if df.empty:
                        st.warning("Uploaded file is empty.")
                    else:
                        st.session_state.products = extract_products(df)
                        st.success("Refreshed product list from uploaded file.")
                except pd.errors.EmptyDataError:
                    st.error("Uploaded file has no readable data.")
                except Exception as e:
                    st.error(f"An error occurred while reading the file: {e}")
            else:
                st.success("Cleared product list.")
