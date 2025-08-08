# <img src="https://raw.githubusercontent.com/DevanshMalhotra17/AI_ProductFinder/main/Logo_ProductFinder.png" alt="AI ProductFinder Logo" width="40" style="vertical-align: middle;"> AI ProductFinder
**AI ProductFinder** is a clean, interactive Streamlit web app that helps you discover the best products tailored to your preferences — including **budget**, **rating**, and **product type** — all powered by a structured dataset (`products.csv`). With a sleek UI, visual star rating input, and instant shopping access, finding the right product has never been easier.

---

## 🚀 Features

### 🎯 Smart Recommendations

Input your **budget**, **minimum rating** (via star selector), and **product category** (e.g., earbuds, water bottles, fans) to get the most relevant product suggestions.

### 📊 CSV-Driven Dataset

Pulls data directly from a local `products.csv` file to provide real-time, tailored recommendations.

### ⭐ Interactive Star Rating

A smooth and intuitive visual star rating selector with accurate value mapping.

### 🛍️ “Shop Now” Integration

Each recommended product includes a clickable button that searches it on **Google Shopping**.

### 🎨 Clean UX

Automatically clears old suggestions when new filters are applied, ensuring a seamless experience.

---

## 🔧 How to Run

### ✅ Option 1 (Recommended): Use the Hosted Version

👉 Open: [https://jitterfreejammers.streamlit.app/](https://jitterfreejammers.streamlit.app/)

### 🛠️ Option 2: Run Locally

**1. Clone this repository**
`git clone https://github.com/YourUsername/AI_ProductFinder.git`
`cd AI_ProductFinder`

**2. Install dependencies**
`pip install -r requirements.txt`

**3. Set your Gemini API key**
Create a file at `.streamlit/secrets.toml` and add:

```
API_KEY = "your-google-generativeai-api-key"
```

**4. Launch the app**
`streamlit run project.py`

---

## 💡 Example Use Case

Looking for **headphones under \$50** with at least a **4-star rating**?
→ AI ProductFinder filters the best matches and offers direct links to purchase them.

---

## 🧰 Tech Stack

* Python
* Streamlit
* Pandas
