# <img src="https://raw.githubusercontent.com/DevanshMalhotra17/AI_ProductFinder/main/Logo_ProductFinder.png" alt="AI ProductFinder Logo" width="40" style="vertical-align: middle;"> AI ProductFinder

**AI ProductFinder** is a  Steamlit web application that provides personalized product recommendations using Google's Gemini AI. Features user authentication, community sharing, rate limiting, and persistent SQLite database storage to help users discover the best products based on their specific criteria including **budget**, **rating**, **context**, and **constraints**.

---

## 🚀 Features

### 🎯 AI-Powered Smart Recommendations
Input products with **price ranges**, **minimum ratings** (via interactive star selector), **usage context**, and **specific constraints** to get 5 tailored AI recommendations per product with direct Google Shopping links.

### 👥 Community Features  
Browse and share product recommendations with other users, vote on suggestions, add comments, and discover what the community recommends for similar needs.

### 📊 Flexible Input Methods
- **CSV Upload**: Bulk import products with structured data (`product_name`, `price_min`, `price_max`, `rating`, `context`, `constraints`)
- **Manual Entry**: Add individual products with detailed criteria using intuitive forms
- **Visual Controls**: Star rating selector and price range inputs

### 🔐 User Management & Security
Secure user authentication with bcrypt password hashing, session management, rate limiting (20 API requests/hour), and persistent SQLite database storage.

### 🛡️ Safety Features
Input validation, content sanitization, error handling with retry mechanisms, comprehensive logging, and AI safety filters.

---

## 🔧 How to Run

### ✅ Option 1 (Recommended): Use the Hosted Version
👉 Open: [https://jitterfreejammers.streamlit.app/](https://jitterfreejammers.streamlit.app/)

### 🛠️ Option 2: Local Installation

**1. Clone this repository**
```bash
git clone https://github.com/YourUsername/AI_ProductFinder.git
cd AI_ProductFinder
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Set your Gemini API key**
Replace the API key in `get_api_key()` function:
```python
API_KEY = "your-actual-gemini-api-key-here"
```
Get your API key from: [https://makersuite.google.com/app/apikey](https://makersuite.google.com/app/apikey)

**4. Launch the app**
```bash
streamlit run project.py
```

**5. Demo Login**
- Username: `demo`  
- Password: `demo123`

---

## 💡 Example Use Cases

### Gaming Setup Under Budget
Add "Gaming Mouse" ($20-60, 4+ stars, "FPS gaming", "RGB lighting") + "Mechanical Keyboard" ($40-100, 4+ stars) → Get AI recommendations → Share successful finds with community

### Office Equipment Search  
Upload CSV with multiple office products and budgets → Generate bulk recommendations → Compare with community suggestions → Make informed purchases

---

## 📋 CSV Format Guide

| Column | Description | Example |
|--------|-------------|---------|
| `product_name` | Product category/name | "Gaming Laptop" |
| `price_min` | Minimum budget | 800 |
| `price_max` | Maximum budget | 1500 |
| `rating` | Minimum rating (1.0-5.0) | 4.2 |
| `context` | Usage context | "For gaming and work" |
| `constraints` | Special requirements | "Under 2.5kg weight" |

**Sample CSV:**
```csv
product_name,price_min,price_max,rating,context,constraints
Gaming Laptop,800,1500,4.2,For gaming and work,Under 2.5kg weight
Wireless Headphones,50,200,4.5,For daily commute,Noise cancelling required
Coffee Maker,30,150,4.0,For office use,Programmable timer
```

---

## 🗄️ Database Schema

SQLite database with tables for:
- **users**: Authentication and profiles
- **user_sessions**: Session management  
- **community_recommendations**: Shared recommendations
- **votes**: Community voting system
- **comments**: Discussion threads
- **rate_limits**: API usage tracking
- **user_products**: Persistent product storage

---

## 🧰 Tech Stack

### Core
- **Python 3.8+** - Backend language
- **Streamlit** - Web application framework
- **SQLite** - Database storage with threading locks

### AI & APIs  
- **Google Gemini AI** - Product recommendation engine
- **google-generativeai** - AI API client

### Security & Data
- **bcrypt** - Password hashing
- **pandas** - Data manipulation and CSV processing
- **secrets** - Secure token generation
- **logging** - Application monitoring

---

## 🔒 Security & Performance

### Security Features
- Password requirements (8+ chars, mixed case, numbers)
- Session tokens (7-day expiry with cleanup)
- Rate limiting (20 API requests/hour/user)
- Input sanitization and SQL injection prevention
- AI content safety filters

### Performance Limits
- **API Calls**: 20 Gemini requests per user per hour
- **Products**: 1-10 products per session recommended
- **Response Time**: 2-5 seconds per recommendation batch
- **Concurrent Users**: SQLite supports hundreds of users

---

## 📊 Application Flow

1. **Authentication** → Secure login/registration with demo account
2. **Product Input** → CSV upload or manual entry with price/rating/context
3. **AI Processing** → Gemini API generates 5 recommendations per product  
4. **Results Display** → Formatted recommendations with Google Shopping links
5. **Community Sharing** → Optional sharing with voting and comments system

---

## 🎯 Key Differentiators

Unlike basic product finders, this app provides:
- **AI-powered contextual matching** (not just keyword search)
- **Community-driven insights** with voting and discussions  
- **Persistent user profiles** with saved preferences
- **Bulk processing** via CSV uploads
- **Rate-limited API usage** for sustainable operation
- **Production-ready security** with proper authentication
