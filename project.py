import streamlit as st
import google.generativeai as genai
import time
import re
import io
from datetime import datetime, timedelta
import json
import os
import hashlib
from pathlib import Path
import random
import secrets
import bcrypt
from collections import defaultdict
import sqlite3
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
import pandas as pd
import threading

# ============ Configuration & Setup ============
MAX_REQUESTS_PER_HOUR = 20
MAX_SAFE_INT = float(9007199254740991)
DATABASE_PATH = "productfinder.db"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('productfinder.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Thread lock for database operations
db_lock = threading.Lock()

# ============ Secure API Configuration ============
def get_api_key() -> str:
    """Get API key - replace YOUR_API_KEY_HERE with your actual key"""
    # FOR TESTING ONLY - Replace with your actual Gemini API key
    API_KEY = "AIzaSyB9y6t8dWz_NMypwB2cX70jJijUx2sqiGI"
    
    if API_KEY == "YOUR_API_KEY_HERE":
        st.error("Please replace YOUR_API_KEY_HERE with your actual Gemini API key in the code")
        st.info("Get your API key from: https://makersuite.google.com/app/apikey")
        st.stop()
    
    return API_KEY

# Initialize Gemini
try:
    API_KEY = get_api_key()
    genai.configure(api_key=API_KEY)
    model = genai.GenerativeModel(
        "gemini-2.0-flash-exp",
        generation_config=genai.types.GenerationConfig(
            temperature=0.7,
            top_p=0.8,
            top_k=40,
            max_output_tokens=8192,
        )
    )
    logger.info("Gemini API configured successfully")
except Exception as e:
    logger.error(f"Failed to configure Gemini API: {e}")
    st.error("Failed to initialize AI service. Please check configuration.")
    st.stop()

# ============ Database Setup ============
def init_database():
    """Initialize SQLite database with all required tables"""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                )
            ''')
            
            # User sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Rate limiting table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    endpoint TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Community recommendations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS community_recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    product_name TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    original_query TEXT,
                    created_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                    updated_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                    upvotes INTEGER DEFAULT 0,
                    downvotes INTEGER DEFAULT 0,
                    is_deleted BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Votes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS votes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    recommendation_id INTEGER,
                    vote_type TEXT CHECK(vote_type IN ('up', 'down')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, recommendation_id),
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (recommendation_id) REFERENCES community_recommendations (id)
                )
            ''')
            
            # Comments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recommendation_id INTEGER,
                    user_id INTEGER,
                    username TEXT,
                    comment_text TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_deleted BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (recommendation_id) REFERENCES community_recommendations (id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # User products table (for persistence)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    product_name TEXT NOT NULL,
                    price_min REAL,
                    price_max REAL,
                    rating REAL,
                    context TEXT,
                    constraints TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
            logger.info("Database initialized successfully")
            
            # Create demo user if it doesn't exist
            create_demo_user()
            
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        st.error("Failed to initialize database")
        st.stop()

def create_demo_user():
    """Create demo user for testing"""
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            
            # Check if demo user exists
            cursor.execute("SELECT id FROM users WHERE username = ?", ("demo",))
            if not cursor.fetchone():
                demo_password_hash = bcrypt.hashpw("demo123".encode('utf-8'), bcrypt.gensalt())
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    ("demo", demo_password_hash)
                )
                conn.commit()
                logger.info("Demo user created")
    except sqlite3.Error as e:
        logger.error(f"Error creating demo user: {e}")

# Initialize database on startup
init_database()

def initialize_sample_data():
    """Add sample recommendation to database if empty"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                
                # Check if we have any recommendations
                cursor.execute("SELECT COUNT(*) FROM community_recommendations WHERE is_deleted = FALSE")
                count = cursor.fetchone()[0]
                
                if count == 0:
                    # Add sample recommendation
                    sample_rec = """**Logitech G502 Gaming Mouse**
Estimated Price: $45-60
Rating: 4.5/5
Why It Fits: Excellent precision and customizable buttons for gaming

**HyperX Cloud II Headset**  
Estimated Price: $70-90
Rating: 4.6/5
Why It Fits: Great sound quality and comfort for long gaming sessions

**Corsair K55 RGB Keyboard**
Estimated Price: $40-55
Rating: 4.2/5
Why It Fits: Affordable RGB membrane keyboard with good build quality"""
                    
                    cursor.execute('''
                        INSERT INTO community_recommendations (user_id, username, product_name, recommendation, original_query, upvotes, downvotes)
                        VALUES (1, 'TechReviewer', 'Best Budget Gaming Setup', ?, ?, 15, 2)
                    ''', (sample_rec, json.dumps({"product_count": 3})))
                    
                    rec_id = cursor.lastrowid
                    
                    # Add sample comment
                    cursor.execute('''
                        INSERT INTO comments (recommendation_id, user_id, username, comment_text)
                        VALUES (?, 1, 'GamerDude', 'Great recommendations! I got the G502 and it''s amazing.')
                    ''', (rec_id,))
                    
                    conn.commit()
                    logger.info("Sample community data added")
    except sqlite3.Error as e:
        logger.error(f"Error adding sample data: {e}")

# ============ Streamlit Configuration ============
st.set_page_config(
    page_title="AI ProductFinder",
    page_icon="🛒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============ Database Operations ============
def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username from database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, username, password_hash, created_at, last_login FROM users WHERE username = ? AND is_active = TRUE",
                    (username,)
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "username": row[1],
                        "password_hash": row[2],
                        "created_at": row[3],
                        "last_login": row[4]
                    }
                return None
    except sqlite3.Error as e:
        logger.error(f"Error getting user: {e}")
        return None

def create_user(username: str, password: str) -> bool:
    """Create new user in database"""
    try:
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
                logger.info(f"User created: {username}")
                return True
    except sqlite3.IntegrityError:
        logger.warning(f"Username already exists: {username}")
        return False
    except sqlite3.Error as e:
        logger.error(f"Error creating user: {e}")
        return False

def create_user_session(user_id: int) -> str:
    """Create user session and return token"""
    try:
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=7)  # 7 day expiry
        
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                # Deactivate old sessions
                cursor.execute(
                    "UPDATE user_sessions SET is_active = FALSE WHERE user_id = ?",
                    (user_id,)
                )
                # Create new session
                cursor.execute(
                    "INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
                    (user_id, session_token, expires_at)
                )
                conn.commit()
                return session_token
    except sqlite3.Error as e:
        logger.error(f"Error creating session: {e}")
        return ""

def validate_session_token(session_token: str) -> Optional[Dict]:
    """Validate session token and return user info"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT u.id, u.username, s.expires_at 
                    FROM user_sessions s 
                    JOIN users u ON s.user_id = u.id 
                    WHERE s.session_token = ? AND s.is_active = TRUE AND s.expires_at > ?
                ''', (session_token, datetime.now()))
                
                row = cursor.fetchone()
                if row:
                    return {
                        "user_id": row[0],
                        "username": row[1],
                        "expires_at": row[2]
                    }
                return None
    except sqlite3.Error as e:
        logger.error(f"Error validating session: {e}")
        return None

def check_rate_limit(user_id: int, endpoint: str = "api_request") -> bool:
    """Check if user has exceeded rate limit"""
    try:
        one_hour_ago = datetime.now() - timedelta(hours=1)
        
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                
                # Count requests in the last hour
                cursor.execute(
                    "SELECT COUNT(*) FROM rate_limits WHERE user_id = ? AND endpoint = ? AND request_time > ?",
                    (user_id, endpoint, one_hour_ago)
                )
                count = cursor.fetchone()[0]
                
                if count >= MAX_REQUESTS_PER_HOUR:
                    logger.warning(f"Rate limit exceeded for user {user_id}")
                    return False
                
                # Log this request
                cursor.execute(
                    "INSERT INTO rate_limits (user_id, endpoint) VALUES (?, ?)",
                    (user_id, endpoint)
                )
                conn.commit()
                
                # Clean old entries (keep last 24 hours)
                cursor.execute(
                    "DELETE FROM rate_limits WHERE request_time < ?",
                    (datetime.now() - timedelta(hours=24),)
                )
                conn.commit()
                
                return True
    except sqlite3.Error as e:
        logger.error(f"Rate limit check error: {e}")
        return False

def save_user_products(user_id: int, products: Dict):
    """Save user's products to database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                
                # Clear existing products for user
                cursor.execute("DELETE FROM user_products WHERE user_id = ?", (user_id,))
                
                # Insert new products
                for product_name, details in products.items():
                    price_min = details.get('price_range', (None, None))[0] if details.get('price_range') else None
                    price_max = details.get('price_range', (None, None))[1] if details.get('price_range') else None
                    
                    cursor.execute('''
                        INSERT INTO user_products (user_id, product_name, price_min, price_max, rating, context, constraints)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        user_id,
                        details.get('original_name', product_name),
                        price_min,
                        price_max,
                        details.get('rating'),
                        details.get('context', ''),
                        details.get('constraints', '')
                    ))
                
                conn.commit()
                logger.info(f"Saved {len(products)} products for user {user_id}")
    except sqlite3.Error as e:
        logger.error(f"Error saving products: {e}")

def load_user_products(user_id: int) -> Dict[str, Any]:
    """Load user's products from database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT product_name, price_min, price_max, rating, context, constraints FROM user_products WHERE user_id = ?",
                    (user_id,)
                )
                
                products: Dict[str, Any] = {}  # Explicit type annotation
                for row in cursor.fetchall():
                    product_name = row[0]
                    price_range = (row[1], row[2]) if row[1] is not None and row[2] is not None else None
                    
                    products[product_name] = {
                        "original_name": product_name,
                        "price_range": price_range,
                        "rating": row[3],
                        "context": row[4] or "",
                        "constraints": row[5] or ""
                    }
                
                logger.info(f"Loaded {len(products)} products for user {user_id}")
                return products
    except sqlite3.Error as e:
        logger.error(f"Error loading products: {e}")
        return {}  # Return empty dict instead of None

# Alternative approach using Union type for session state keys
def safe_clear_session_keys(prefixes: List[str]):
    """Safely clear session state keys with given prefixes"""
    keys_to_clear = []
    
    for key in st.session_state.keys():
        # Type guard: only process string keys
        if isinstance(key, str):
            for prefix in prefixes:
                if key.startswith(prefix):
                    keys_to_clear.append(key)
                    break
    
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]

# Type-safe session state access helpers
def get_session_value(key: str, default: Any = None) -> Any:
    """Safely get a value from session state"""
    return st.session_state.get(key, default)

def set_session_value(key: str, value: Any) -> None:
    """Safely set a value in session state"""
    st.session_state[key] = value

def has_session_key(key: str) -> bool:
    """Check if a key exists in session state"""
    return key in st.session_state

# ============ Authentication Functions ============
def hash_password(password: str) -> bytes:
    """Hash password with bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def validate_password_strength(password: str) -> List[str]:
    """Validate password strength and return list of issues"""
    issues = []
    
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long")
    if not re.search(r'[A-Z]', password):
        issues.append("Password must contain at least one uppercase letter")
    if not re.search(r'[a-z]', password):
        issues.append("Password must contain at least one lowercase letter")
    if not re.search(r'\d', password):
        issues.append("Password must contain at least one number")
    
    return issues

def validate_username(username: str) -> List[str]:
    """Validate username and return list of issues"""
    issues = []
    
    if len(username) < 3:
        issues.append("Username must be at least 3 characters long")
    if len(username) > 30:
        issues.append("Username must be less than 30 characters")
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        issues.append("Username can only contain letters, numbers, and underscores")
    
    return issues

def logout_user():
    """Clear all authentication-related session state"""
    # Invalidate session in database if exists
    if 'session_token' in st.session_state:
        try:
            with db_lock:
                with sqlite3.connect(DATABASE_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE user_sessions SET is_active = FALSE WHERE session_token = ?",
                        (st.session_state.session_token,)
                    )
                    conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error invalidating session: {e}")
    
    # Clear session state
    keys_to_clear = [
        'authenticated', 'username', 'user_id', 'session_token', 
        'products', 'current_recommendations', 'current_products', 
        'shared_current_recs', 'show_add_success', 'last_added_product',
        'manual_counter'
    ]
    
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]
    
    # Clear temporary UI state - Fix: Handle both string and non-string keys
    temp_keys = []
    for key in st.session_state.keys():
        # Only check startswith for string keys
        if isinstance(key, str) and (key.startswith('editing_') or 
                                   key.startswith('confirm_delete_') or 
                                   key.startswith('shared_')):
            temp_keys.append(key)
    
    for key in temp_keys:
        del st.session_state[key]
    
    logger.info("User logged out")

def authenticate_user() -> None:
    """Handle user authentication with database persistence"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    # Check existing session
    if not st.session_state.authenticated and 'session_token' in st.session_state:
        session_info = validate_session_token(st.session_state.session_token)
        if session_info:
            st.session_state.authenticated = True
            st.session_state.username = session_info['username']
            st.session_state.user_id = session_info['user_id']
            
            # Load user's products - ensure we get a dict, not None
            user_products = load_user_products(session_info['user_id'])
            st.session_state.products = user_products if user_products is not None else {}
            logger.info(f"Session restored for user: {session_info['username']}")
    
    if not st.session_state.authenticated:
        with st.form("login_form"):
            st.subheader("Login Required")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            col1, col2 = st.columns(2)
            with col1:
                login = st.form_submit_button("Login")
            with col2:
                register = st.form_submit_button("Register")
            
            if login and username and password:
                user = get_user_by_username(username)
                if user and verify_password(password, user['password_hash']):
                    # Create session
                    session_token = create_user_session(user['id'])
                    if session_token:
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.session_state.user_id = user['id']
                        st.session_state.session_token = session_token
                        
                        # Load user's products
                        st.session_state.products = load_user_products(user['id'])
                        
                        # Update last login
                        try:
                            with db_lock:
                                with sqlite3.connect(DATABASE_PATH) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute(
                                        "UPDATE users SET last_login = ? WHERE id = ?",
                                        (datetime.now(), user['id'])
                                    )
                                    conn.commit()
                        except sqlite3.Error as e:
                            logger.error(f"Error updating last login: {e}")
                        
                        st.success(f"Welcome back, {username}!")
                        logger.info(f"User logged in: {username}")
                        st.rerun()
                    else:
                        st.error("Failed to create session. Please try again.")
                else:
                    st.error("Invalid username or password!")
                    logger.warning(f"Failed login attempt: {username}")
            
            if register and username and password:
                username_issues = validate_username(username)
                password_issues = validate_password_strength(password)
                
                if username_issues:
                    for issue in username_issues:
                        st.error(issue)
                elif password_issues:
                    for issue in password_issues:
                        st.error(issue)
                else:
                    if create_user(username, password):
                        # Login the new user
                        user = get_user_by_username(username)
                        if user:
                            session_token = create_user_session(user['id'])
                            if session_token:
                                st.session_state.authenticated = True
                                st.session_state.username = username
                                st.session_state.user_id = user['id']
                                st.session_state.session_token = session_token
                                st.session_state.products = {}
                                
                                st.success("Account created successfully!")
                                st.balloons()
                                logger.info(f"New user registered: {username}")
                                st.rerun()
                    else:
                        st.error("Username already exists! Please choose a different username.")
        
        # Show demo info
        with st.expander("Demo Account", expanded=False):
            st.info("Demo account: username='demo', password='demo123'")
            st.warning("Note: This demo uses stronger password requirements for new accounts.")
        
        st.stop()

# ============ Community Functions with Database ============
def get_community_recommendations(search_filter: str = "", sort_option: str = "Most Recent") -> List[Dict]:
    """Get community recommendations from database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT id, username, product_name, recommendation, original_query,
                           created_at, updated_at, upvotes, downvotes
                    FROM community_recommendations 
                    WHERE is_deleted = FALSE
                '''
                params = []
                
                if search_filter:
                    query += ' AND (product_name LIKE ? OR username LIKE ?)'
                    params.extend([f'%{search_filter}%', f'%{search_filter}%'])
                
                if sort_option == "Most Upvoted":
                    query += ' ORDER BY (upvotes - downvotes) DESC, created_at DESC'
                elif sort_option == "Most Discussed":
                    query += '''
                        ORDER BY (
                            SELECT COUNT(*) FROM comments 
                            WHERE recommendation_id = community_recommendations.id AND is_deleted = FALSE
                        ) DESC, created_at DESC
                    '''
                else:  # Most Recent
                    query += ' ORDER BY created_at DESC'
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                recommendations = []
                for row in rows:
                    # Get comments count
                    cursor.execute(
                        "SELECT COUNT(*) FROM comments WHERE recommendation_id = ? AND is_deleted = FALSE",
                        (row[0],)
                    )
                    comments_count = cursor.fetchone()[0]
                    
                    recommendations.append({
                        "id": row[0],
                        "username": row[1],
                        "product_name": row[2],
                        "recommendation": row[3],
                        "original_query": json.loads(row[4]) if row[4] else {},
                        "timestamp": row[5],
                        "updated_at": row[6],
                        "upvotes": row[7],
                        "downvotes": row[8],
                        "comments_count": comments_count
                    })
                
                return recommendations
    except sqlite3.Error as e:
        logger.error(f"Error getting recommendations: {e}")
        return []

def add_community_recommendation(user_id: int, username: str, product_name: str, recommendation_text: str, original_query: Dict = None) -> Optional[int]:
    """Add recommendation to database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO community_recommendations (user_id, username, product_name, recommendation, original_query)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, username, product_name, recommendation_text, json.dumps(original_query) if original_query else None))
                
                rec_id = cursor.lastrowid
                conn.commit()
                logger.info(f"Recommendation added: {rec_id} by {username}")
                return rec_id
    except sqlite3.Error as e:
        logger.error(f"Error adding recommendation: {e}")
        return None

def vote_on_recommendation(user_id: int, rec_id: int, vote_type: str) -> bool:
    """Vote on recommendation in database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                
                # Check existing vote
                cursor.execute(
                    "SELECT vote_type FROM votes WHERE user_id = ? AND recommendation_id = ?",
                    (user_id, rec_id)
                )
                existing_vote = cursor.fetchone()
                
                if existing_vote:
                    old_vote = existing_vote[0]
                    # Remove old vote count
                    if old_vote == "up":
                        cursor.execute(
                            "UPDATE community_recommendations SET upvotes = upvotes - 1 WHERE id = ?",
                            (rec_id,)
                        )
                    else:
                        cursor.execute(
                            "UPDATE community_recommendations SET downvotes = downvotes - 1 WHERE id = ?",
                            (rec_id,)
                        )
                    
                    # Update vote
                    cursor.execute(
                        "UPDATE votes SET vote_type = ? WHERE user_id = ? AND recommendation_id = ?",
                        (vote_type, user_id, rec_id)
                    )
                else:
                    # Insert new vote
                    cursor.execute(
                        "INSERT INTO votes (user_id, recommendation_id, vote_type) VALUES (?, ?, ?)",
                        (user_id, rec_id, vote_type)
                    )
                
                # Add new vote count
                if vote_type == "up":
                    cursor.execute(
                        "UPDATE community_recommendations SET upvotes = upvotes + 1 WHERE id = ?",
                        (rec_id,)
                    )
                else:
                    cursor.execute(
                        "UPDATE community_recommendations SET downvotes = downvotes + 1 WHERE id = ?",
                        (rec_id,)
                    )
                
                conn.commit()
                return True
    except sqlite3.Error as e:
        logger.error(f"Error voting on recommendation: {e}")
        return False

def get_recommendation_comments(rec_id: int) -> List[Dict]:
    """Get comments for a recommendation"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT username, comment_text, created_at 
                    FROM comments 
                    WHERE recommendation_id = ? AND is_deleted = FALSE 
                    ORDER BY created_at ASC
                ''', (rec_id,))
                
                return [
                    {
                        "username": row[0],
                        "text": row[1],
                        "timestamp": row[2]
                    }
                    for row in cursor.fetchall()
                ]
    except sqlite3.Error as e:
        logger.error(f"Error getting comments: {e}")
        return []

def add_recommendation_comment(rec_id: int, user_id: int, username: str, comment_text: str) -> bool:
    """Add comment to recommendation"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO comments (recommendation_id, user_id, username, comment_text)
                    VALUES (?, ?, ?, ?)
                ''', (rec_id, user_id, username, comment_text))
                conn.commit()
                return True
    except sqlite3.Error as e:
        logger.error(f"Error adding comment: {e}")
        return False

# ============ Utility Functions ============
def extract_products(df: pd.DataFrame) -> Dict[str, Any]:
    """Extract and validate products from DataFrame"""
    products = {}
    errors = []
    
    # Fix: Use iterrows() properly with explicit typing
    for idx, row in df.iterrows():
        try:
            # Cast idx to int explicitly since it could be various types
            row_number = int(idx) + 1
            
            name = str(row.get("product_name", "")).strip()
            if not name:
                errors.append(f"Row {row_number}: Missing product name")
                continue
            
            price_min = float(row.get("price_min", 0)) if pd.notna(row.get("price_min")) else 0.0
            price_max = float(row.get("price_max", 0)) if pd.notna(row.get("price_max")) else 0.0
            rating = float(row.get("rating", 0)) if pd.notna(row.get("rating")) else 0.0
            
            if rating < 1.0 or rating > 5.0:
                errors.append(f"Row {row_number}: Invalid rating {rating} (must be 1.0-5.0)")
                continue
            
            if price_min > price_max and price_max > 0:
                errors.append(f"Row {row_number}: Min price greater than max price")
                continue
            
            context = str(row.get("context", "")).strip()
            constraints = str(row.get("constraints", "")).strip()
            price_range = (price_min, price_max) if price_min and price_max else None

            products[name] = {
                "original_name": name,
                "price_range": price_range,
                "rating": rating,
                "context": context,
                "constraints": constraints
            }
            
        except (ValueError, TypeError) as e:
            # Use row_number which is guaranteed to be an int
            row_number = int(idx) + 1 if isinstance(idx, (int, float)) else len(products) + 1
            errors.append(f"Row {row_number}: Invalid data - {str(e)}")
            continue
    
    if errors:
        st.warning(f"Found {len(errors)} errors in CSV:")
        for error in errors[:5]:  # Show first 5 errors
            st.warning(f"• {error}")
        if len(errors) > 5:
            st.warning(f"... and {len(errors) - 5} more errors")
    
    return products

def validate_product_input(product_name: str, context: str, constraints: str) -> List[str]:
    """Validate product inputs to prevent API issues"""
    issues = []
    
    product_name = product_name.strip()
    context = context.strip()
    constraints = constraints.strip()
    
    if not product_name:
        issues.append("Product name is required")
        return issues
    
    if len(product_name) > 100:
        issues.append("Product name is too long (max 100 characters)")
    if len(context) > 500:
        issues.append("Context is too long (max 500 characters)")
    if len(constraints) > 300:
        issues.append("Constraints are too long (max 300 characters)")
    
    # Check for potentially problematic characters
    if not re.match(r'^[a-zA-Z0-9\s\-_().,/&]+$', product_name):
        issues.append("Product name contains invalid characters")
        return issues

def sanitize_prompt(prompt: str) -> str:
    """Remove potentially problematic content from prompt"""
    sensitive_replacements = {
        'weapon': 'tool',
        'kill': 'stop',
        'destroy': 'remove',
        'hack': 'modify',
        'crack': 'open'
    }
    
    sanitized = prompt
    for sensitive, replacement in sensitive_replacements.items():
        sanitized = sanitized.replace(sensitive, replacement)
    
    return sanitized

def fix_incomplete_links(recommendations: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Fix incomplete Google Shopping links"""
    fixed_recommendations = []
    
    for block, link in recommendations:
        lines = block.split('\n')
        if lines:
            product_name = lines[0].strip().replace('*', '')
            
            if len(link) < 50 or 'tbm=shop&q=' in link:
                if 'q=' in link:
                    query_part = link.split('q=')[1]
                    if len(query_part) < len(product_name.replace(' ', '')) / 2:
                        encoded_name = product_name.replace(' ', '+').replace('(', '').replace(')', '').replace('/', '+')
                        new_link = f"https://www.google.com/search?tbm=shop&q={encoded_name}"
                        fixed_recommendations.append((block, new_link))
                    else:
                        fixed_recommendations.append((block, link))
                else:
                    encoded_name = product_name.replace(' ', '+').replace('(', '').replace(')', '').replace('/', '+')
                    new_link = f"https://www.google.com/search?tbm=shop&q={encoded_name}"
                    fixed_recommendations.append((block, new_link))
            else:
                fixed_recommendations.append((block, link))
        else:
            fixed_recommendations.append((block, link))
    
    return fixed_recommendations

def extract_recommendations_manually(text: str) -> List[Tuple[str, str]]:
    """Manually extract recommendations when regex fails"""
    recommendations = []
    lines = text.split('\n')
    
    current_product = ""
    current_link = ""
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if ('**' in line or line.isupper() or 
            (len(line) < 100 and not line.startswith(('Estimated', 'Rating', 'Why', 'Price')))):
            if current_product and current_link:
                recommendations.append((current_product, current_link))
            current_product = line.replace('**', '').strip()
            current_link = ""
            
        elif 'google.com' in line or 'shopping' in line:
            if 'https' in line:
                url_match = re.search(r'https[^\s\n]+', line)
                if url_match:
                    current_link = url_match.group()
    
    if current_product and current_link:
        recommendations.append((current_product, current_link))
    
    return recommendations

def genai_response(prompt: str, user_id: int) -> List[Tuple[str, str]]:
    """Improved API response with rate limiting and error handling"""
    
    if not check_rate_limit(user_id, "gemini_api"):
        st.error("Rate limit exceeded. Please try again in an hour.")
        return []
    
    if not prompt or len(prompt.strip()) == 0:
        st.error("Empty prompt provided")
        return []
    
    max_retries = 5
    base_delay = 1
    
    for attempt in range(max_retries):
        try:
            if len(prompt) > 5000:
                prompt = prompt[:5000] + "..."
            
            # Sanitize prompt
            prompt = sanitize_prompt(prompt)
            
            generation_config = genai.types.GenerationConfig(
                temperature=0.7,
                top_p=0.8,
                top_k=40,
                max_output_tokens=4096,
                candidate_count=1
            )
            
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_ONLY_HIGH"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"}
            ]
            
            response = model.generate_content(
                [prompt], 
                generation_config=generation_config,
                safety_settings=safety_settings
            )
            
            if not response.candidates:
                if attempt < max_retries - 1:
                    st.warning(f"API request blocked (attempt {attempt + 1}). Retrying...")
                    time.sleep(base_delay * (2 ** attempt) + random.uniform(0, 1))
                    continue
                else:
                    st.error("API request was blocked after multiple attempts. Try rephrasing your product description.")
                    return []
            
            candidate = response.candidates[0]
            
            if candidate.finish_reason == 1:  # STOP - normal completion
                if hasattr(candidate.content, 'parts') and candidate.content.parts:
                    text = candidate.content.parts[0].text
                    
                    patterns = [
                        r"<(.*?)>\s*(https[^\~\s\n]+)~",
                        r"<(.*?)>\s*(https[^\~\s\n]+)",
                        r"\*\*(.*?)\*\*.*?(https[^\s\n]+)",
                        r"(.*?)\n.*?(https[^\s\n]+)"
                    ]
                    
                    recommendations = []
                    for pattern in patterns:
                        matches = re.findall(pattern, text, re.DOTALL)
                        if matches:
                            recommendations = matches
                            break
                    
                    if not recommendations:
                        recommendations = extract_recommendations_manually(text)
                    
                    if recommendations:
                        logger.info(f"Generated {len(recommendations)} recommendations for user {user_id}")
                        return fix_incomplete_links(recommendations)
                    elif attempt < max_retries - 1:
                        st.warning(f"No properly formatted recommendations found (attempt {attempt + 1}). Retrying...")
                        time.sleep(base_delay * (2 ** attempt))
                        continue
                    else:
                        st.error("Could not extract recommendations from API response.")
                        return []
                else:
                    if attempt < max_retries - 1:
                        st.warning(f"API returned empty content (attempt {attempt + 1}). Retrying...")
                        time.sleep(base_delay * (2 ** attempt))
                        continue
                    else:
                        st.error("API returned empty response after multiple attempts.")
                        return []
                        
            elif candidate.finish_reason == 10:  # MAX_TOKENS
                st.warning("Response was truncated due to length. Try reducing the number of products.")
                if hasattr(candidate.content, 'parts') and candidate.content.parts:
                    text = candidate.content.parts[0].text
                    recommendations = re.findall(r"<(.*?)>\s*(https[^\~]+)~", text, re.DOTALL)
                    if recommendations:
                        st.info(f"Extracted {len(recommendations)} partial recommendations.")
                        return fix_incomplete_links(recommendations)
                return []
                
            elif candidate.finish_reason == 3:  # SAFETY
                if attempt < max_retries - 1:
                    st.warning(f"Content blocked for safety (attempt {attempt + 1}). Trying with modified prompt...")
                    time.sleep(base_delay * (2 ** attempt))
                    continue
                else:
                    st.error("Content was blocked for safety reasons. Try using more generic product descriptions.")
                    return []
                    
            elif candidate.finish_reason == 4:  # RECITATION
                if attempt < max_retries - 1:
                    st.warning(f"Content blocked for recitation (attempt {attempt + 1}). Retrying with variation...")
                    # Add some randomization to avoid recitation
                    variation_phrases = ["Please suggest", "Can you recommend", "What would be good"]
                    variation = random.choice(variation_phrases)
                    prompt = prompt.replace("Recommend", variation, 1)
                    time.sleep(base_delay * (2 ** attempt))
                    continue
                else:
                    st.error("Content was blocked for recitation. Try rephrasing your requirements.")
                    return []
            else:
                logger.error(f"Unexpected API response: {candidate.finish_reason}")
                st.error("Unexpected API response.")
                return []
                
        except Exception as e:
            error_msg = str(e).lower()
            logger.error(f"API Error (attempt {attempt + 1}): {e}")
            
            if "quota" in error_msg or "limit" in error_msg:
                st.error("API quota exceeded. Please try again later.")
                return []
            elif "api_key" in error_msg or "authentication" in error_msg:
                st.error("API authentication failed. Please check configuration.")
                return []
            elif attempt < max_retries - 1:
                st.warning(f"API error (attempt {attempt + 1}). Retrying...")
                time.sleep(base_delay * (2 ** attempt) + random.uniform(0, 1))
                continue
            else:
                st.error(f"API Error after {max_retries} attempts.")
                return []
    
    st.error("Failed to get recommendations after all retry attempts.")
    return []

# ============ Page Functions ============
def show_project_info():
    """Show project information page"""
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
    
    # Sample CSV download
    sample_csv = """product_name,price_min,price_max,rating,context,constraints
Gaming Laptop,800,1500,4.2,For gaming and work,Under 2.5kg weight
Wireless Headphones,50,200,4.5,For daily commute,Noise cancelling required
Coffee Maker,30,150,4.0,For office use,Programmable timer"""
    
    st.download_button(
        "📥 Download Sample CSV", 
        sample_csv, 
        "products_template.csv", 
        "text/csv",
        help="Use this template to upload multiple products at once"
    )

def show_logout_page():
    """Show logout confirmation page"""
    st.title("🚪 Logout")
    st.write("Are you sure you want to logout?")
    
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col2:
        if st.button("🚪 Yes, Logout", use_container_width=True, type="primary"):
            logout_user()
            st.success("Successfully logged out!")
            st.info("Redirecting to login page...")
            time.sleep(1)
            st.rerun()
    
    st.markdown("---")
    st.info("Click 'Yes, Logout' above to sign out of your account.")

def show_community_page():
    """Show community recommendations page"""
    st.title("👥 Community Recommendations")
    st.write("Discover and share product recommendations with the community!")
    
    tab1, tab2, tab3 = st.tabs(["🔥 Browse Recommendations", "➕ Share Recommendation", "📊 My Contributions"])
    
    with tab1:
        show_browse_recommendations()
    
    with tab2:
        show_share_recommendation()
    
    with tab3:
        show_my_contributions()

def can_user_edit(recommendation_username: str, current_username: str) -> bool:
    """Check if user can edit/delete a recommendation"""
    return recommendation_username == current_username

def edit_recommendation(rec_id: int, new_title: str, new_content: str) -> bool:
    """Update recommendation in database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE community_recommendations 
                    SET product_name = ?, recommendation = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (new_title, new_content, rec_id))
                conn.commit()
                return True
    except sqlite3.Error as e:
        logger.error(f"Error editing recommendation: {e}")
        return False

def delete_recommendation(rec_id: int) -> bool:
    """Mark recommendation as deleted in database"""
    try:
        with db_lock:
            with sqlite3.connect(DATABASE_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE community_recommendations 
                    SET is_deleted = TRUE
                    WHERE id = ?
                ''', (rec_id,))
                conn.commit()
                return True
    except sqlite3.Error as e:
        logger.error(f"Error deleting recommendation: {e}")
        return False
def format_timestamp(timestamp_str):
    """Format timestamp to show date • time"""
    try:
        # Parse the timestamp and format it
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d • %H:%M:%S")
    except:
        return timestamp_str

def show_browse_recommendations():
    """Show browse recommendations tab"""
    st.subheader("Community Recommendations")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        search_filter = st.text_input("🔍 Search recommendations:", placeholder="Search by product name or username...")
    with col2:
        sort_option = st.selectbox("Sort by:", ["Most Recent", "Most Upvoted", "Most Discussed"])
    
    recommendations = get_community_recommendations(search_filter, sort_option)
    
    if not recommendations:
        st.info("No recommendations found. Be the first to share!")
        return
    
    for rec in recommendations:
        with st.container():
            st.markdown("---")
            col1, col2 = st.columns([4, 1])
            
            with col1:
                st.markdown(f"### {rec['product_name']}")
                
                timestamp = format_timestamp(rec.get('updated_at', rec['timestamp']))
                edited_text = " (edited)" if rec.get('updated_at') != rec['timestamp'] else ""
                st.caption(f"By **{rec['username']}** • {timestamp}{edited_text}")
                
                if can_user_edit(rec['username'], st.session_state.username):
                    edit_col1, edit_col2, edit_col3 = st.columns([1, 1, 2])
                    with edit_col1:
                        if st.button("✏️ Edit", key=f"browse_edit_{rec['id']}"):
                            st.session_state[f"editing_{rec['id']}"] = True
                            st.rerun()
                    with edit_col2:
                        if st.button("🗑️ Delete", key=f"browse_delete_{rec['id']}"):
                            st.session_state[f"confirm_delete_{rec['id']}"] = True
                            st.rerun()
            
            with col2:
                net_votes = rec["upvotes"] - rec["downvotes"]
                st.metric("Score", net_votes)
                
                col_up, col_down = st.columns(2)
                with col_up:
                    if st.button("👍", key=f"up_{rec['id']}", help=f"Upvote ({rec['upvotes']})"):
                        if vote_on_recommendation(st.session_state.user_id, rec["id"], "up"):
                            st.success("Vote recorded!")
                            st.rerun()
                        else:
                            st.error("Failed to record vote")
                
                with col_down:
                    if st.button("👎", key=f"down_{rec['id']}", help=f"Downvote ({rec['downvotes']})"):
                        if vote_on_recommendation(st.session_state.user_id, rec["id"], "down"):
                            st.success("Vote recorded!")
                            st.rerun()
                        else:
                            st.error("Failed to record vote")
            
            # Handle editing
            if st.session_state.get(f"editing_{rec['id']}", False):
                with st.form(f"edit_form_{rec['id']}"):
                    st.subheader("✏️ Edit Your Recommendation")
                    new_title = st.text_input("Title:", value=rec['product_name'], key=f"edit_title_{rec['id']}")
                    new_content = st.text_area("Content:", value=rec['recommendation'], height=150, key=f"edit_content_{rec['id']}")
                    col_save, col_cancel = st.columns(2)
                    with col_save:
                        if st.form_submit_button("💾 Save Changes"):
                            if new_title and new_content:
                                edit_recommendation(rec['id'], new_title, new_content)
                                st.session_state[f"editing_{rec['id']}"] = False
                                st.success("✅ Recommendation updated!")
                                st.rerun()
                            else:
                                st.error("Please fill in both title and content.")
                    with col_cancel:
                        if st.form_submit_button("❌ Cancel"):
                            st.session_state[f"editing_{rec['id']}"] = False
                            st.rerun()
            
            # Handle delete confirmation
            elif st.session_state.get(f"confirm_delete_{rec['id']}", False):
                st.warning("⚠️ Are you sure you want to delete this recommendation? This action cannot be undone.")
                col_confirm, col_cancel = st.columns(2)
                with col_confirm:
                    if st.button("🗑️ Yes, Delete", key=f"confirm_yes_{rec['id']}"):
                        delete_recommendation(rec['id'])
                        st.session_state[f"confirm_delete_{rec['id']}"] = False
                        st.success("🗑️ Recommendation deleted!")
                        st.rerun()
                with col_cancel:
                    if st.button("❌ Cancel", key=f"confirm_no_{rec['id']}"):
                        st.session_state[f"confirm_delete_{rec['id']}"] = False
                        st.rerun()
            
            # Show recommendation content
            with st.expander("📝 View Recommendations", expanded=False):
                st.markdown(rec["recommendation"])
            
            # Comments section
            comments = get_recommendation_comments(rec["id"])
            with st.expander(f"💬 Comments ({len(comments)})", expanded=False):
                # Add new comment
                new_comment = st.text_input(
                    f"Add a comment:", 
                    key=f"comment_{rec['id']}", 
                    placeholder="Share your thoughts..."
                )
                if st.button("Post Comment", key=f"post_{rec['id']}") and new_comment:
                    if add_recommendation_comment(rec["id"], st.session_state.user_id, st.session_state.username, new_comment):
                        st.success("Comment added!")
                        st.rerun()
                    else:
                        st.error("Failed to add comment")
                
                # Display existing comments
                for comment in comments:
                    st.markdown(f"**{comment['username']}** • *{comment['timestamp']}*")
                    st.write(comment["text"])
                    st.markdown("---")

def show_share_recommendation():
    """Show share recommendation tab"""
    st.subheader("Share Your Recommendation")
    st.write("Have a great product recommendation? Share it with the community!")
    
    with st.form("share_recommendation_form"):
        rec_title = st.text_input("📝 Recommendation Title:", placeholder="e.g., Best Budget Gaming Laptops")
        rec_content = st.text_area("💡 Your Recommendation:", 
                                placeholder="Share your detailed product recommendations, including why you recommend them, pricing, ratings, etc.",
                                height=200)
        
        submitted = st.form_submit_button("🌟 Share with Community")
        if submitted:
            if rec_title.strip() and rec_content.strip():
                rec_id = add_community_recommendation(
                    user_id=st.session_state.user_id,
                    username=st.session_state.username,
                    product_name=rec_title.strip(),  # Use the actual title
                    recommendation_text=rec_content.strip(),  # Use the actual content
                    original_query={"manual_entry": True}  # Mark as manual entry
                )
                if rec_id:
                    st.success("🎉 Your recommendation has been shared with the community!")
                    st.balloons()
                    logger.info(f"Manual recommendation shared: {rec_id} by {st.session_state.username}")
                else:
                    st.error("Failed to share recommendation. Please try again.")
            else:
                st.error("Please fill in both the title and recommendation content.")

def show_my_contributions():
    """Show user's contributions tab"""
    st.subheader("Your Contributions")
    
    # Get user's recommendations
    user_recs = []
    all_recs = get_community_recommendations()
    for rec in all_recs:
        if rec["username"] == st.session_state.username:
            user_recs.append(rec)
    
    if user_recs:
        st.write(f"You have shared **{len(user_recs)}** recommendations:")
        
        for rec in user_recs:
            with st.container():
                st.markdown("---")
                col1, col2 = st.columns([4, 1])
                
                with col1:
                    st.markdown(f"### {rec['product_name']}")
                    timestamp = format_timestamp(rec.get('updated_at', rec['timestamp']))
                    edited_text = " (edited)" if rec.get('updated_at') != rec['timestamp'] else ""
                    st.caption(f"Shared on {timestamp}{edited_text}")
                    
                    # Edit and Delete buttons
                    edit_col1, edit_col2 = st.columns([1, 1])
                    with edit_col1:
                        if st.button("✏️ Edit", key=f"contrib_edit_{rec['id']}"):
                            st.session_state[f"editing_{rec['id']}"] = True
                            st.rerun()
                    with edit_col2:
                        if st.button("🗑️ Delete", key=f"contrib_delete_{rec['id']}"):
                            st.session_state[f"confirm_delete_{rec['id']}"] = True
                            st.rerun()
                
                with col2:
                    net_votes = rec["upvotes"] - rec["downvotes"]
                    st.metric("Score", net_votes)
                    st.metric("💬 Comments", rec["comments_count"])
                
                # Handle editing
                if st.session_state.get(f"editing_{rec['id']}", False):
                    with st.form(f"contrib_edit_form_{rec['id']}"):
                        st.subheader("✏️ Edit Your Recommendation")
                        new_title = st.text_input("Title:", value=rec['product_name'], key=f"contrib_edit_title_{rec['id']}")
                        new_content = st.text_area("Content:", value=rec['recommendation'], height=150, key=f"contrib_edit_content_{rec['id']}")
                        col_save, col_cancel = st.columns(2)
                        with col_save:
                            if st.form_submit_button("💾 Save Changes"):
                                if new_title and new_content:
                                    edit_recommendation(rec['id'], new_title, new_content)
                                    st.session_state[f"editing_{rec['id']}"] = False
                                    st.success("✅ Recommendation updated!")
                                    st.rerun()
                                else:
                                    st.error("Please fill in both title and content.")
                        with col_cancel:
                            if st.form_submit_button("❌ Cancel"):
                                st.session_state[f"editing_{rec['id']}"] = False
                                st.rerun()
                
                # Handle delete confirmation
                elif st.session_state.get(f"confirm_delete_{rec['id']}", False):
                    st.warning("⚠️ Are you sure you want to delete this recommendation? This action cannot be undone.")
                    col_confirm, col_cancel = st.columns(2)
                    with col_confirm:
                        if st.button("🗑️ Yes, Delete", key=f"contrib_confirm_yes_{rec['id']}"):
                            delete_recommendation(rec['id'])
                            st.session_state[f"confirm_delete_{rec['id']}"] = False
                            st.success("🗑️ Recommendation deleted!")
                            st.rerun()
                    with col_cancel:
                        if st.button("❌ Cancel", key=f"contrib_confirm_no_{rec['id']}"):
                            st.session_state[f"confirm_delete_{rec['id']}"] = False
                            st.rerun()
                
                # Show recommendation content
                with st.expander("📝 View Recommendation", expanded=False):
                    st.markdown(rec["recommendation"])
                
                # Comments section
                comments = get_recommendation_comments(rec["id"])
                with st.expander(f"💬 Comments ({len(comments)})", expanded=False):
                    # Add new comment
                    new_comment = st.text_input(
                        f"Add a comment:", 
                        key=f"contrib_comment_{rec['id']}", 
                        placeholder="Share your thoughts..."
                    )
                    if st.button("Post Comment", key=f"contrib_post_{rec['id']}") and new_comment:
                        if add_recommendation_comment(rec["id"], st.session_state.user_id, st.session_state.username, new_comment):
                            st.success("Comment added!")
                            st.rerun()
                        else:
                            st.error("Failed to add comment")
                    
                    # Display existing comments
                    for comment in comments:
                        st.markdown(f"**{comment['username']}** • *{comment['timestamp']}*")
                        st.write(comment["text"])
                        st.markdown("---")
    else:
        st.info("You haven't shared any recommendations yet. Use the 'Share Recommendation' tab to get started!")

def show_product_finder():
    """Main product finder page"""
    st.title("🛒 AI ProductFinder")
    st.write("Get AI-powered product recommendations based on your criteria!")
    
    # Initialize session state for products
    if "products" not in st.session_state:
        st.session_state.products = load_user_products(st.session_state.user_id)
    if "manual_counter" not in st.session_state:
        st.session_state.manual_counter = 0
    
    # Create tabs for different input methods
    tab1, tab2, tab3 = st.tabs(["📄 Upload CSV", "✏️ Manual Entry", "🎯 Get Recommendations"])
    
    with tab1:
        show_csv_upload_tab()
    
    with tab2:
        show_manual_entry_tab()
    
    with tab3:
        show_recommendations_tab()

def show_csv_upload_tab():
    """Show CSV upload tab"""
    st.subheader("📄 Upload Products via CSV")
    st.write("Upload a CSV file containing your product requirements.")
    
    uploaded_file = st.file_uploader("Choose a CSV file", type="csv", key="csv_uploader")
    
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.write("Preview of uploaded data:")
            st.dataframe(df.head())
            
            if st.button("📥 Import Products from CSV", key="import_csv"):
                csv_products = extract_products(df)
                if csv_products:
                    # Merge with existing products
                    st.session_state.products.update(csv_products)
                    
                    # Save to database
                    save_user_products(st.session_state.user_id, st.session_state.products)
                    
                    st.success(f"✅ Successfully imported {len(csv_products)} products from CSV!")
                    st.balloons()
                else:
                    st.error("❌ No valid products found in CSV. Please check the format.")
                    
        except Exception as e:
            st.error(f"❌ Error reading CSV file: {str(e)}")
            logger.error(f"CSV upload error: {e}")
    
    # Show sample CSV format
    with st.expander("📋 CSV Format Guide"):
        st.write("Your CSV should have these columns:")
        sample_data = {
            "product_name": ["Gaming Laptop", "Wireless Headphones", "Coffee Maker"],
            "price_min": [500, 50, 30],
            "price_max": [1200, 200, 150],
            "rating": [4.0, 4.5, 4.2],
            "context": ["For gaming and work", "For daily commute", "For office use"],
            "constraints": ["Under 2kg weight", "Noise cancelling", "Programmable timer"]
        }
        st.dataframe(pd.DataFrame(sample_data))

def show_manual_entry_tab():
    """Show manual entry tab"""
    st.subheader("✏️ Add Products Manually")
    if "show_add_success" not in st.session_state:
        st.session_state.show_add_success = False
    
    st.write("Add individual products with specific requirements.")
    
    col1, col2 = st.columns(2)

    with col1:
        product_name = st.text_input("Product Name:", placeholder="e.g., Gaming Laptop", key="product_name_manual")
        context = st.text_area("Context (optional):", placeholder="e.g., For gaming and work", height=80, key="context_manual")

    with col2:
        st.markdown('<div style="padding-top: 84.6px;"></div>', unsafe_allow_html=True)
        constraints = st.text_area("⚠️ Constraints (optional):", placeholder="e.g., Must be under 2kg", height=80, key="constraints_manual")

    # Price range inputs
    st.subheader("💰 Price Range")
    price_mode = st.radio("Price Input", ["Set Price Range", "No price limit"], horizontal=True, key="price_mode_manual", label_visibility="collapsed")

    price_min, price_max = 0.0, 0.0
    if price_mode == "Set Price Range":
        col3, col4 = st.columns(2)
        with col3:
            price_min = st.number_input("Minimum Price ($):", min_value=0.0, value=0.0, step=10.0, key="min_price_manual")
        with col4:
            price_max = st.number_input("Maximum Price ($):", min_value=0.0, value=1000.0, step=10.0, key="max_price_manual")

    # Rating inputs
    st.subheader("⭐ Minimum Rating")
    rating_mode = st.radio("Rating Input", ["Stars (whole numbers)", "Numeric (decimals allowed)"], horizontal=True, key="rating_mode_manual", label_visibility="collapsed")

    if rating_mode == "Stars (whole numbers)":
        star_rating = st.feedback("stars", key="star_feedback_manual")
        rating = float(star_rating + 1) if star_rating is not None else 4.0
    else:
        rating = st.number_input("Numeric Rating", min_value=1.0, max_value=5.0, step=0.1, value=4.0, key="numeric_rating_manual")

    if st.button("➕ Add Product", key="add_product_manual", use_container_width=True):
        product_name = product_name.strip()
        if not product_name:
            st.error("Please enter a product name!")
        else:
            validation_issues = validate_product_input(product_name, context, constraints)
            if validation_issues:
                for issue in validation_issues:
                    st.error(issue)
            elif price_min > price_max and price_max > 0:
                st.error("Minimum price cannot be greater than maximum price!")
            elif rating < 1.0 or rating > 5.0:
                st.error("Rating must be between 1.0 and 5.0")
            else:
                # Add the product
                st.session_state.manual_counter += 1
                unique_key = f"{product_name}_{st.session_state.manual_counter}"
                    
                price_range = (price_min, price_max) if price_mode == "Set Price Range" and price_max > 0 else None
                
                st.session_state.products[unique_key] = {
                    "original_name": product_name,
                    "price_range": price_range,
                    "rating": rating,
                    "context": context.strip(),
                    "constraints": constraints.strip()
                }
                
                # Save to database
                save_user_products(st.session_state.user_id, st.session_state.products)
                
                st.success(f"Added '{product_name}' to your product list!")
                st.balloons()
                logger.info(f"Product added by user {st.session_state.user_id}: {product_name}")

def show_recommendations_tab():
    """Show recommendations tab"""
    st.subheader("🎯 Your Products & Recommendations")
    
    # Display current products
    if st.session_state.products:
        st.write(f"**Current Products ({len(st.session_state.products)}):**")
        
        for key, details in st.session_state.products.items():
            display_name = details.get("original_name", key)
            
            with st.expander(f"📦 {display_name}", expanded=False):
                col1, col2 = st.columns([8, 1])
                
                with col1:
                    price_text = f"${details['price_range'][0]:.2f} - ${details['price_range'][1]:.2f}" if details.get('price_range') else "No price limit"
                    st.write(f"**Price Range:** {price_text}")
                    st.write(f"**Minimum Rating:** {details.get('rating', 'N/A')}")
                    if details.get('context'):
                        st.write(f"**Context:** {details['context']}")
                    if details.get('constraints'):
                        st.write(f"**Constraints:** {details['constraints']}")
                
                with col2:
                    if st.button("🗑️", key=f"remove_{key}"):
                        del st.session_state.products[key]
                        save_user_products(st.session_state.user_id, st.session_state.products)
                        st.success(f"Removed '{display_name}'")
                        st.rerun()
        
        st.markdown("---")
        
        # Get recommendations button
        col1, col2 = st.columns([2, 1])
        with col1:
            if st.button("🔍 Generate Recommendations", use_container_width=True, type="primary"):
                generate_recommendations()

        with col2:
            if st.button("🗑️ Clear All", use_container_width=True):
                st.session_state.products = {}
                save_user_products(st.session_state.user_id, st.session_state.products)
                st.success("🗑️ Cleared all products!")
                st.rerun()

        # Share recommendations button
        if hasattr(st.session_state, 'current_recommendations') and st.session_state.current_recommendations:
            if st.session_state.get('recommendations_shared', False):
                st.info("✅ Recommendations already shared with community!")
            else:
                if st.button("🌟 Share All Recommendations with Community", use_container_width=True):
                    share_all_recommendations()
    else:
        st.info("📝 No products added yet. Use the tabs above to add products via CSV upload or manual entry.")

def generate_recommendations():
    
    """Generate AI recommendations for user's products"""
    if 'recommendations_shared' in st.session_state:
        del st.session_state.recommendations_shared
    if not st.session_state.products:
        st.warning("⚠️ Please add some products first!")
        return
    
    # Show loading spinner
    with st.spinner("Finding the best products for you..."):
        time.sleep(0.5)
        
        # Build prompt
        prompt = "Recommend 5 products for each of the following items:\n"
        for name, details in st.session_state.products.items():
            display_name = details.get("original_name", name)
            price_text = f"${details['price_range'][0]:.2f} - ${details['price_range'][1]:.2f}" if details.get('price_range') else "No price limit"
            rating_text = f"{float(details.get('rating', 0)):.1f}"
            context = (details.get('context') or "").strip()
            constraints = (details.get('constraints') or "").strip()

            item_line = f"{display_name}: Price = {price_text}, Minimum rating = {rating_text}"
            if context:
                item_line += f", Context = {context}"
            if constraints:
                item_line += f", Constraints = {constraints}"
            prompt += item_line + "\n"

        prompt += (
            "\nFor each input item above, use the provided Context and Constraints to filter and prioritize "
            "recommendations. Format each product block exactly like this:\n"
            "<Product Name\n"
            "Estimated Price: X\n"
            "Rating: X\n"
            "Why It Fits: X>\n"
            "After each product block add a Google Shopping search link in this format https://www.google.com/search?tbm=shop&q=PRODUCT_NAME followed by '~'\n"
        )

        # Get recommendations
        recommendations = genai_response(prompt, st.session_state.user_id)

    if recommendations:
        st.session_state.current_recommendations = recommendations
        st.session_state.current_products = dict(st.session_state.products)

        # Display recommendations grouped by input products
        input_products = list(st.session_state.products.keys())
        recs_per_input = len(recommendations) // len(input_products) if input_products else 1
        
        for i, product_key in enumerate(input_products):
            details = st.session_state.products[product_key]
            display_name = details.get("original_name", product_key)
            
            st.markdown(f"## Recommendations for: {display_name}")
            
            # Show the original criteria
            price_text = f"${details['price_range'][0]:.2f} - ${details['price_range'][1]:.2f}" if details.get('price_range') else "No price limit"
            
            with st.expander("View Search Criteria", expanded=False):
                st.write(f"**Price Range:** {price_text}")
                st.write(f"**Minimum Rating:** {details.get('rating', 'N/A')}")
                if details.get('context'):
                    st.write(f"**Context:** {details['context']}")
                if details.get('constraints'):
                    st.write(f"**Constraints:** {details['constraints']}")
            
            # Display recommendations for this input
            start_idx = i * recs_per_input
            end_idx = min((i + 1) * recs_per_input, len(recommendations))
            
            for j, (block, link) in enumerate(recommendations[start_idx:end_idx], 1):
                lines = [line.strip() for line in block.split("\n") if line.strip()]
                if not lines:
                    continue
                    
                product_name = lines[0]
                st.markdown(f"### {j}. {product_name}")
                
                # Display product details
                for line in lines[1:]:
                    st.write(line)
                st.link_button("Browse", link)
                st.markdown("---")

    else:
        st.warning("No recommendations found. Try adjusting your product descriptions.")

def share_all_recommendations():
    """Share all current recommendations with the community"""
    if not hasattr(st.session_state, 'current_recommendations') or not st.session_state.current_recommendations:
        st.error("No recommendations to share. Generate recommendations first!")
        return
    
    # Create comprehensive recommendation text
    full_rec = "**AI Generated Product Recommendations**\n\n"
    
    # Group by input products
    input_products = list(st.session_state.current_products.keys())
    recs_per_input = len(st.session_state.current_recommendations) // len(input_products) if input_products else 1
    
    for i, product_key in enumerate(input_products):
        details = st.session_state.current_products[product_key]
        display_name = details.get("original_name", product_key)
        full_rec += f"## Recommendations for: {display_name}\n\n"
        
        start_idx = i * recs_per_input
        end_idx = min((i + 1) * recs_per_input, len(st.session_state.current_recommendations))
        
        for j, (block, link) in enumerate(st.session_state.current_recommendations[start_idx:end_idx], 1):
            lines = [line.strip() for line in block.split("\n") if line.strip()]
            if lines:
                full_rec += f"**{j}. {lines[0]}**\n"
                for line in lines[1:]:
                    full_rec += f"{line}\n"
                full_rec += f"Browse: {link}\n\n"
        
        full_rec += "---\n\n"
    
    # Get display names for title
    display_names = [st.session_state.current_products[key].get("original_name", key) 
                    for key in input_products]
    
    rec_id = add_community_recommendation(
        user_id=st.session_state.user_id,
        username=st.session_state.username,
        product_name=f"AI Recommendations for: " + ", ".join(display_names),
        recommendation_text=full_rec,
        original_query={"product_count": len(st.session_state.current_products)}
    )
    
    if rec_id:
        st.session_state.recommendations_shared = True  # Add this line
        st.success("Recommendations shared with community!")
        st.balloons()
        logger.info(f"Recommendations shared with community by user {st.session_state.user_id}")
    else:
        st.error("Failed to share recommendations. Please try again.")

# ============ Main App Logic ============
def main():
    """Main application entry point"""
    try:
        # Authentication
        authenticate_user()

        initialize_sample_data()

        # Create page navigation
        product_page = st.Page(show_product_finder, title="Product Finder", icon="🛒", url_path="product")
        community_page = st.Page(show_community_page, title="Community", icon="👥", url_path="community")  
        info_page = st.Page(show_project_info, title="Project Info", icon="ℹ️", url_path="info")
        logout_page = st.Page(show_logout_page, title="Logout", icon="🚪", url_path="logout")

        # Custom sidebar styling
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
                    background-position: center;
                    height: 70px;
                    margin-bottom: 20px;
                    margin-left: 20px;
                    margin-right: 20px;
                }

                div[data-testid="stSidebarNav"] > div:first-child {
                    margin-top: 20px;
                }

                div[data-testid="stSidebarNav"] button {
                    font-size: 18px !important;
                    text-align: center !important;
                    color: white !important;
                    margin-bottom: 5px !important;
                }

                div[data-testid="stSidebarNav"] button[title="Product Finder"][aria-selected="true"] {
                    color: #1E90FF !important;
                    font-weight: bold !important;
                    background-color: rgba(30, 144, 255, 0.1) !important;
                }
                
                div[data-testid="stSidebarNav"] button[title="Community"][aria-selected="true"] {
                    color: #FF6B35 !important;
                    font-weight: bold !important;
                    background-color: rgba(255, 107, 53, 0.1) !important;
                }

                div[data-testid="stSidebarNav"] button[title="Project Info"][aria-selected="true"] {
                    color: #32CD32 !important;
                    font-weight: bold !important;
                    background-color: rgba(50, 205, 50, 0.1) !important;
                }
                </style>
                """,
                unsafe_allow_html=True
            )
            
            # Navigation
            pg = st.navigation([product_page, community_page, info_page])
            
            st.markdown(f"**Logged in as:** {st.session_state.username}")
            
            if "confirm_logout" not in st.session_state:
                st.session_state.confirm_logout = False
            
            if not st.session_state.confirm_logout:
                if st.button("🚪 Logout", use_container_width=True, type="secondary"):
                    st.session_state.confirm_logout = True
                    st.rerun()
            else:
                st.warning("Are you sure?")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Yes", use_container_width=True, type="primary"):
                        st.session_state.confirm_logout = False
                        logout_user()
                        st.rerun()
                with col2:
                    if st.button("Cancel", use_container_width=True):
                        st.session_state.confirm_logout = False
                        st.rerun()

        # Run the selected page
        pg.run()

    except Exception as e:
        logger.error(f"Application error: {e}")
        st.error("An unexpected error occurred. Please refresh the page or contact support.")
        st.exception(e)

# ============ Configuration File Creation Helper ============
def create_secrets_template():
    """Create a template secrets.toml file for users"""
    secrets_template = """# Streamlit secrets configuration
# Place this content in .streamlit/secrets.toml

[secrets]
GEMINI_API_KEY = "your_gemini_api_key_here"

# To get a Gemini API key:
# 1. Go to https://makersuite.google.com/app/apikey
# 2. Create a new API key
# 3. Replace "your_gemini_api_key_here" with your actual key
"""
    return secrets_template

# ============ Run Main App ============
if __name__ == "__main__":
    main()
