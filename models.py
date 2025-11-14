import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class Database:
    def __init__(self, db_path='scam_flagger.db'):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Websites table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                risk_score INTEGER NOT NULL,
                flagged BOOLEAN NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Reviews table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                website_id INTEGER NOT NULL,
                rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
                comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (website_id) REFERENCES websites (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)

class User:
    def __init__(self, id, username, email, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
    
    @staticmethod
    def create(username, email, password):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        password_hash = generate_password_hash(password)
        
        try:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return User(user_id, username, email, password_hash)
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    @staticmethod
    def get_by_username(username):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
        return None
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Website:
    def __init__(self, id, url, risk_score, flagged, created_at, last_checked):
        self.id = id
        self.url = url
        self.risk_score = risk_score
        self.flagged = bool(flagged)
        self.created_at = created_at
        self.last_checked = last_checked
    
    @staticmethod
    def create_or_update(url, risk_score):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        flagged = risk_score >= 70
        
        cursor.execute('''
            INSERT OR REPLACE INTO websites (url, risk_score, flagged, last_checked)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (url, risk_score, flagged))
        
        conn.commit()
        website_id = cursor.lastrowid
        
        cursor.execute('SELECT * FROM websites WHERE id = ?', (website_id,))
        website_data = cursor.fetchone()
        conn.close()
        
        return Website(*website_data)
    
    @staticmethod
    def get_by_url(url):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM websites WHERE url = ?', (url,))
        website_data = cursor.fetchone()
        conn.close()
        
        if website_data:
            return Website(*website_data)
        return None

class Review:
    def __init__(self, id, user_id, website_id, rating, comment, created_at):
        self.id = id
        self.user_id = user_id
        self.website_id = website_id
        self.rating = rating
        self.comment = comment
        self.created_at = created_at
    
    @staticmethod
    def create(user_id, website_id, rating, comment):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO reviews (user_id, website_id, rating, comment)
            VALUES (?, ?, ?, ?)
        ''', (user_id, website_id, rating, comment))
        
        conn.commit()
        review_id = cursor.lastrowid
        
        cursor.execute('SELECT * FROM reviews WHERE id = ?', (review_id,))
        review_data = cursor.fetchone()
        conn.close()
        
        return Review(*review_data)
    
    @staticmethod
    def get_by_website(website_id):
        db = Database()
        conn = db.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT r.*, u.username 
            FROM reviews r 
            JOIN users u ON r.user_id = u.id 
            WHERE r.website_id = ? 
            ORDER BY r.created_at DESC
        ''', (website_id,))
        
        reviews = cursor.fetchall()
        conn.close()
        return reviews