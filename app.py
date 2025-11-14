from flask import Flask, render_template, request, redirect, url_for, flash, session
from models import Database, User, Website, Review
from risk_calculator import RiskCalculator
import sqlite3

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this in production!

# Initialize database
db = Database()
risk_calc = RiskCalculator()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        user = User.create(username, email, password)
        if user:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username or email already exists.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.get_by_username(username)
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/check', methods=['GET', 'POST'])
def check_website():
    if 'user_id' not in session:
        flash('Please log in to check websites.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        url = request.form['url']
        
        # Check if website already exists in database
        existing_website = Website.get_by_url(url)
        
        if existing_website:
            website = existing_website
            flash('Website found in database.', 'info')
        else:
            # Calculate risk score
            risk_score, triggered_flags = risk_calc.calculate_risk(url)
            website = Website.create_or_update(url, risk_score)
            flash('Website analysis completed!', 'success')
        
        # Get reviews for this website
        reviews = Review.get_by_website(website.id)
        
        return render_template('result.html', 
                             website=website, 
                             triggered_flags=triggered_flags,
                             reviews=reviews)
    
    return render_template('check.html')

@app.route('/review', methods=['POST'])
def add_review():
    if 'user_id' not in session:
        flash('Please log in to add reviews.', 'error')
        return redirect(url_for('login'))
    
    website_id = request.form['website_id']
    rating = int(request.form['rating'])
    comment = request.form['comment']
    
    Review.create(session['user_id'], website_id, rating, comment)
    flash('Review added successfully!', 'success')
    
    return redirect(request.referrer or url_for('index'))

# Remove these lines:
# if __name__ == '__main__':
#     app.run(debug=True)

# Add this instead:
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)