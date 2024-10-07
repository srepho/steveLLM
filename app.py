from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import openai
import anthropic
#from google.cloud import aiplatform
import os
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///llm_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Set up rate limiting
limiter = Limiter(app, key_func=get_remote_address)

# Set up API keys and credentials
openai.api_key = os.getenv('OPENAI_API_KEY')
anthropic.api_key = os.getenv('ANTHROPIC_API_KEY')
#os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(120), nullable=False)

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    model = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['username'] = user.username
            return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/ask', methods=['POST'])
@limiter.limit("5 per minute")
def ask():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401
    
    question = request.form.get('question')
    model = request.form.get('model')
    
    # Input validation
    if not question or not model:
        return jsonify({'error': 'Missing question or model'}), 400
    
    try:
        if 'openai' in model:
            answer = call_openai_api(question, model)
        elif 'anthropic' in model:
            answer = call_anthropic_api(question, model)
        #elif 'google' in model:
        #    answer = call_google_api(question, model)
        else:
            return jsonify({'error': 'Unsupported model'}), 400
        
        new_conversation = Conversation(
            question=question, 
            answer=answer, 
            model=model, 
            timestamp=datetime.utcnow()
        )
        db.session.add(new_conversation)
        db.session.commit()
        
        logger.info(f"Successful API call to {model}")
        return jsonify({'answer': answer})
    except Exception as e:
        logger.error(f"Error in API call: {str(e)}")
        return jsonify({'error': str(e)}), 500

def call_openai_api(question, model):
    try:
        response = openai.Completion.create(
            engine=model,
            prompt=question,
            max_tokens=150
        )
        return response.choices[0].text.strip()
    except Exception as e:
        logger.error(f"OpenAI API error: {str(e)}")
        raise

def call_anthropic_api(question, model):
    try:
        client = anthropic.Anthropic(
            api_key=os.getenv('ANTHROPIC_API_KEY'),
            # Add the anthropic-version header
            default_headers={"anthropic-version": "2023-06-01"}
        )
        response = client.completions.create(
            prompt=f"{anthropic.HUMAN_PROMPT} {question}{anthropic.AI_PROMPT}",
            model=model,
            max_tokens_to_sample=150,
            stop_sequences=[anthropic.HUMAN_PROMPT]
        )
        return response.completion
    except Exception as e:
        logger.error(f"Anthropic API error: {str(e)}")
        raise

'''def call_google_api(question, model):
    try:
        aiplatform.init(project='your-project-id')
        model = aiplatform.Model(model_name=model)
        response = model.predict(instances=[question])
        return response.predictions[0]
    except Exception as e:
        logger.error(f"Google API error: {str(e)}")
        raise
'''
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8080)