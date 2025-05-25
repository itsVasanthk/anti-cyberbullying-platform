# preprocessing.py

import nltk
import string
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

# Make sure you downloaded these already
# nltk.download('punkt')
# nltk.download('stopwords')

stop_words = set(stopwords.words('english'))

def clean_text(text):
    # 1. Lowercase the text
    text = text.lower()
    
    # 2. Remove punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    # 3. Tokenize
    words = text.split()

    
    # 4. Remove stopwords
    filtered_words = [word for word in words if word not in stop_words]
    
    # 5. Return the cleaned text (you can either return list or join back into sentence)
    return " ".join(filtered_words)
