import re
import streamlit as st
import random
import string

# Customize Streamlit theme
st.set_page_config(
    page_title="Password Strength Meter",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# Add custom CSS for styling
st.markdown(
    """
    <style>
    .title {
        font-size: 40px;
        font-weight: bold;
        color: #4CAF50;  /* Green color for title */
        text-align: center;
    }
    .owner {
        font-size: 24px;
        font-weight: bold;  /* Bold owner name */
        color: #000000;  /* Black color for owner name */
        text-align: center;
    }
    .feedback {
        font-size: 16px;
        color: #2196F3;  /* Blue color for feedback */
    }
    .strong-password {
        font-size: 18px;
        font-weight: bold;
        color: #4CAF50;  /* Green color for strong password */
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# App title and owner name
st.markdown('<p class="title">🔐 PASSWORD STRENGTH METER 🔐</p>', unsafe_allow_html=True)
st.markdown('<p class="owner">Created by SAMNA BABAR</p>', unsafe_allow_html=True)

def check_password_strength(password):
    # Initialize score
    score = 0
    feedback = []

    # Check length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one uppercase letter.")

    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one lowercase letter.")

    # Check for digits
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one digit.")

    # Check for underscores
    if re.search(r'_', password):
        score += 1
    else:
        feedback.append("Password should contain at least one underscore (_).")

    # Assign strength level
    if score <= 2:
        strength = "Weak 👎"
    elif score <= 4:
        strength = "Moderate 👍"
    else:
        strength = "Strong 💪"

    return strength, feedback

def generate_strong_password(use_numbers=True, use_alphabets=True, use_underscore=True):
    # Generate a random strong password based on user preferences
    characters = []
    if use_alphabets:
        characters.extend(random.choices(string.ascii_letters, k=6))  # Alphabets (uppercase + lowercase)
    if use_numbers:
        characters.extend(random.choices(string.digits, k=2))  # Numbers
    if use_underscore:
        characters.extend(random.choices('_', k=2))  # Underscores

    # Shuffle the characters to randomize the password
    random.shuffle(characters)
    return ''.join(characters)

def main():
    st.write("Enter your password below to check its strength.")

    # Input field for password
    password = st.text_input("Enter your password:", type="password")

    # Options for password generation
    st.write("Customize your password suggestion:")
    use_alphabets = st.checkbox("Include alphabets", value=True)
    use_numbers = st.checkbox("Include numbers", value=True)
    use_underscore = st.checkbox("Include underscores (_)", value=True)

    if password:
        # Check password strength
        strength, feedback = check_password_strength(password)
        st.write(f"**Password Strength:** {strength}")

        if strength != "Strong 💪":
            st.write("**Feedback to improve your password:**")
            for suggestion in feedback:
                st.write(f'<p class="feedback">- {suggestion}</p>', unsafe_allow_html=True)

            # Suggest a strong password
            if st.button("Generate a Strong Password"):
                if not use_alphabets and not use_numbers and not use_underscore:
                    st.warning("Please select at least one option (alphabets, numbers, or underscores).")
                else:
                    strong_password = generate_strong_password(use_numbers, use_alphabets, use_underscore)
                    st.write(f'<p class="strong-password">💡 Here\'s a strong password suggestion: `{strong_password}`</p>', unsafe_allow_html=True)
        else:
            st.success("✅ Your password is strong and secure!")

if __name__ == "__main__":
    main()