# CASCADE
Cascade - Multi-Factor Authentication (MFA) Project
Cascade is a Django-based web application that provides robust multi-factor authentication (MFA) functionalities including OTP (One-Time Password), captcha, security questions, and more.

Features
User Authentication:
Username/Password login,
Captcha verification,
OTP via email,
Security questions for additional authentication.



User Management:
User registration,
Forgot password/reset password functionality.


Technologies Used
Backend: Django
Frontend: HTML, CSS


Setup Instructions
Clone the repository:
git clone <repository-url>
cd cascade


Create a virtual environment:
python -m venv venv
source `venv\Scripts\activate



Install dependencies:
pip install -r requirements.txt



Run migrations:
python manage.py migrate


Collect static files:
python manage.py collectstatic


Run the development server:
python manage.py runserver
