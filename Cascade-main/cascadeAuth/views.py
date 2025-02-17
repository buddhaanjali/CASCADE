import random
from django.shortcuts import render, redirect
from django.contrib.sites.shortcuts import get_current_site
from .forms import CreateUserForm, LoginForm, CaptchaVerificationForm, OTPForm, ForgotPasswordForm, ResetPasswordForm, SecurityQuestionForm, ResendOTPForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, auth
from .models import UserProfile
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.conf import settings
from django.http import HttpResponse
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.urls import reverse
from datetime import timedelta
from django.utils import timezone  
import datetime
from django.contrib.auth import login

# -----------------------------------------------------Homepage view-----------------------------------------------
def homepage(request):
    return render(request, 'cascadeAuth/index.html')

# ------------------------------------------------------Register view-----------------------------------------------

def register(request):
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid():
            request.session['registration_data'] = form.cleaned_data
            return redirect('security_questions')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = CreateUserForm()

    # Clear previous session data
    if 'registration_data' in request.session:
        del request.session['registration_data']

    context = {'registerform': form}
    return render(request, 'cascadeAuth/register.html', context=context)

def security_questions(request):
    if request.method == 'POST':
        form = SecurityQuestionForm(request.POST)
        if form.is_valid():
            registration_data = request.session.get('registration_data')
            if registration_data:
                username = registration_data['username']
                email = registration_data['email']

                if User.objects.filter(username=username).exists():
                    messages.error(request, 'Username already exists. Please choose a different username.')
                    return redirect('register')

                # Create the user
                user = User(
                    username=username,
                    email=email,
                )
                user.set_password(registration_data['password1'])
                user.is_active = False
                user.save()

                # Create the UserProfile
                UserProfile.objects.create(
                    user=user,
                    security_question_1=form.cleaned_data['security_question_1'],
                    security_answer_1=form.cleaned_data['security_answer_1'],
                    security_question_2=form.cleaned_data['security_question_2'],
                    security_answer_2=form.cleaned_data['security_answer_2'],
                )

                # Send activation email
                current_site = get_current_site(request)
                mail_subject = 'Activate your account.'
                message = render_to_string('cascadeAuth/activate.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })
                to_email = email
                send_mail(mail_subject, message, 'your-email@example.com', [to_email])

                # Clear session data after successful registration
                del request.session['registration_data']

                return redirect('confirmation')
            else:
                messages.error(request, 'No registration data found. Please register again.')
                return redirect('register')
    else:
        form = SecurityQuestionForm()

    context = {'security_question_form': form}
    return render(request, 'cascadeAuth/security_questions.html', context=context)

def confirmation(request):
    return render(request, 'cascadeAuth/confirmation.html')

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        return redirect('activation_success')
    else:
        return render(request, 'cascadeAuth/activation_invalid.html')

def activation_success(request):
    return render(request, 'cascadeAuth/activation_success.html')

def activation_invalid(request):
    return render(request, 'cascadeAuth/activation_invalid.html')
    
# -------------------------------------------------------Dashboard view-----------------------------------------------
@login_required(login_url="login")
def dashboard(request):
    return render(request, 'cascadeAuth/dashboard.html')
# --------------------------------------------------------Login view-----------------------------------------------
def login_view(request):
    form = LoginForm()
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                request.session['username'] = username
                request.session['password'] = password
                return redirect("captcha")
            else:
                messages.error(request, "Invalid username or password")
        else:
            messages.error(request, "Invalid form data")

    context = {'form': form}
    return render(request, 'cascadeAuth/login.html', context=context)

# ----------------------------------------------------Forgot password view-----------------------------------------

def password_reset(request):
    form = ForgotPasswordForm()
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                reset_url = request.build_absolute_uri(
                    reverse('resetPassword', kwargs={'uidb64': uid, 'token': token})
                )
                subject = "Password Reset Requested"
                message = render_to_string('cascadeAuth/password_reset_email.html', {
                    'user': user,
                    'reset_url': reset_url,
                })
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
                return redirect('password_reset_done')  # Redirect to password reset done page
            except User.DoesNotExist:
                messages.error(request, "No user is registered with this email address.")
        else:
            messages.error(request, "Invalid email address.")

    context = {'form': form}
    return render(request, 'cascadeAuth/password_reset_form.html', context=context)

def resetPassword(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = ResetPasswordForm(request.POST)
            if form.is_valid():
                new_password = form.cleaned_data['password1']
                confirm_password = form.cleaned_data['password2']
                if new_password == confirm_password:
                    user.set_password(new_password)
                    user.save()
                    messages.success(request, "Your password has been reset successfully.")
                    return redirect('password_reset_complete')  # Redirect to password reset complete page
                else:
                    messages.error(request, "Passwords do not match.")
            else:
                messages.error(request, "Invalid form data.")
        else:
            form = ResetPasswordForm()

        context = {'form': form}
        return render(request, 'cascadeAuth/password_reset_confirm.html', context=context)
    else:
        messages.error(request, "The reset link is invalid or has expired.")
        return redirect('password_reset') 

# -----------------------------------------------------OTP view---------------------------------------------------

def otp(request):
    form = OTPForm()
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            entered_otp = form.cleaned_data.get('otp')
            stored_otp = request.session.get('otp')
            otp_expiry_time_str = request.session.get('otp_expiry_time')
            otp_expiry_time = timezone.datetime.fromisoformat(otp_expiry_time_str)

            if timezone.now() > otp_expiry_time:
                messages.error(request, "OTP has expired. Please request a new OTP.")
            elif str(entered_otp) == str(stored_otp):
                username = request.session.get('username')
                password = request.session.get('password')
                user = authenticate(request, username=username, password=password)
                
                if user is not None:
                    auth.login(request, user)
                    return redirect("security_questions_auth")
                else:
                    messages.error(request, "Invalid credentials. Please try again.")
            else:
                messages.error(request, "Invalid OTP. Please enter the correct OTP.")
        
    else:
        new_otp = random.randint(100000, 999999)
        otp_expiry_time = timezone.now() + timedelta(minutes=10)
        request.session['otp'] = new_otp
        request.session['otp_expiry_time'] = otp_expiry_time.isoformat()

        username = request.session.get('username')
        if username:
            user = User.objects.get(username=username)
            email_subject = 'Your OTP for verification'
            email_message = f'Your OTP is: {new_otp}, Your code will expire in 10 minutes.'
            send_mail(email_subject, email_message, settings.EMAIL_HOST_USER, [user.email], fail_silently=False)
        
    context = {'otp_form': form}
    return render(request, 'cascadeAuth/otp.html', context=context)


def resend_otp(request):
    if request.method == 'POST':
        form = ResendOTPForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')

            try:
                user = User.objects.get(username=username)
                otp = random.randint(100000, 999999)
                request.session['otp'] = otp
                request.session['username'] = username

                send_mail(
                    'Resend OTP for login',
                    f'Your new OTP is {otp}',
                    settings.EMAIL_HOST_USER,
                    [user.email],
                    fail_silently=False,
                )
                messages.success(request, "New OTP has been sent to your email.")
                return redirect('otp')  # Redirect to OTP verification page after sending OTP
            except User.DoesNotExist:
                messages.error(request, "User does not exist.")
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")  # Handle other exceptions
        else:
            messages.error(request, "Invalid form data.")
    else:
        form = ResendOTPForm()

    context = {'form': form}
    return render(request, 'cascadeAuth/resend_otp.html', context=context)

# ----------------------------------------------------Captcha view--------------------------------------------------
def captcha(request):
    form =  CaptchaVerificationForm()
    if request.method == 'POST':
        form = CaptchaVerificationForm(request.POST)
        if form.is_valid():
            username = request.session.get('username')
            password = request.session.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                return redirect("otp")
            else:
                messages.error(request, "Invalid credentials. Please try again.")
    context = {'captcha_form': form}
    return render(request, 'cascadeAuth/captcha.html', context=context)

# ----------------------------------------------------Security questions view-----------------------------------------

def security_questions_auth(request):
    security_question = None
    
    if request.method == 'POST':
        username = request.session.get('username')
        password = request.session.get('password')

        if username is None:
            messages.error(request, "Username not found in session. Please log in again.")
            return redirect('login')  # Redirect to login page if username is not found

        user = authenticate(request, username=username, password=password)
        if user is not None:
            try:
                user_profile = UserProfile.objects.get(user=user)
                entered_answer = request.POST.get('security_answer')

                if request.session.get('security_question_number') == 1 and entered_answer == user_profile.security_answer_1:
                    login(request, user)
                    return redirect('dashboard')
                elif request.session.get('security_question_number') == 2 and entered_answer == user_profile.security_answer_2:
                    login(request, user)
                    return redirect('dashboard')
                else:
                    messages.error(request, "Security answer does not match.")
            except UserProfile.DoesNotExist:
                messages.error(request, "User profile not found.")
        else:
            messages.error(request, "Invalid credentials")
    else:
        # Retrieve security question based on username
        username = request.session.get('username')
        if username:
            try:
                user_profile = UserProfile.objects.get(user__username=username)
                question_number = random.randint(1, 2)
                request.session['security_question_number'] = question_number

                if question_number == 1:
                    security_question = user_profile.security_question_1.question_text
                elif question_number == 2:
                    security_question = user_profile.security_question_2.question_text
                else:
                    messages.error(request, "Invalid question number")
            except UserProfile.DoesNotExist:
                messages.error(request, "User profile not found.")
        else:
            messages.error(request, "Username not found in session.")

    context = {'security_question': security_question}
    return render(request, 'cascadeAuth/security_questions_auth.html', context)

# -----------------------------------------Logout view-------------------------------------------
def logout(request):
    auth.logout(request)
    return redirect("homepage")

# Description: This file contains the working logic for the authentication system of the Cascade application.
# The views in this file are responsible for handling the registration, login, logout, password reset, OTP verification, and security questions.
# The forms in this file are used to create the forms for user input in the registration, login, password reset, OTP verification, and security questions.
# The models in this file are used to create the models for the security questions and user profile.
# The urls in this file are used to define the URL patterns for the authentication system.
# The views in this file are responsible for rendering the HTML templates and handling the user input for the authentication system.