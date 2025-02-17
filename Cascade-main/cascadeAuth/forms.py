from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django import forms
from django.forms.widgets import PasswordInput, TextInput
from captcha.fields import CaptchaField
from .models import SecurityQuestion

class CreateUserForm(UserCreationForm):

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def clean_password2(self):
        cd = self.cleaned_data
        if cd['password1'] != cd['password2']:
            raise forms.ValidationError('Passwords don\'t match.')
        return cd['password2']

class SecurityQuestionForm(forms.Form):
    security_question_1 = forms.ModelChoiceField(queryset=SecurityQuestion.objects.all(), required=True)
    security_answer_1 = forms.CharField(max_length=255, required=True)
    security_question_2 = forms.ModelChoiceField(queryset=SecurityQuestion.objects.all(), required=True)
    security_answer_2 = forms.CharField(max_length=255, required=True)

class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=TextInput())
    password = forms.CharField(widget=PasswordInput())

class CaptchaVerificationForm(forms.Form):
    captcha = CaptchaField()

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField()

class ResetPasswordForm(forms.Form):
    password1 = forms.CharField(widget=PasswordInput())
    password2 = forms.CharField(widget=PasswordInput())

class OTPForm(forms.Form):
    otp = forms.CharField(label='OTP', max_length=6, required=True)
    
class ResendOTPForm(forms.Form):
    username = forms.CharField(label='Username', max_length=150)