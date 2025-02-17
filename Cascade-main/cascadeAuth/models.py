from django.db import models
from django.contrib.auth.models import User

# Creating a new user defined model for security questions class of MFA.
class SecurityQuestion(models.Model):
    question_text = models.CharField(max_length=255)

    def __str__(self):
        return self.question_text

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    security_question_1 = models.ForeignKey(SecurityQuestion, related_name='security_question_1', on_delete=models.SET_NULL, null=True)
    security_answer_1 = models.CharField(max_length=255)
    security_question_2 = models.ForeignKey(SecurityQuestion, related_name='security_question_2', on_delete=models.SET_NULL, null=True)
    security_answer_2 = models.CharField(max_length=255, default='default_answer')

    def __str__(self):
        return self.user.username