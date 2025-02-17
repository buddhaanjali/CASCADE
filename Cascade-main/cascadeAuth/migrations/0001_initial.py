# Generated by Django 5.0.6 on 2024-06-30 10:54

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SecurityQuestion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('question_text', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('security_answer_1', models.CharField(max_length=255)),
                ('security_answer_2', models.CharField(max_length=255)),
                ('phone_number', models.CharField(blank=True, max_length=15, null=True)),
                ('security_question_1', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='security_question_1', to='cascadeAuth.securityquestion')),
                ('security_question_2', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='security_question_2', to='cascadeAuth.securityquestion')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
