# Generated by Django 4.2.2 on 2023-06-07 14:16

import django.core.validators
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_alter_customuser_id'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userconfirmation',
            name='verify_type',
        ),
        migrations.AddField(
            model_name='customuser',
            name='auth_status',
            field=models.CharField(choices=[('new', 'new'), ('code_verified', 'code_verified'), ('done', 'done'), ('photo_step', 'photo_step')], default='new', max_length=31),
        ),
        migrations.AddField(
            model_name='customuser',
            name='photo',
            field=models.ImageField(blank=True, null=True, upload_to='user_photos/', validators=[django.core.validators.FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png', 'heic', 'heif'])]),
        ),
        migrations.AddField(
            model_name='customuser',
            name='user_roles',
            field=models.CharField(choices=[('ordinary_user', 'ordinary_user'), ('manager', 'manager'), ('admin', 'admin')], default='ordinary_user', max_length=31),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='id',
            field=models.UUIDField(default=uuid.UUID('2cc5fa92-3231-4eac-8a55-aa3473d9bf8a'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]
