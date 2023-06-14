# Generated by Django 4.2.2 on 2023-06-07 10:45

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='id',
            field=models.UUIDField(default=uuid.UUID('7baeacfd-c9bb-429f-b523-a4e6d3421892'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]