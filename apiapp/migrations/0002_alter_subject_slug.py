# Generated by Django 3.2.5 on 2021-07-25 20:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('apiapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='subject',
            name='slug',
            field=models.SlugField(max_length=100, unique=True),
        ),
    ]
