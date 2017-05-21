# -*- coding: utf-8 -*-
# Generated by Django 1.10.4 on 2016-12-06 07:31
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('account', '0018_auto_20161205_0407'),
    ]

    operations = [
        migrations.CreateModel(
            name='MessageBoard',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('hivepk', models.IntegerField(default=0)),
                ('message', models.CharField(blank=True, max_length=200)),
                ('user', models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AlterField(
            model_name='bio',
            name='about',
            field=models.CharField(blank=True, max_length=500),
        ),
        migrations.AlterField(
            model_name='profilenotes',
            name='notes_title',
            field=models.CharField(blank=True, max_length=250),
        ),
    ]