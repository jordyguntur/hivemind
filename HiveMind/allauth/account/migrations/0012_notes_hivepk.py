# -*- coding: utf-8 -*-
# Generated by Django 1.10.3 on 2016-12-05 08:26
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0011_profilepic_university'),
    ]

    operations = [
        migrations.AddField(
            model_name='notes',
            name='hivepk',
            field=models.IntegerField(default=0),
        ),
    ]