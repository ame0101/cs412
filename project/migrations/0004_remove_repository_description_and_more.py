# Generated by Django 4.2 on 2024-12-10 01:50

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("project", "0003_remove_repository_error_message_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="repository",
            name="description",
        ),
        migrations.RemoveField(
            model_name="repository",
            name="html_url",
        ),
        migrations.AddField(
            model_name="repository",
            name="error_message",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="repository",
            name="last_analyzed",
            field=models.DateTimeField(auto_now=True),
        ),
        migrations.AlterField(
            model_name="repository",
            name="owner",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="repositories",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]