from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings

class Migration(migrations.Migration):

    dependencies = [
        ("project", "0011_alter_repository_owner"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Delete repositories with noncompliant owner data
        migrations.RunPython(
            code=lambda apps, schema_editor: apps.get_model("project", "Repository").objects.filter(owner__isnull=True).delete()
        ),
        # Alter the owner field to a ForeignKey
        migrations.AlterField(
            model_name="repository",
            name="owner",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
