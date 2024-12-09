from django.db import migrations, models
import django.db.models.deletion
from django.conf import settings

def assign_default_owner(apps, schema_editor):
    User = apps.get_model(settings.AUTH_USER_MODEL)
    Repository = apps.get_model("project", "Repository")

    # Create a default user
    default_user, created = User.objects.get_or_create(
        username="default_owner",
        defaults={"email": "default@example.com", "is_active": False},
    )
    if created:
        default_user.set_password("defaultpassword")
        default_user.save()

    # Assign all repositories to the default user
    Repository.objects.all().update(owner=default_user.id)

class Migration(migrations.Migration):

    dependencies = [
        ("project", "0010_alter_repository_owner"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Run data migration first
        migrations.RunPython(assign_default_owner, reverse_code=migrations.RunPython.noop),
        # Alter the field to a ForeignKey
        migrations.AlterField(
            model_name="repository",
            name="owner",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
