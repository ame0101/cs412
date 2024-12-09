from django.db import migrations

def fix_owner_field(apps, schema_editor):
    Repository = apps.get_model('project', 'Repository')
    CustomUser = apps.get_model('project', 'CustomUser')
    
    # Example: Assign a default CustomUser if no valid owner exists
    default_user = CustomUser.objects.first()  # You can set your default user here if needed

    for repo in Repository.objects.all():
        if not repo.owner or not isinstance(repo.owner, CustomUser):
            repo.owner = default_user  # Assign the default user if owner is invalid
            repo.save()

class Migration(migrations.Migration):

    dependencies = [
        ('project', '0009_cachedgithubrepository'),
    ]

    operations = [
        migrations.RunPython(fix_owner_field),
    ]
