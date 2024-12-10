from django.db import migrations, models

def populate_owner_field(apps, schema_editor):
    CachedGitHubRepository = apps.get_model("project", "CachedGitHubRepository")
    for repo in CachedGitHubRepository.objects.all():
        if repo.html_url:
            try:
                owner = repo.html_url.split('/')[-2]  # Extract the owner from the URL
                repo.owner = owner
                repo.save()
            except IndexError:
                repo.owner = "unknown"
                repo.save()

class Migration(migrations.Migration):

    dependencies = [
        ("project", "0007_githubrepository"),
    ]

    operations = [
        migrations.AddField(
            model_name="cachedgithubrepository",
            name="owner",
            field=models.CharField(max_length=255, default="unknown"),
        ),
        migrations.RunPython(populate_owner_field),  # Populate the owner field
    ]
