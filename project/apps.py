from django.apps import AppConfig

class ProjectConfig(AppConfig):
    """
    Configuration class for the 'project' app.

    This class defines the default auto field and the name of the app.
    """
    
    default_auto_field = 'django.db.models.BigAutoField'
    # Set the default auto field for models in this app to BigAutoField
    
    name = 'project'
    # Set the name of the app to 'project'