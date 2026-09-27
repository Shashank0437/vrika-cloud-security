from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("api", "0102_unknown_severity")]

    operations = [
        migrations.AddField(
            model_name="task",
            name="vrika_provider_ids",
            field=models.JSONField(default=list, db_default=[], editable=False),
        ),
        migrations.AddField(
            model_name="role",
            name="vrika_policy",
            field=models.JSONField(blank=True, default=None, editable=False, null=True),
        ),
    ]
