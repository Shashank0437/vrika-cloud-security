from api.db_router import MainRouter
from django.db import migrations


def grant_managed_triage_permissions(apps, schema_editor):
    roles = apps.get_model("api", "Role").objects.using(MainRouter.admin_db)
    roles.filter(name="admin").update(manage_triage=True, manage_triage_exceptions=True)
    roles.filter(name="vrika_member").update(
        manage_triage=True, manage_triage_exceptions=False
    )


class Migration(migrations.Migration):
    dependencies = [("api", "0099_finding_triage")]
    operations = [
        migrations.RunPython(
            grant_managed_triage_permissions, migrations.RunPython.noop
        ),
    ]
