import uuid

import api.rls
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0097_attack_paths_scan_db_defaults"),
    ]

    operations = [
        migrations.CreateModel(
            name="TenantBranding",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("logo_base64", models.TextField(blank=True, default="")),
                (
                    "logo_content_type",
                    models.CharField(blank=True, default="", max_length=100),
                ),
                (
                    "logo_filename",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "tenant_branding",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="tenantbranding",
            constraint=models.UniqueConstraint(
                fields=("tenant_id",), name="unique_tenant_branding"
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantbranding",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_tenantbranding",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
