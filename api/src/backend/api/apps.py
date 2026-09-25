import logging
import os
import sys
from pathlib import Path

from config.custom_logging import BackendLogger
from config.env import env
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(BackendLogger.API)

SIGNING_KEY_ENV = "DJANGO_TOKEN_SIGNING_KEY"
VERIFYING_KEY_ENV = "DJANGO_TOKEN_VERIFYING_KEY"

PRIVATE_KEY_FILE = "jwt_private.pem"
PUBLIC_KEY_FILE = "jwt_public.pem"

KEYS_DIRECTORY = (
    Path.home() / ".config" / "prowler-api"
)  # `/home/prowler/.config/prowler-api` inside the container

_keys_initialized = False  # Flag to prevent multiple executions within the same process


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        from api import (
            schema_extensions,  # noqa: F401
            signals,  # noqa: F401
        )

        self._patch_image_provider()

        # Generate required cryptographic keys if not present, but only if:
        #   `"manage.py" not in sys.argv[0]`: If an external server (e.g., Gunicorn) is running the app
        #   `os.environ.get("RUN_MAIN")`: If it's not a Django command or using `runserver`,
        #                                 only the main process will do it
        if (len(sys.argv) >= 1 and "manage.py" not in sys.argv[0]) or os.environ.get(
            "RUN_MAIN"
        ):
            self._ensure_crypto_keys()

    def _patch_image_provider(self):
        """
        Patch ImageProvider for robust container scanning:
        1. Support Google Artifact Registry / GCR service account JSON keys (which break
           Trivy if passed via TRIVY_PASSWORD because Trivy splits on commas).
        2. Use persistent Trivy cache directory (/home/prowler/.cache/trivy) instead
           of recreating tempdirs per scan (avoids 117MB re-download each time).
        3. Extend scan timeout default from 5m to 15m.
        """
        try:
            import subprocess
            import tempfile
            from prowler.providers.image.image_provider import ImageProvider

            def _build_trivy_env_patched(provider_self) -> tuple[dict, str | None]:
                env_vars = dict(os.environ)
                cleanup_file = None
                if provider_self.registry_username and provider_self.registry_password:
                    if provider_self.registry_username == "_json_key" or (
                        isinstance(provider_self.registry_password, str)
                        and "{" in provider_self.registry_password
                        and "service_account" in provider_self.registry_password
                    ):
                        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
                        f.write(provider_self.registry_password)
                        f.close()
                        env_vars["GOOGLE_APPLICATION_CREDENTIALS"] = f.name
                        cleanup_file = f.name
                    else:
                        env_vars["TRIVY_USERNAME"] = provider_self.registry_username
                        env_vars["TRIVY_PASSWORD"] = provider_self.registry_password
                elif provider_self.registry_token:
                    env_vars["TRIVY_REGISTRY_TOKEN"] = provider_self.registry_token
                return env_vars, cleanup_file

            ImageProvider._build_trivy_env = _build_trivy_env_patched

            orig_execute_trivy = ImageProvider._execute_trivy

            def _execute_trivy_patched(provider_self, command: list, image: str) -> subprocess.CompletedProcess:
                cleanup_file = None
                res = provider_self._build_trivy_env()
                if isinstance(res, tuple):
                    env_vars, cleanup_file = res
                else:
                    env_vars = res
                try:
                    logger.info(f"Scanning {image} with Trivy...")
                    return subprocess.run(command, capture_output=True, text=True, env=env_vars)
                finally:
                    if cleanup_file and os.path.exists(cleanup_file):
                        try:
                            os.unlink(cleanup_file)
                        except OSError:
                            pass

            ImageProvider._execute_trivy = _execute_trivy_patched

            orig_init = ImageProvider.__init__

            def _init_patched(provider_self, *args, **kwargs):
                if "timeout" not in kwargs or kwargs.get("timeout") == "5m":
                    kwargs["timeout"] = "15m"
                orig_init(provider_self, *args, **kwargs)
                provider_self._trivy_cache_dir = os.environ.get(
                    "TRIVY_CACHE_DIR", "/home/prowler/.cache/trivy"
                )
                os.makedirs(provider_self._trivy_cache_dir, exist_ok=True)
                provider_self._trivy_cache_dir_obj = None

            ImageProvider.__init__ = _init_patched

            def _cleanup_patched(provider_self):
                if getattr(provider_self, "_trivy_cache_dir_obj", None):
                    try:
                        provider_self._trivy_cache_dir_obj.cleanup()
                    except Exception:
                        pass

            ImageProvider.cleanup = _cleanup_patched
            logger.info("ImageProvider patched for GCP Artifact Registry and persistent Trivy cache")
        except Exception as e:
            logger.warning(f"Could not patch ImageProvider: {e}")


    def _ensure_crypto_keys(self):
        """
        Orchestrator method that ensures all required cryptographic keys are present.
        This method coordinates the generation of:
          - RSA key pairs for JWT token signing and verification
        Note: During development, Django spawns multiple processes (migrations, fixtures, etc.)
        which will each generate their own keys. This is expected behavior and each process
        will have consistent keys for its lifetime. In production, set the keys as environment
        variables to avoid regeneration.
        """
        global _keys_initialized

        # Skip key generation if running tests
        if getattr(settings, "TESTING", False):
            return

        # Skip if already initialized in this process
        if _keys_initialized:
            return

        # Check if both JWT keys are set; if not, generate them
        signing_key = env.str(SIGNING_KEY_ENV, default="").strip()
        verifying_key = env.str(VERIFYING_KEY_ENV, default="").strip()

        if not signing_key or not verifying_key:
            logger.info(
                f"Generating JWT RSA key pair. In production, set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' "
                "environment variables."
            )
            self._ensure_jwt_keys()

        # Mark as initialized to prevent future executions in this process
        _keys_initialized = True

    def _read_key_file(self, file_name):
        """
        Utility method to read the contents of a file.
        """
        file_path = KEYS_DIRECTORY / file_name
        return file_path.read_text().strip() if file_path.is_file() else None

    def _write_key_file(self, file_name, content, private=True):
        """
        Utility method to write content to a file.
        """
        try:
            file_path = KEYS_DIRECTORY / file_name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)
            file_path.chmod(0o600 if private else 0o644)

        except Exception as e:
            logger.error(
                f"Error writing key file '{file_name}': {e}. "
                f"Please set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' manually."
            )
            raise e

    def _ensure_jwt_keys(self):
        """
        Generate RSA key pairs for JWT token signing and verification
        if they are not already set in environment variables.
        """
        # Read existing keys from files if they exist
        signing_key = self._read_key_file(PRIVATE_KEY_FILE)
        verifying_key = self._read_key_file(PUBLIC_KEY_FILE)

        if not signing_key or not verifying_key:
            # Generate and store the RSA key pair
            signing_key, verifying_key = self._generate_jwt_keys()
            self._write_key_file(PRIVATE_KEY_FILE, signing_key, private=True)
            self._write_key_file(PUBLIC_KEY_FILE, verifying_key, private=False)
            logger.info("JWT keys generated and stored successfully")

        else:
            logger.info("JWT keys already generated")

        # Set environment variables and Django settings
        os.environ[SIGNING_KEY_ENV] = signing_key
        settings.SIMPLE_JWT["SIGNING_KEY"] = signing_key

        os.environ[VERIFYING_KEY_ENV] = verifying_key
        settings.SIMPLE_JWT["VERIFYING_KEY"] = verifying_key

    def _generate_jwt_keys(self):
        """
        Generate and set RSA key pairs for JWT token operations.
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            # Generate RSA key pair
            private_key = rsa.generate_private_key(  # Future improvement: we could read the next values from env vars
                public_exponent=65537,
                key_size=2048,
            )

            # Serialize private key (for signing)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            # Serialize public key (for verification)
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            logger.debug("JWT RSA key pair generated successfully.")
            return private_pem, public_pem

        except ImportError as e:
            logger.warning(
                "The 'cryptography' package is required for automatic JWT key generation."
            )
            raise e

        except Exception as e:
            logger.error(
                f"Error generating JWT keys: {e}. Please set '{SIGNING_KEY_ENV}' and '{VERIFYING_KEY_ENV}' manually."
            )
            raise e
