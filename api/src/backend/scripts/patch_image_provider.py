#!/usr/bin/env python3
"""
Patch Prowler's ImageProvider for robust container scanning:
1. Support Google Artifact Registry / GCR service account JSON keys (prevent TRIVY_PASSWORD comma splitting).
2. Use persistent Trivy cache directory (/home/prowler/.cache/trivy) instead of recreating tempdirs per scan.
3. Extend scan timeout default from 5m to 15m.
"""

import os
import sys

target_file = "/home/prowler/.venv/lib/python3.12/site-packages/prowler/providers/image/image_provider.py"

if not os.path.exists(target_file):
    # Try finding in current python environment
    import importlib.util
    spec = importlib.util.find_spec("prowler.providers.image.image_provider")
    if spec and spec.origin:
        target_file = spec.origin
    else:
        print(f"File not found: {target_file}, skipping patch.")
        sys.exit(0)

try:
    with open(target_file, "r") as f:
        content = f.read()

    modified = False

    # 1. Update timeout default from 5m to 15m
    if 'timeout: str = "5m",' in content:
        content = content.replace('timeout: str = "5m",', 'timeout: str = "15m",')
        modified = True

    # 2. Update cache dir to persistent cache
    old_cache_setup = """        self._trivy_cache_dir_obj = tempfile.TemporaryDirectory(
            prefix="prowler-trivy-cache-"
        )
        self._trivy_cache_dir = self._trivy_cache_dir_obj.name"""

    new_cache_setup = """        self._trivy_cache_dir = os.environ.get("TRIVY_CACHE_DIR", "/home/prowler/.cache/trivy")
        os.makedirs(self._trivy_cache_dir, exist_ok=True)
        self._trivy_cache_dir_obj = None"""

    if old_cache_setup in content:
        content = content.replace(old_cache_setup, new_cache_setup)
        modified = True

    old_cleanup = """    def cleanup(self) -> None:
        \"\"\"Clean up any resources after scanning.\"\"\"
        if hasattr(self, "_trivy_cache_dir_obj"):
            self._trivy_cache_dir_obj.cleanup()"""

    new_cleanup = """    def cleanup(self) -> None:
        \"\"\"Clean up any resources after scanning.\"\"\"
        if getattr(self, "_trivy_cache_dir_obj", None):
            self._trivy_cache_dir_obj.cleanup()"""

    if old_cleanup in content:
        content = content.replace(old_cleanup, new_cleanup)
        modified = True

    # 3. Patch GCP service account credentials in _build_trivy_env
    if "GOOGLE_APPLICATION_CREDENTIALS" not in content:
        old_def = """    def _build_trivy_env(self) -> dict:
        \"\"\"Build environment variables for Trivy, injecting registry credentials.\"\"\"
        env = dict(os.environ)
        if self.registry_username and self.registry_password:
            env["TRIVY_USERNAME"] = self.registry_username
            env["TRIVY_PASSWORD"] = self.registry_password
        elif self.registry_token:
            env["TRIVY_REGISTRY_TOKEN"] = self.registry_token
        return env"""

        new_def = """    def _build_trivy_env(self) -> tuple[dict, str | None]:
        \"\"\"Build environment variables for Trivy, injecting registry credentials.\"\"\"
        env = dict(os.environ)
        cleanup_file = None
        if self.registry_username and self.registry_password:
            if self.registry_username == "_json_key" or (
                isinstance(self.registry_password, str)
                and "{" in self.registry_password
                and "service_account" in self.registry_password
            ):
                f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
                f.write(self.registry_password)
                f.close()
                env["GOOGLE_APPLICATION_CREDENTIALS"] = f.name
                cleanup_file = f.name
            else:
                env["TRIVY_USERNAME"] = self.registry_username
                env["TRIVY_PASSWORD"] = self.registry_password
        elif self.registry_token:
            env["TRIVY_REGISTRY_TOKEN"] = self.registry_token
        return env, cleanup_file"""

        old_exec = """    def _execute_trivy(self, command: list, image: str) -> subprocess.CompletedProcess:
        \"\"\"Execute Trivy command with optional progress bar.\"\"\"
        env = self._build_trivy_env()"""

        new_exec = """    def _execute_trivy(self, command: list, image: str) -> subprocess.CompletedProcess:
        \"\"\"Execute Trivy command with optional progress bar.\"\"\"
        env, cleanup_file = self._build_trivy_env()"""

        old_finally = """        except (AttributeError, OSError):
            logger.info(f"Scanning {image}...")
            return subprocess.run(command, capture_output=True, text=True, env=env)"""

        new_finally = """        except (AttributeError, OSError):
            logger.info(f"Scanning {image}...")
            return subprocess.run(command, capture_output=True, text=True, env=env)
        finally:
            if cleanup_file and os.path.exists(cleanup_file):
                try:
                    os.unlink(cleanup_file)
                except OSError:
                    pass"""

        if old_def in content:
            content = content.replace(old_def, new_def)
            content = content.replace(old_exec, new_exec)
            content = content.replace(old_finally, new_finally)
            modified = True

    if modified:
        with open(target_file, "w") as f:
            f.write(content)
        print(f"Successfully patched {target_file}")
    else:
        print(f"{target_file} is already up to date")
except Exception as e:
    print(f"Warning: could not patch {target_file}: {e}")
