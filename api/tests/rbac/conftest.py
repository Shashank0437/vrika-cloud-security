from unittest.mock import patch


def pytest_configure(config):
    config._rbac_admin_alias = patch("api.db_router.MainRouter.admin_db", "default")
    config._rbac_admin_alias.start()


def pytest_unconfigure(config):
    config._rbac_admin_alias.stop()
