# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""
Tests for CVE-2024-53949: Verify that FAB security API view menus
(Role, User, Group) are restricted to admin-only access so that
lower-privilege users cannot create or modify roles when
FAB_ADD_SECURITY_API is enabled.
"""

from superset.security.manager import SupersetSecurityManager


def test_fab_role_api_is_admin_only() -> None:
    """The FAB RoleApi class_permission_name must be in ADMIN_ONLY_VIEW_MENUS."""
    assert "Role" in SupersetSecurityManager.ADMIN_ONLY_VIEW_MENUS


def test_fab_user_api_is_admin_only() -> None:
    """The FAB UserApi class_permission_name must be in ADMIN_ONLY_VIEW_MENUS."""
    assert "User" in SupersetSecurityManager.ADMIN_ONLY_VIEW_MENUS


def test_fab_group_api_is_admin_only() -> None:
    """The FAB GroupApi class_permission_name must be in ADMIN_ONLY_VIEW_MENUS."""
    assert "Group" in SupersetSecurityManager.ADMIN_ONLY_VIEW_MENUS
