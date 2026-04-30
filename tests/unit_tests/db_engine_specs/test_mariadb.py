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

from typing import Any

import pytest
from sqlalchemy.engine.url import make_url


@pytest.mark.parametrize(
    "sqlalchemy_uri,error",
    [
        ("mariadb://user:password@host/db1?local_infile=1", True),
        ("mariadb+mysqlconnector://user:password@host/db1?allow_local_infile=1", True),
        ("mariadb://user:password@host/db1?local_infile=0", True),
        ("mariadb+mysqlconnector://user:password@host/db1?allow_local_infile=0", True),
        ("mariadb://user:password@host/db1", False),
        ("mariadb+mysqlconnector://user:password@host/db1", False),
    ],
)
def test_validate_database_uri_local_infile(sqlalchemy_uri: str, error: bool) -> None:
    """CVE-2024-34693: MariaDB must reject local_infile in URI query params."""
    from superset.db_engine_specs.mariadb import MariaDBEngineSpec

    url = make_url(sqlalchemy_uri)
    if error:
        with pytest.raises(ValueError):  # noqa: PT011
            MariaDBEngineSpec.validate_database_uri(url)
        return
    MariaDBEngineSpec.validate_database_uri(url)


@pytest.mark.parametrize(
    "sqlalchemy_uri,connect_args,returns",
    [
        ("mariadb://user:password@host/db1", {"local_infile": 1}, {"local_infile": 0}),
        (
            "mariadb+mysqlconnector://user:password@host/db1",
            {"allow_local_infile": 1},
            {"allow_local_infile": 0},
        ),
        ("mariadb://user:password@host/db1", {"local_infile": 0}, {"local_infile": 0}),
        (
            "mariadb+mysqlconnector://user:password@host/db1",
            {"allow_local_infile": 0},
            {"allow_local_infile": 0},
        ),
        (
            "mariadb://user:password@host/db1",
            {"param1": "some_value"},
            {"local_infile": 0, "param1": "some_value"},
        ),
        (
            "mariadb+mysqlconnector://user:password@host/db1",
            {"param1": "some_value"},
            {"allow_local_infile": 0, "param1": "some_value"},
        ),
    ],
)
def test_adjust_engine_params_enforces_local_infile_off(
    sqlalchemy_uri: str, connect_args: dict[str, Any], returns: dict[str, Any]
) -> None:
    """CVE-2024-34693: MariaDB must enforce local_infile=0 in connect_args."""
    from superset.db_engine_specs.mariadb import MariaDBEngineSpec

    url = make_url(sqlalchemy_uri)
    returned_url, returned_connect_args = MariaDBEngineSpec.adjust_engine_params(
        url, connect_args
    )
    assert returned_connect_args == returns
