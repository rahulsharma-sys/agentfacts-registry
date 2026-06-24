# SPDX-License-Identifier: Apache-2.0
def test_package_imports():
    import agentfacts

    assert agentfacts.__version__ == "0.1.0"
