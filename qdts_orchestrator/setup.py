from setuptools import setup, find_packages

setup(
    name='qdts_orchestrator',
    version='0.2.0',
    packages=find_packages(),
    install_requires=[
        'click',
        'pyyaml',
        'ansible',
        'ansible_runner',
        'ansible-core'
    ],
    entry_points={
        'console_scripts': [
            'qdts_orchestrator = src.cli:cli',
        ],
    },
)
