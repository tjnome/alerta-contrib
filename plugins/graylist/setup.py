from setuptools import find_packages, setup

version = '2.2.0'

setup(
    name='alerta-graylist',
    version=version,
    description='Alerta plugin for graylisting alarms and blackout.',
    url='https://github.com/alerta/alerta-contrib',
    license='MIT',
    author='Terje Solend Nomeland',
    author_email='tjnome@gmail.com',
    packages=find_packages(),
    py_modules=['alerta_graylist'],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.plugins': [
            'graylist = alerta_graylist:GrayHandler'
        ]
    }
)
