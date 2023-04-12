from setuptools import setup, find_packages

version = '1.0.0'

setup(
    name="alerta_graylist",
    version=version,
    description='Alerta plugin for graylisting/whitelisting alarms/blackout.',
    url='https://github.com/alerta/alerta-contrib',
    license='MIT',
    author='Terje Solend Nomeland',
    author_email='tjnome@gmail.com',
    packages=find_packages(),
    py_modules=['alerta_delay'],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.plugins': [
            'graylist = alerta_graylist:GrayHandler'
        ]
    }
)