# Graylist Plugin

The Graylist plugin is a plugin for the Alerta monitoring system. It allows for graylisting of alerts and blackouts based on specified filters. This README provides an overview of the plugin and instructions on how to use it.

Installation
------------

Clone the GitHub repo and run:

    $ python setup.py install

Or, to install remotely from GitHub run:

    $ pip install git+https://github.com/alerta/alerta-contrib.git#subdirectory=plugins/graylist

Note: If Alerta is installed in a python virtual environment then plugins
need to be installed into the same environment for Alerta to dynamically
discover them.

Configuration
------------
The Graylist plugin requires the following configuration parameters to be set in the Alerta configuration file:

* host_tags: A list of host tags to be used for filtering alerts and blackouts. Default is ['host'].

* target_tags: A list of target host tags to be used for allowing targethosts. Default is ['targethost'].

* reporter_headers: A list of reporter headers to be used for extracting reporter information from alert headers. Default is ['X-Pamola-Reporter-Host', 'X-Pamola-Reporter-External-ID', 'X-Pamola-Reporter-Customer-Prefix'].

* alert_customer_tags: A list of customer tags to be used for setting customer-specific tags in alerts. Default is ['externalid', 'customerprefix'].

* alert_customer_tags: A list of customer tags to be used for setting customer-specific tags in blackouts. Default is ['externalid'].

> Make sure to update the configuration file with the appropriate values for your environment.

Usage
------------
The Graylist plugin provides the following methods:

* pre_receive(alert: Alert) -> Alert: This method is called before an alert is received. It performs graylisting of alerts based on the specified filters and sets host and customer tags if missing.

* receive_blackout(blackout: Blackout) -> Blackout: This method is called when a blackout is received. It performs graylisting of blackouts based on the specified filters and sets host and customer tags if missing.

Contributing
-------
Contributions to the Graylist plugin are welcome! If you find a bug or have a suggestion for improvement, please open an issue or submit a pull request on the GitHub repository.

License
-------

Copyright (c) 2023 Orange Business . Available under the MIT License.