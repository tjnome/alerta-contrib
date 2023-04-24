import logging
from dataclasses import dataclass
from typing import Any

from alerta.exceptions import RejectException
from alerta.models.alert import Alert
from alerta.models.blackout import Blackout
from alerta.models.filter import Filter
from alerta.plugins import PluginBase, app

LOG = logging.getLogger('alerta.plugins')

HOSTNAME_TAGS = app.config.get('HOSTNAME_TAGS', ['targethost', 'host'])
REPORTER_TAGS = app.config.get(
    'REPORTER_TAGS', ['pamola_host', 'pamola_externalid', 'pamola_customerprefix'])
CUSTOMER_TAGS = app.config.get(
    'CUSTOMER_TAGS', ['externalid', 'customerprefix'])


@dataclass
class GrayAttributes:
    pamola: dict[str, Any]
    roles: list[str]
    host: str


class GrayHandler(PluginBase):

    def pre_receive(self, alert, **kwargs):
        # Create a dict (Much faster than list)
        tags = {}
        for tag in alert.tags:
            if '=' in tag:
                key, value = tags.split('=', 1)
                tags[key] = value

        if not all([tag in tags for tag in REPORTER_TAGS]):
            LOG.debug(f'Missing {REPORTER_TAGS} in alert: {alert}')
            return alert

        if (not tags.get('targethost') and tags.get('host') == tags['pamola_host']):
            LOG.debug(
                f'{HOSTNAME_TAGS} matches {REPORTER_TAGS} in alert: {alert}')

            if (tags.get('externalid') != tags['pamola_externalid'] and tags.get('customerprefix') != tags['pamola_customerprefix']):
                LOG.debug(
                    f'{CUSTOMER_TAGS} and {REPORTER_TAGS} does not match. Set tags for: {alert}')

                # Insert customerprefix, externalid.
                for key in CUSTOMER_TAGS:
                    if key in tags:
                        alert.tags.remove(key + '=' + tags[key])
                        alert.tags.append(
                            key + '=' + tags['pamola' + '_' + key])

            # Remove reporter tags
            for key in REPORTER_TAGS:
                alert.tags.remove(key + '=' + tags[key])
            return alert

        filters = Filter.find_matching_filters(alert, 'graylist')
        if not filters:
            # Impersonate (Amogus)
            LOG.warning(
                f'Filter does not match alert. Amogus SUS alert: {alert}')
            # Remove host, tagethost, externalid and customerprefix
            for key in CUSTOMER_TAGS:
                if key in tags:
                    alert.tags.remove(key + '=' + tags[key])
            for key in HOSTNAME_TAGS:
                if key in tags:
                    alert.tags.remove(key + '=' + tags[key])

            for key in REPORTER_TAGS:
                # Remove reporter tags
                alert.tags.remove(key + '=' + tags[key])
                # Insert host, customerprefix, externalid.
                alert.tags.append(key.split('_', 1)[1] + '=' + tags[key])
            return alert

        for f in filters:
            try:
                grayattr = GrayAttributes(**f.attributes)
            except Exception as e:
                LOG.warning(
                    f'filter has invalid attributes: {f.id} error: {e}')
                continue

            if grayattr.host == tags['pamola_host']:
                if 'alert' in grayattr.roles:
                    for key in REPORTER_TAGS:
                        alert.tags.remove(key + '=' + tags[key])
                    return alert

        raise RejectException

    def post_receive(self, alert, **kwargs):
        return alert

    def status_change(self, alert, status, text, **kwargs):
        return

    def take_action(self, alert, action, text, **kwargs):
        raise NotImplementedError

    def delete(self, alert, **kwargs) -> bool:
        raise NotImplementedError

    def receive_blackout(self, blackout: 'Blackout', **kwargs) -> 'Blackout':
        # Create a dict (Much faster than list)
        tags = {}
        for tag in blackout.tags:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key] = value

        if not all([tag in tags for tag in REPORTER_TAGS]):
            LOG.debug(f'Missing {REPORTER_TAGS} in blackout: {blackout}')
            return blackout

        if any(tag.startswith(tags['pamola_host']) for tag in blackout.tags):
            if not tags.get('targethost'):
                if not tags.get('externalid') and not tags.get('customerprefix'):
                    # Insert customerprefix, externalid.
                    for key in CUSTOMER_TAGS:
                        blackout.tags.append(
                            key + '=' + tags['pamola' + '_' + key])

                    # Remove REPORTER_TAGS
                    for key in REPORTER_TAGS:
                        blackout.tags.remove(key + '=' + tags[key])
                    return blackout

                if (tags.get('externalid') == tags['pamola_externalid'] and tags.get('customerprefix') == tags['pamola_customerprefix']):
                    # Remove REPORTER_TAGS
                    for key in REPORTER_TAGS:
                        blackout.tags.remove(key + '=' + tags[key])
                    return blackout

        # Check if blackout matches anything:
        filters = Filter.find_matching_filters(
            self.parse(blackout), 'graylist')

        if not filters:
            raise RejectException

        for f in filters:
            try:
                grayattr = GrayAttributes(**f.attributes)
            except Exception as e:
                LOG.warning(
                    f'filter has invalid attributes: {f.id} error: {e}')
                continue

            if grayattr.host == tags['pamola_host']:
                if 'blackout' in grayattr.roles:
                    for key in REPORTER_TAGS:
                        blackout.tags.remove(key + '=' + tags[key])
                    return blackout

        raise RejectException

    def delete_blackout(self, blackout: 'Blackout', **kwargs) -> bool:
        LOG.debug(f'Blackout that is deleted: {blackout}')
        raise NotImplementedError

    def create_filter(self, filter: 'Filter', **kwargs) -> 'Filter':
        LOG.debug(f'Filter that is used: {filter}')
        raise NotImplementedError

    def receive_filter(self, filter: 'Filter', **kwargs) -> 'Filter':
        LOG.debug(f'Filter that it matches: {filter}')
        raise NotImplementedError

    def delete_filter(self, filter: 'Filter', **kwargs) -> bool:
        LOG.debug(f'Filter that is deleted: {filter}')
        raise NotImplementedError

    @staticmethod
    def parse(blackout: 'Blackout') -> 'Alert':
        return Alert(
            id=None,
            resource=blackout.get('resource', None),
            event=blackout.get('event', None),
            environment=blackout.get('environment', None),
            severity=None,
            correlate=list(),
            status=None,
            service=blackout.get('service', list()),
            group=blackout.get('group', None),
            value=None,
            text=None,
            tags=blackout.get('tags', list()),
            attributes=dict(),
            origin=None,
            event_type=None,
            create_time=None,
            timeout=None,
            raw_data=None,
            customer=None
        )
